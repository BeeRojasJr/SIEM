import asyncio
import ipaddress
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from .models import AlertUpdate, SimulatorConfig
from .store import MemoryStore
from .detection import DetectionEngine
from typing import Optional
from fastapi.responses import StreamingResponse
from .ai import AIRequest, AnalystAI
from .geoip import GeoIPService
from .simulator import simulator_loop, make_event, simulated_geo

store = MemoryStore()
engine = DetectionEngine()
geoip = GeoIPService(placeholder=simulated_geo)
ai = AnalystAI(store)
clients = set()

async def broadcast(message):
    dead = []
    for ws in list(clients):
        try: await ws.send_json(message)
        except Exception: dead.append(ws)
    for ws in dead: clients.discard(ws)

@asynccontextmanager
async def lifespan(app):
    task = asyncio.create_task(simulator_loop(store, engine, broadcast, geoip.enrich))
    yield
    geoip.close()
    await ai.close()
    task.cancel()
    try: await task
    except asyncio.CancelledError: pass

app = FastAPI(title="AEGIS Mini SIEM API", version="0.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

@app.get("/api/health")
def health(): return {"status":"ok","service":"mini-siem-api"}

@app.get("/api/overview")
def overview():
    with store.lock:
        events, alerts = list(store.events), list(store.alerts)
    counts = {s:sum(1 for a in alerts if a.severity == s and a.status != "closed") for s in ["critical","high","medium","low","info"]}
    now = datetime.now(timezone.utc).replace(second=0,microsecond=0)
    chart = []
    for i in range(11,-1,-1):
        minute = now - timedelta(minutes=i)
        chart.append({"time":minute.strftime("%H:%M"),"events":sum(1 for e in events if e.timestamp.replace(second=0,microsecond=0)==minute)})
    return {"events_total":len(events),"alerts_total":len(alerts),
        "active_alerts":sum(1 for a in alerts if a.status!="closed"),
        "critical_alerts":counts["critical"],"high_alerts":counts["high"],
        "affected_hosts":len({a.hostname for a in alerts if a.status!="closed"}),
        "events_per_minute":store.events_per_minute,"simulator_running":store.simulator_running,
        "severity_counts":counts,"events_by_minute":chart,
        "recent_event_count":sum(1 for e in events if (datetime.now(timezone.utc)-e.timestamp).total_seconds()<=60)}

@app.get("/api/events")
def get_events(limit:int=100):
    with store.lock: return [e.model_dump(mode="json") for e in list(store.events)[:max(1,min(limit,3000))]]

@app.get("/api/alerts")
def get_alerts(status:str="all",limit:int=200):
    with store.lock: alerts=list(store.alerts)
    if status!="all": alerts=[a for a in alerts if a.status==status]
    return [a.model_dump(mode="json") for a in alerts[:max(1,min(limit,1000))]]

@app.patch("/api/alerts/{alert_id}")
async def update_alert(alert_id:str, update:AlertUpdate):
    changed=None
    with store.lock:
        for i,a in enumerate(store.alerts):
            if a.id==alert_id:
                changed=a.model_copy(update={"status":update.status})
                store.alerts[i]=changed
                break
    if changed is None: raise HTTPException(404,"Alert not found")
    payload=changed.model_dump(mode="json")
    await broadcast({"type":"alert_update","alert":payload})
    return payload

@app.post("/api/simulator/start")
async def start():
    store.simulator_running=True
    await broadcast({"type":"simulator","running":True})
    return {"running":True}

@app.post("/api/simulator/pause")
async def pause():
    store.simulator_running=False
    await broadcast({"type":"simulator","running":False})
    return {"running":False}

@app.post("/api/simulator/reset")
async def reset():
    store.reset()
    engine.failed.clear()
    engine.seen.clear()
    await broadcast({"type":"reset"})
    return {"reset":True}

@app.post("/api/simulator/config")
async def configure(config:SimulatorConfig):
    store.events_per_minute=config.events_per_minute
    await broadcast({"type":"config","events_per_minute":store.events_per_minute})
    return {"events_per_minute":store.events_per_minute}

async def ingest(event):
    geoip.enrich(event)  # must happen before detection so alerts inherit the location
    with store.lock:
        store.events.appendleft(event); alerts=engine.evaluate(event)
        for a in alerts: store.alerts.appendleft(a)
    await broadcast({"type":"event","event":event.model_dump(mode="json"),"alerts":[a.model_dump(mode="json") for a in alerts]})

@app.get("/api/ai/status")
def ai_status(): return ai.status()

@app.post("/api/ai/stream")
async def ai_stream(req: AIRequest):
    """Server-Sent Events: meta -> delta* -> done | error. The API key never leaves the backend."""
    prepared = ai.prepare(req)  # raises 400/404/429/503 before streaming starts
    return StreamingResponse(ai.stream(prepared), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.get("/api/geoip/status")
def geoip_status(): return geoip.status()

@app.get("/api/geoip/lookup")
def geoip_lookup(ip:str):
    try: ipaddress.ip_address(ip.strip())
    except ValueError: raise HTTPException(400,"Invalid IP address")
    return {"ip":ip.strip(),"geo":geoip.lookup(ip)}

@app.post("/api/simulator/trigger/{scenario}")
async def trigger(scenario:str, ip:Optional[str]=None):
    """Fire a synthetic scenario. Optional ?ip= overrides the remote address (handy for testing GeoIP)."""
    if ip:
        try: ip=str(ipaddress.ip_address(ip.strip()))
        except ValueError: raise HTTPException(400,"Invalid IP address")
    mapping={"powershell":"powershell_suspicious","outbound":"outbound_connection_suspicious","malware":"malware_indicator",
             "scan":"port_scan","unusual-login":"unusual_login_location"}
    if scenario=="brute-force":
        for _ in range(6):
            await ingest(make_event("authentication_failure", hostname="WS-014", username="admin.lab",
                source_ip=ip or "203.0.113.77", message="Failed sign-in during manually triggered brute-force simulation."))
    elif scenario in mapping:
        over={}
        if ip: over["destination_ip" if scenario=="outbound" else "source_ip"]=ip
        await ingest(make_event(mapping[scenario], **over))
    else: raise HTTPException(400,"Unknown scenario")
    return {"triggered":scenario}

@app.websocket("/ws")
async def websocket_endpoint(ws:WebSocket):
    await ws.accept(); clients.add(ws)
    try:
        await ws.send_json({"type":"connected"})
        while True: await ws.receive_text()
    except WebSocketDisconnect: clients.discard(ws)