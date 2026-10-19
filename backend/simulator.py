import random, asyncio, uuid
from datetime import datetime, timezone
from .models import SecurityEvent

HOSTS = ["WS-014","WS-022","FIN-LT-008","HR-WS-003","APP-SRV-02","DC-LAB-01","ENG-WS-019"]
USERS = ["j.santos","m.reyes","a.cruz","svc_backup","k.delarosa","admin.lab"]
INTERNAL = ["10.20.1.14","10.20.1.22","10.20.2.8","10.20.3.19","192.168.10.5"]
# RFC 5737 documentation ranges, not real public targets.
EXTERNAL = ["198.51.100.23","203.0.113.77","192.0.2.44","198.51.100.88","203.0.113.12",
            "192.0.2.9","203.0.113.140","198.51.100.150","192.0.2.201","203.0.113.201"]

# --- Simulated geography -------------------------------------------------------
# Documentation IPs have NO real location. Each one is mapped to a placeholder city so the Threat Map
# has something to draw. GeoIPService calls simulated_geo() first, and the result is flagged
# "simulated": True so the UI labels it. Real public IPs never reach this: they go to MaxMind.
SIM_SOURCES = [("Frankfurt", 50.11, 8.68), ("Sao Paulo", -23.55, -46.63), ("Lagos", 6.52, 3.38),
               ("Mumbai", 19.08, 72.88), ("Toronto", 43.65, -79.38), ("Sydney", -33.87, 151.21),
               ("Seoul", 37.57, 126.98), ("Johannesburg", -26.20, 28.05),
               ("Mexico City", 19.43, -99.13), ("Helsinki", 60.17, 24.94)]

def simulated_geo(ip):
    if ip not in EXTERNAL:
        return None
    city, lat, lon = SIM_SOURCES[EXTERNAL.index(ip) % len(SIM_SOURCES)]
    return {"city": city, "country": None, "country_code": None, "lat": lat, "lon": lon, "accuracy_km": None,
            "internal": False, "simulated": True, "source": "simulated"}

BENIGN = [
 ("process_start","endpoint","info","A user application process started.",False,None),
 ("authentication_success","identity","info","Successful interactive sign-in.",False,None),
 ("dns_query","network","low","DNS query observed for a business application.",False,None),
 ("web_access","network","info","HTTPS request to an approved business service.",False,None),
 ("file_access","endpoint","low","User accessed a work document.",False,None)]
ATTACKS = [
 ("authentication_failure","identity","medium","Failed sign-in attempt detected.",True,"T1110"),
 ("powershell_suspicious","endpoint","high","Suspicious PowerShell command-line pattern observed.",True,"T1059.001"),
 ("outbound_connection_suspicious","network","medium","Unusual outbound connection observed.",True,"T1071"),
 ("malware_indicator","endpoint","critical","Synthetic malware hash indicator matched.",True,"T1204"),
 ("port_scan","network","medium","Sequential connection attempts across many ports observed.",True,"T1046"),
 ("unusual_login_location","identity","medium","Successful sign-in from a location not seen for this user.",True,"T1078")]

def make_event(event_type=None, **over):
    attack = event_type is not None or random.random() < .17
    item = next((x for x in ATTACKS if x[0] == event_type), None) if event_type else None
    item = item or (random.choice(ATTACKS) if attack else random.choice(BENIGN))
    et, category, severity, message, suspicious, mitre = item
    host, user = random.choice(HOSTS), random.choice(USERS)
    external_src = ((et == "authentication_failure" and random.random() < .75)
                    or (et == "port_scan" and random.random() < .85)
                    or et == "unusual_login_location")
    src = random.choice(EXTERNAL) if external_src else random.choice(INTERNAL)
    dst = random.choice(EXTERNAL) if "outbound" in et or et == "web_access" else random.choice(INTERNAL)
    host, user, src = over.get("hostname", host), over.get("username", user), over.get("source_ip", src)
    dst = over.get("destination_ip", dst)
    if et == "authentication_failure":
        message = f"Failed sign-in for {user} from {src}."
    elif et == "unusual_login_location":
        message = f"Successful sign-in for {user} from an unfamiliar location ({src})."
    elif et == "port_scan":
        message = f"Sequential connection attempts from {src} across many ports on {host}."
    message = over.get("message", message)
    return SecurityEvent(id=uuid.uuid4().hex, timestamp=datetime.now(timezone.utc),
        hostname=host, username=user, source_ip=src, destination_ip=dst,
        event_type=et, category=category, severity=severity, message=message,
        is_suspicious=suspicious, mitre_technique=mitre,
        raw={"simulated": True, "process": "powershell.exe" if et == "powershell_suspicious" else None})

async def simulator_loop(store, engine, broadcast, enrich=None):
    while True:
        if store.simulator_running:
            event = make_event()
            if enrich: enrich(event)
            with store.lock:
                store.events.appendleft(event)
                alerts = engine.evaluate(event)
                for alert in alerts: store.alerts.appendleft(alert)
            await broadcast({"type":"event","event":event.model_dump(mode="json"),
                             "alerts":[a.model_dump(mode="json") for a in alerts]})
        await asyncio.sleep(max(.2, 60 / store.events_per_minute))