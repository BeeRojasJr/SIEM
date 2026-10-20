import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Activity, AlertTriangle, Bell, CheckCircle2, Sparkles, ChevronRight, Database, Globe2, Gauge, LockKeyhole, MapPinned, Pause, Play, Radar, RefreshCw, Search, Server, Shield, ShieldAlert, Terminal, UserCheck, Wifi, X } from 'lucide-react';
import { Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import ThreatMap from './ThreatMap';
import AiAssistant from './AiAssistant';
import AiCompanion from './AiCompanion';
import { bumpStreakState, petMood, toAiTarget } from './aiUtils';
import { SEVS, Sev, Status, geoBadge, geoKey, isSim, placeLabel, pretty, sevColors, tm, typeLabel, usePersisted } from './common';

const API_URL = import.meta.env.VITE_API_URL ?? '/api';
const WS_URL = import.meta.env.VITE_WS_URL ??
  `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`;

const api = async (path, opts = {}) => {
  const r = await fetch(API_URL + path, { headers: { 'Content-Type': 'application/json' }, ...opts });
};
const EMPTY = { severity: [], types: [], status: 'all', host: null, query: '', minute: null };
const ROW_OPTIONS = [20, 50, 100];
const EVENT_CAP = 2000, ALERT_CAP = 1000;
const minuteOf = ts => Math.floor(Date.parse(ts) / 60000);
const hhmm = m => new Date(m * 60000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

// One filter pipeline feeds every card, chart, table and the map, so they can never disagree.
function applyFilters(list, f, kind, skip = []) {
  const q = f.query.trim().toLowerCase();
  return list.filter(x => {
    if (!skip.includes('severity') && f.severity.length && !f.severity.includes(x.severity)) return false;
    if (!skip.includes('types') && f.types.length && !f.types.includes(x.event_type)) return false;
    if (!skip.includes('host') && f.host && x.hostname !== f.host) return false;
    if (!skip.includes('minute') && f.minute != null && minuteOf(x.timestamp) !== f.minute) return false;
    if (!skip.includes('status') && kind === 'alert' && f.status !== 'all' &&
      !(f.status === 'active' ? x.status !== 'closed' : x.status === f.status)) return false;
    if (q && ![x.title, x.hostname, x.username, x.source_ip, x.rule_id, x.event_type, x.message, x.geo?.city, x.geo?.country, x.geo?.country_code, typeLabel(x.event_type)]
      .some(v => (v || '').toLowerCase().includes(q))) return false;
    return true;
  });
}
const newestFirst = (a, b) => (a.timestamp < b.timestamp ? 1 : a.timestamp > b.timestamp ? -1 : 0);
const mergeLatest = (server, prev, cap) => {
  const ids = new Set(server.map(x => x.id));
  return [...prev.filter(x => !ids.has(x.id)), ...server].sort(newestFirst).slice(0, cap);
};

function App() {
  const [ov, setOv] = useState(null), [events, setEvents] = useState([]), [alerts, setAlerts] = useState([]);
  const [selected, setSelected] = useState(null), [f, setF] = useState(EMPTY);
  const [view, setView] = useState('overview');
  const [tab, setTab] = usePersisted('aegis.tab', 'alerts', v => v === 'alerts' || v === 'events');
  const [rowLimit, setRowLimit] = usePersisted('aegis.rows', 50, v => ROW_OPTIONS.includes(v));
  const [mapMin, setMapMin] = usePersisted('aegis.mapMin', false, v => typeof v === 'boolean');
  const [mapWin, setMapWin] = usePersisted('aegis.mapWin', 15, v => [0, 5, 15, 60].includes(v));
  const [mapFull, setMapFull] = useState(false), [selKey, setSelKey] = useState(null);
  const [rate, setRate] = useState(30), [connected, setConnected] = useState(false), [error, setError] = useState('');
  const [hostsOpen, setHostsOpen] = useState(false), [tick, setTick] = useState(0), [gip, setGip] = useState(null);
  const rateEditing = useRef(false);
  // ---- AI assistant + companion
  const [aiOpen, setAiOpen] = useState(false), [aiTarget, setAiTarget] = useState(null), [aiAuto, setAiAuto] = useState(null);
  const [aiStatus, setAiStatus] = useState(undefined), [aiBusy, setAiBusy] = useState(false);
  const [petHidden, setPetHidden] = usePersisted('aegis.petHidden', false, v => typeof v === 'boolean');
  const [streak, setStreak] = usePersisted('aegis.streak', { last: null, count: 0 }, v => v && typeof v.count === 'number');
  const [kudos, setKudos] = useState({ nonce: 0, count: 0 });
  const aiNonce = useRef(0);

  useEffect(() => { const t = setInterval(() => setTick(x => x + 1), 10000); return () => clearInterval(t); }, []);

  const refresh = useCallback(async () => {
    try {
      const [o, e, a] = await Promise.all([api('/overview'), api(`/events?limit=${EVENT_CAP}`), api(`/alerts?limit=${ALERT_CAP}`)]);
      setOv(o); setEvents(p => mergeLatest(e, p, EVENT_CAP)); setAlerts(p => mergeLatest(a, p, ALERT_CAP));
      if (!rateEditing.current) setRate(o.events_per_minute);
      setError('');
    } catch { setError('Backend not connected. Start FastAPI on port 8000.'); }
  }, []);
  useEffect(() => { refresh(); }, [refresh]);
  // The WebSocket is the live path; polling is only a resync (fast while the socket is down).
  useEffect(() => { const t = setInterval(refresh, connected ? 20000 : 4000); return () => clearInterval(t); }, [refresh, connected]);

  useEffect(() => {
    let ws, retry, closed = false;
    function connect() {
      ws = new WebSocket(WS_URL);
      ws.onopen = () => { setConnected(true); refresh(); };
      ws.onclose = () => { setConnected(false); if (!closed) retry = setTimeout(connect, 2500); };
      ws.onerror = () => ws.close();
      ws.onmessage = ev => {
        const m = JSON.parse(ev.data);
        if (m.type === 'reset') { setEvents([]); setAlerts([]); setSelected(null); setSelKey(null); }
        else if (m.type === 'event') {
          setEvents(p => p.some(x => x.id === m.event.id) ? p : [m.event, ...p].slice(0, EVENT_CAP));
          if (m.alerts?.length) setAlerts(p => { const ids = new Set(p.map(x => x.id)); return [...m.alerts.filter(a => !ids.has(a.id)), ...p].slice(0, ALERT_CAP); });
        } else if (m.type === 'alert_update') {
          setAlerts(p => p.map(a => a.id === m.alert.id ? m.alert : a));
          setSelected(s => s && s.id === m.alert.id ? { ...s, ...m.alert } : s);
        } else if (m.type === 'simulator' || m.type === 'config') refresh();
      };
    }
    connect();
    return () => { closed = true; clearTimeout(retry); ws?.close(); };
  }, [refresh]);

  useEffect(() => {
    const k = e => { if (e.key === 'Escape') { if (aiOpen) setAiOpen(false); else if (mapFull) setMapFull(false); else setSelected(null); } };
    window.addEventListener('keydown', k); return () => window.removeEventListener('keydown', k);
  }, [mapFull, aiOpen]);
  useEffect(() => {
    if (!hostsOpen) return;
    const c = e => { if (!e.target.closest('.hostcard')) setHostsOpen(false); };
    document.addEventListener('mousedown', c); return () => document.removeEventListener('mousedown', c);
  }, [hostsOpen]);

  useEffect(() => { api('/ai/status').then(setAiStatus).catch(() => setAiStatus(null)); }, [connected]);
  useEffect(() => { api('/geoip/status').then(setGip).catch(() => setGip(null)); }, [connected]);

  // ---- filter actions
  const toggleSev = (s, only) => setF(x => ({ ...x, severity: only ? (x.severity.length === 1 && x.severity[0] === s ? [] : [s]) : x.severity.includes(s) ? x.severity.filter(v => v !== s) : [...x.severity, s] }));
  const toggleType = t => setF(x => ({ ...x, types: x.types.includes(t) ? x.types.filter(v => v !== t) : [...x.types, t] }));
  const toggleHost = h => setF(x => ({ ...x, host: x.host === h ? null : h }));
  const toggleMinute = m => setF(x => ({ ...x, minute: x.minute === m ? null : m }));
  const toggleQuery = q => setF(x => ({ ...x, query: x.query === q ? '' : q }));
  const setQuery = q => setF(x => ({ ...x, query: q }));
  const setStatus = s => setF(x => ({ ...x, status: s }));
  const clearAll = () => setF(EMPTY);

  // ---- derived data (single source of truth)
  const fEvents = useMemo(() => applyFilters(events, f, 'event'), [events, f]);
  const fAlerts = useMemo(() => applyFilters(alerts, f, 'alert'), [alerts, f]);
  const alertByEvent = useMemo(() => new Map(alerts.map(a => [a.event_id, a])), [alerts]);
  const hasFilter = f.severity.length || f.types.length || f.host || f.query || f.minute != null || f.status !== 'all';

  const chartData = useMemo(() => {
    const nowMin = Math.floor(Date.now() / 60000), counts = new Map();
    for (const e of applyFilters(events, f, 'event', ['minute'])) { const m = minuteOf(e.timestamp); if (m > nowMin - 12) counts.set(m, (counts.get(m) || 0) + 1); }
    return Array.from({ length: 12 }, (_, i) => { const m = nowMin - 11 + i; return { ts: m, time: hhmm(m), events: counts.get(m) || 0 }; });
  }, [events, f, tick]);
  const sevCounts = useMemo(() => {
    const c = Object.fromEntries(SEVS.map(s => [s, 0]));
    applyFilters(alerts, f, 'alert', ['severity']).filter(a => f.status === 'all' ? a.status !== 'closed' : true).forEach(a => { c[a.severity]++; });
    return c;
  }, [alerts, f]);
  const donut = SEVS.filter(s => sevCounts[s] > 0).map(name => ({ name, value: sevCounts[name] }));
  const donutTotal = SEVS.reduce((n, s) => n + sevCounts[s], 0);

  const active = useMemo(() => fAlerts.filter(a => a.status !== 'closed'), [fAlerts]);
  const hostCounts = useMemo(() => { const m = new Map(); active.forEach(a => m.set(a.hostname, (m.get(a.hostname) || 0) + 1)); return [...m].sort((a, b) => b[1] - a[1]); }, [active]);
  const last60 = useMemo(() => fEvents.filter(e => Date.now() - Date.parse(e.timestamp) <= 60000).length, [fEvents, tick]);
  const totalIngested = Math.max(ov?.events_total || 0, events.length);
  const critN = active.filter(a => a.severity === 'critical').length, highN = active.filter(a => a.severity === 'high').length;
  const critHighOn = f.severity.length === 2 && f.severity.includes('critical') && f.severity.includes('high');

  const mapBase = useMemo(() => {
    const cutoff = mapWin ? Date.now() - mapWin * 60000 : 0;
    return applyFilters(events, f, 'event', ['types']).filter(e => e.is_suspicious && e.geo && (!cutoff || Date.parse(e.timestamp) >= cutoff));
  }, [events, f, mapWin, tick]);
  const mapEvents = useMemo(() => f.types.length ? mapBase.filter(e => f.types.includes(e.event_type)) : mapBase, [mapBase, f.types]);
  const simCount = mapBase.filter(isSim).length, realCount = mapBase.length - simCount;
  const unlocated = useMemo(() => {
    const cutoff = mapWin ? Date.now() - mapWin * 60000 : 0;
    return applyFilters(events, f, 'event', ['types']).filter(e => e.is_suspicious && !e.geo && (!cutoff || Date.parse(e.timestamp) >= cutoff)).length;
  }, [events, f, mapWin, tick]);

  // ---- actions
  const run = ov?.simulator_running;
  const action = async (path, body) => {
    try {
      await api(path, { method: 'POST', body: body ? JSON.stringify(body) : undefined });
      if (path === '/simulator/reset') { setEvents([]); setAlerts([]); setSelected(null); setSelKey(null); }
      await refresh();
    } catch (e) { setError(e.message); }
  };
  const update = async (a, status) => { try { await api('/alerts/' + a.id, { method: 'PATCH', body: JSON.stringify({ status }) }); setSelected(s => ({ ...s, status })); if (status !== 'new') bumpStreak(); await refresh(); } catch (e) { setError(e.message); } };
  const bumpStreak = () => setStreak(s => { const n = bumpStreakState(s); if (n !== s) setKudos(k => ({ nonce: k.nonce + 1, count: n.count })); return n; });
  const openAi = (target, task) => {
    setAiTarget(target || null);
    if (task) { aiNonce.current += 1; setAiAuto({ nonce: aiNonce.current, task, label: task === 'report' ? 'Generate report' : `Analyze this ${target?.kind === 'event' ? 'event' : 'alert'}` }); }
    setAiOpen(true); setSelected(null);
  };
  const openEvent = e => {
    const a = alertByEvent.get(e.id);
    setSelected(a ? { ...e, ...a, event_id: e.id, destination_ip: e.destination_ip, source: e.source }
      : { ...e, title: typeLabel(e.event_type), description: e.message, rule_id: 'EVENT', status: null, event_id: e.id });
  };
  const scrollTo = id => setTimeout(() => document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 60);
  const go = t => {
    if (t === 'map') { setView('map'); window.scrollTo({ top: 0 }); return; }
    setView('overview');
    if (t === 'alerts' || t === 'events') { setTab(t); scrollTo('telemetry'); }
    else if (t === 'simulator') scrollTo('simulator');
    else window.scrollTo({ top: 0, behavior: 'smooth' });
  };
  const showOnMap = g => { setSelKey(geoKey(g)); setMapMin(false); setSelected(null); setView('map'); window.scrollTo({ top: 0 }); };
  const commitRate = () => { rateEditing.current = false; action('/simulator/config', { events_per_minute: rate }); };

  const filterBar = (showStatus) => (
    <FilterBar f={f} setQuery={setQuery} toggleSev={toggleSev} setStatus={setStatus} toggleType={toggleType} toggleHost={toggleHost}
      toggleMinute={toggleMinute} clearAll={clearAll} showStatus={showStatus} hasFilter={hasFilter} />);
  const actions = (
    <div className="actions"><span><i className="live" /> Live simulation</span>
      <button onClick={() => action('/simulator/reset')}><RefreshCw size={14} /> Reset</button>
      <button className="primary" onClick={() => action('/simulator/' + (run ? 'pause' : 'start'))}>{run ? <Pause size={14} /> : <Play size={14} />} {run ? 'Pause stream' : 'Start stream'}</button></div>);

  const openAlerts = alerts.filter(a => a.status !== 'closed'), critOpen = openAlerts.filter(a => a.severity === 'critical').length;
  const mood = petMood({ connected, run, critical: critOpen, open: openAlerts.length, thinking: aiBusy });
  const sel = selected;
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand"><div className="logo"><Shield size={23} /></div><div><b>AEGIS <em>/ SIEM</em></b><small>SECURITY OPERATIONS</small></div></div>
        <div className="env"><i className="live" /><div><b>LAB ENVIRONMENT</b><small>SIMULATION MODE</small></div><span>DEV</span></div>
        <label>WORKSPACE</label>
        <button className={'nav' + (view === 'overview' ? ' active' : '')} onClick={() => go('overview')}><Gauge size={17} /> Overview</button>
        <button className="nav" onClick={() => go('alerts')}><ShieldAlert size={17} /> Detections <span>{ov?.active_alerts ?? alerts.filter(a => a.status !== 'closed').length}</span></button>
        <button className="nav" onClick={() => go('events')}><Activity size={17} /> Event explorer</button>
        <button className={'nav' + (view === 'map' ? ' active' : '')} onClick={() => go('map')}><MapPinned size={17} /> Threat map <span>{mapBase.length}</span></button>
        <button className="nav" onClick={() => go('simulator')}><Terminal size={17} /> Simulator</button>
        <label className="system">SYSTEM</label>
        <div className="side-status"><Database size={16} /><div><b>In-memory store</b><small>Resets on restart</small></div></div>
        <div className="side-status"><Wifi size={16} /><div><b>Event stream</b><small>{connected ? 'WebSocket connected' : 'Connecting...'}</small></div></div>
        <div className="profile"><div>LAB</div><span><b>Analyst Workbench</b><small>Local prototype</small></span></div>
      </aside>

      <main>
        <header>
          <div>Workspace <ChevronRight size={13} /> <b>{view === 'map' ? 'Threat map' : 'Security overview'}</b></div>
          <span className="connection"><i className={connected ? 'live' : 'amber'} />{connected ? 'STREAM CONNECTED' : 'CONNECTING'}</span>
          <button className="iconbtn" onClick={refresh} aria-label="Refresh"><RefreshCw size={16} /></button>
          <button className={'iconbtn aibtn' + (aiOpen ? ' on' : '')} onClick={() => setAiOpen(o => !o)} aria-label="AI analyst" title="AI analyst (Aegi)"><Sparkles size={16} /></button>
          <button className="iconbtn bell" aria-label="Notifications"><Bell size={16} /></button><div className="user">A</div>
        </header>

        <div className="content">
          {error && <div className="error"><AlertTriangle size={16} />{error}<button onClick={() => setError('')}><X size={14} /></button></div>}

          {/* ================= OVERVIEW ================= */}
          <div className={view === 'overview' ? '' : 'hide'}>
            <section className="heading"><div><div className="eyebrow"><i /> SECURITY INFORMATION &amp; EVENT MANAGEMENT</div><h1>Security <span>Overview</span></h1>
              <p>Monitor simulated telemetry, investigate detections, and validate your detection rules.</p></div>{actions}</section>
            {filterBar(tab === 'alerts')}

            <section className="stats">
              <Stat icon={Activity} tone="cyan" label="EVENTS INGESTED" value={(hasFilter ? fEvents.length : totalIngested).toLocaleString()}
                note={`${last60} in last 60 sec${hasFilter ? ` · ${totalIngested.toLocaleString()} total` : ''}`} active={tab === 'events'} hint="Open the event explorer"
                onClick={() => go('events')} />
              <Stat icon={ShieldAlert} tone="orange" label="ACTIVE ALERTS" value={active.length} note="New + investigating" active={f.status === 'active'} hint="Show active detections"
                onClick={() => { setStatus(f.status === 'active' ? 'all' : 'active'); go('alerts'); }} />
              <Stat icon={AlertTriangle} tone="red" label="CRITICAL / HIGH" value={`${critN} / ${highN}`} note="Requires attention" active={critHighOn} hint="Filter to critical + high"
                onClick={() => { setF(x => ({ ...x, severity: critHighOn ? [] : ['critical', 'high'] })); go('alerts'); }} />
              <Stat icon={Server} tone="teal" label="AFFECTED HOSTS" value={hostCounts.length} note="Hosts with active alerts" active={!!f.host || hostsOpen} hint="Pick a host to filter by"
                cls="hostcard" onClick={() => setHostsOpen(o => !o)}>
                {hostsOpen && <div className="hostpop" onClick={e => e.stopPropagation()}>
                  {hostCounts.length ? hostCounts.map(([h, n]) => <button key={h} className={f.host === h ? 'on' : ''} onClick={() => { toggleHost(h); setHostsOpen(false); }}><span className="mono">{h}</span><b>{n}</b></button>) : <small>No hosts with active alerts</small>}
                </div>}
              </Stat>
            </section>

            <section className="charts">
              <div className="panel"><div className="paneltitle"><div><h2>Event ingestion</h2><p>Events observed over the last 12 minutes. Click a point to filter by that minute.</p></div><span className="livebadge"><i className="live" /> LIVE</span></div>
                <div className="legend"><span><i /> Security events</span><small>events / min</small></div>
                <div className="area"><ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={chartData} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}
                    onClick={s => { const i = s?.activeTooltipIndex ?? s?.activeIndex; const d = chartData[Number(i)] || chartData.find(x => x.time === s?.activeLabel); if (d) toggleMinute(d.ts); }}>
                    <defs><linearGradient id="fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#22d3ee" stopOpacity=".28" /><stop offset="100%" stopColor="#22d3ee" stopOpacity="0" /></linearGradient></defs>
                    <CartesianGrid stroke="#1b2a3b" strokeDasharray="3 5" vertical={false} />
                    <XAxis dataKey="time" tick={{ fill: '#71849b', fontSize: 10 }} axisLine={false} tickLine={false} interval={2} />
                    <YAxis tick={{ fill: '#71849b', fontSize: 10 }} axisLine={false} tickLine={false} allowDecimals={false} />
                    <Tooltip contentStyle={{ background: '#0d1a2a', border: '1px solid #263b50', borderRadius: 8, color: '#dbeafe', fontSize: 12 }} cursor={{ stroke: '#22d3ee66' }} />
                    {f.minute != null && chartData.some(d => d.ts === f.minute) && <ReferenceLine x={hhmm(f.minute)} stroke="#fbbf24" strokeDasharray="3 3" />}
                    <Area type="monotone" dataKey="events" stroke="#22d3ee" strokeWidth={2} fill="url(#fill)" activeDot={{ r: 5, style: { cursor: 'pointer' } }} />
                  </AreaChart></ResponsiveContainer></div>
                <div className="chartfoot"><span><i className="live" /> Ingestion engine active</span><span>{ov?.events_per_minute || rate} events/min configured</span></div></div>

              <div className="panel"><div className="paneltitle"><div><h2>Alert severity</h2><p>{f.status === 'all' ? 'Open' : pretty(f.status)} alerts · click to filter</p></div><Shield size={18} color="#54d8e7" /></div>
                {donut.length ? <div className="donut"><ResponsiveContainer width="100%" height="100%"><PieChart>
                  <Pie data={donut} dataKey="value" nameKey="name" innerRadius={53} outerRadius={72} paddingAngle={4} stroke="none" onClick={d => toggleSev(d?.name ?? d?.payload?.name, true)}>
                    {donut.map(s => <Cell key={s.name} fill={sevColors[s.name]} fillOpacity={f.severity.length && !f.severity.includes(s.name) ? .3 : 1} style={{ cursor: 'pointer', outline: 'none' }} />)}
                  </Pie><Tooltip /></PieChart></ResponsiveContainer>
                  <div><b>{donutTotal}</b><small>{f.status === 'all' ? 'ACTIVE' : f.status.toUpperCase()}</small></div></div>
                  : <div className="emptychart"><Shield size={25} /><span>No alerts match</span><small>Trigger a scenario or clear filters.</small></div>}
                <div className="sevlegend">{SEVS.map(s => (
                  <div key={s} role="button" tabIndex={0} className={f.severity.includes(s) ? 'on' : ''} onClick={() => toggleSev(s, true)}
                    onKeyDown={e => e.key === 'Enter' && toggleSev(s, true)}><i style={{ background: sevColors[s] }} /><span>{pretty(s)}</span><b>{sevCounts[s]}</b></div>))}</div></div>
            </section>

            <section className="panel simulator" id="simulator"><div className="paneltitle"><div><div className="eyebrow small"><i /> CONTROLLED SCENARIOS</div><h2>Attack simulation console</h2><p>Safe synthetic scenarios to test rules. No commands run on your machine.</p></div>
              <span className="simstate"><i className={run ? 'live' : 'amber'} />{run ? 'SIMULATOR RUNNING' : 'SIMULATOR PAUSED'}</span></div>
              <div className="scenarios">
                <Scenario icon={LockKeyhole} tone="orange" title="Brute-force pattern" desc="Repeated failed sign-ins" onClick={() => action('/simulator/trigger/brute-force')} />
                <Scenario icon={Terminal} tone="violet" title="Suspicious PowerShell" desc="Simulated endpoint behavior" onClick={() => action('/simulator/trigger/powershell')} />
                <Scenario icon={Globe2} tone="cyan" title="Unusual outbound traffic" desc="Documentation-only test IP" onClick={() => action('/simulator/trigger/outbound')} />
                <Scenario icon={ShieldAlert} tone="red" title="Malware indicator" desc="Synthetic file/hash indicator" onClick={() => action('/simulator/trigger/malware')} />
                <Scenario icon={Radar} tone="teal" title="Network scan" desc="Sequential port probing" onClick={() => action('/simulator/trigger/scan')} />
                <Scenario icon={UserCheck} tone="yellow" title="Unusual login location" desc="Employee sign-in from new place" onClick={() => action('/simulator/trigger/unusual-login')} />
              </div>
              <div className="rate"><div><Gauge size={16} /><span>Event generation rate</span><b>{rate} <small>events / min</small></b></div>
                <input type="range" min="5" max="120" step="5" value={rate} aria-label="Events per minute" onChange={e => setRate(+e.target.value)}
                  onPointerDown={() => { rateEditing.current = true; }} onPointerUp={commitRate} onKeyUp={commitRate} />
                <div className="range"><span>5 / min</span><span>120 / min</span></div></div></section>

            <section className="panel tablepanel" id="telemetry">
              <div className="paneltitle tabletitle"><div><h2>Security telemetry</h2><p>Review events and investigate detections</p></div>
                <div className="tools"><span className="livebadge"><i className={run ? 'live' : 'amber'} /> {run ? 'LIVE' : 'PAUSED'}</span><RowLimit value={rowLimit} onChange={setRowLimit} /></div></div>
              <div className="tabs"><button className={tab === 'alerts' ? 'chosen' : ''} onClick={() => setTab('alerts')}>Detections <span>{fAlerts.length}</span></button>
                <button className={tab === 'events' ? 'chosen' : ''} onClick={() => setTab('events')}>All events <span>{fEvents.length}</span></button></div>
              <DataTable kind={tab === 'alerts' ? 'alert' : 'event'} rows={tab === 'alerts' ? fAlerts : fEvents} limit={rowLimit} f={f}
                onOpen={tab === 'alerts' ? setSelected : openEvent} toggleSev={toggleSev} toggleHost={toggleHost} toggleQuery={toggleQuery} />
              <div className="tablefoot"><span>Showing {Math.min(tab === 'alerts' ? fAlerts.length : fEvents.length, rowLimit)} of {(tab === 'alerts' ? fAlerts : fEvents).length} matching · limit {rowLimit} · new records stream in automatically</span>
                <button onClick={refresh}>Refresh data <RefreshCw size={13} /></button></div>
            </section>
          </div>

          {/* ================= THREAT MAP ================= */}
          <div className={view === 'map' ? '' : 'hide'}>
            <section className="heading"><div><div className="eyebrow"><i /> THREAT VISUALIZATION</div><h1>Threat <span>Map</span></h1>
              <p>Where suspicious activity originates: failed and unusual logins, scanning, outbound traffic and malware indicators.</p></div>{actions}</section>
            <div className="simbanner"><AlertTriangle size={15} /><div>
              <b>{realCount ? `${simCount} simulated and ${realCount} observed events` : 'All events on this map are simulated'}</b>
              <span>Events come from the built-in generator (source: simulator), not real attackers; no live threat feed is connected. {gip?.enabled
                ? `Locations: MaxMind ${gip.database_type || 'GeoIP'} database loaded. Real public IPs are looked up in it, private IPs appear at the lab network, and the simulator's documentation-range IPs (which have no real location) use labeled placeholder cities.`
                : 'Locations: no GeoIP database found, so documentation-range IPs use labeled placeholder cities. Add a MaxMind .mmdb file to backend/data to resolve real public IPs.'}
                {unlocated > 0 && ` ${unlocated} suspicious event${unlocated === 1 ? ' has' : 's have'} no resolvable location and ${unlocated === 1 ? 'is' : 'are'} not drawn.`}</span>
              {gip?.enabled && gip.attribution && <span className="attrib">{gip.attribution}</span>}</div></div>
            {filterBar(false)}
            <ThreatMap events={mapEvents} base={mapBase} filters={f} toggleType={toggleType} selKey={selKey} setSelKey={setSelKey}
              onOpenEvent={openEvent} alertByEvent={alertByEvent} minimized={mapMin} setMinimized={setMapMin} full={mapFull} setFull={setMapFull}
              windowMin={mapWin} setWindowMin={setMapWin} streaming={!!run} geoip={gip} />
            <section className="panel tablepanel">
              <div className="paneltitle tabletitle"><div><h2>Map event log</h2><p>Same events as the map, newest first{selKey ? ' · selected location highlighted on map' : ''}</p></div>
                <div className="tools"><RowLimit value={rowLimit} onChange={setRowLimit} /></div></div>
              <DataTable kind="event" rows={mapEvents} limit={rowLimit} f={f} onOpen={openEvent} toggleSev={toggleSev} toggleHost={toggleHost} toggleQuery={toggleQuery} />
              <div className="tablefoot"><span>Showing {Math.min(mapEvents.length, rowLimit)} of {mapEvents.length} map events · limit {rowLimit}</span></div>
            </section>
          </div>

          <footer><span><i className="live" /> AEGIS Mini SIEM <b>v0.2.0</b></span><span>SIMULATION ONLY · NO REAL ENDPOINTS CONNECTED</span><span>Built for SOC learning</span></footer>
        </div>
      </main>

      {sel && <div className="backdrop" onClick={() => setSelected(null)}><aside className="drawer" onClick={e => e.stopPropagation()}>
        <div className="drawertop"><div><div className="eyebrow small"><i /> INVESTIGATION DETAILS</div><h2>{sel.title || typeLabel(sel.event_type)}</h2></div><button className="iconbtn" onClick={() => setSelected(null)} aria-label="Close"><X size={16} /></button></div>
        <div className="badges"><Sev v={sel.severity} />{sel.status && <Status v={sel.status} />}{sel.geo?.simulated && <span className="simtag">SIMULATED GEO</span>}{sel.geo?.source === 'geoip' && <span className="simtag geotag">GEOIP</span>}</div>
        <p className="description">{sel.description || sel.message}</p><h3>EVENT CONTEXT</h3>
        {[['Timestamp', sel.timestamp ? new Date(sel.timestamp).toLocaleString() : '—'], ['Attack type', typeLabel(sel.event_type)], ['Hostname', sel.hostname], ['Username', sel.username], ['Source IP', sel.source_ip],
          ['Destination IP', sel.destination_ip || '—'], [sel.geo?.role === 'destination' ? 'Destination location' : 'Source location', sel.geo ? `${sel.geo.internal ? 'Lab network (internal)' : placeLabel(sel.geo)}${geoBadge(sel.geo) ? ' · ' + geoBadge(sel.geo) : ''}` : '—'],
          ['Rule ID', sel.rule_id || '—'], ['MITRE technique', sel.mitre_technique || '—'], ['Data source', (sel.source || 'simulator') === 'simulator' ? 'Simulator (synthetic)' : sel.source], ['Event ID', sel.event_id || sel.id]]
          .map(([k, v]) => <div className="detailrow" key={k}><span>{k}</span><b>{v}</b></div>)}
        <div className="draweractions">
          <button className="aiaction" onClick={() => openAi(toAiTarget(sel), 'analyze')}><Sparkles size={14} /> Analyze with AI</button>
          {sel.status && sel.status !== 'investigating' && sel.status !== 'closed' && <button className="primary" onClick={() => update(sel, 'investigating')}>Mark investigating</button>}
          {sel.status && sel.status !== 'closed' && <button onClick={() => update(sel, 'closed')}><CheckCircle2 size={14} /> Close detection</button>}
          {sel.status === 'closed' && <button onClick={() => update(sel, 'new')}>Reopen detection</button>}
          <button onClick={() => { setF(x => ({ ...x, host: sel.hostname })); setSelected(null); }}><Server size={14} /> Filter dashboard to {sel.hostname}</button>
          {sel.geo && <button onClick={() => showOnMap(sel.geo)}><MapPinned size={14} /> Show on threat map</button>}
        </div>
        <div className="note"><ShieldAlert size={15} /> Synthetic evidence for training only. Validate rules against real telemetry before production use.</div>
      </aside></div>}

      <AiAssistant open={aiOpen} onClose={() => setAiOpen(false)} target={aiTarget} onClearTarget={() => setAiTarget(null)} auto={aiAuto} status={aiStatus}
        mood={mood} petHidden={petHidden} onTogglePet={() => setPetHidden(h => !h)} onBusy={setAiBusy} shifted={!!selected} />
      <AiCompanion alerts={alerts} mood={mood} critical={critOpen} streak={streak} kudos={kudos} hidden={petHidden || aiOpen} suspend={!!selected || mapFull}
        onOpen={() => setAiOpen(true)} onExplain={a => openAi(toAiTarget(a), 'analyze')}
        onReview={() => { setStatus('new'); go('alerts'); }} />
    </div>
  );
}

function FilterBar({ f, setQuery, toggleSev, setStatus, toggleType, toggleHost, toggleMinute, clearAll, showStatus, hasFilter }) {
  const chips = [
    ...f.severity.map(s => ({ k: 's' + s, l: `Severity: ${s}`, x: () => toggleSev(s) })),
    ...f.types.map(t => ({ k: 't' + t, l: typeLabel(t), x: () => toggleType(t) })),
    ...(f.host ? [{ k: 'h', l: `Host: ${f.host}`, x: () => toggleHost(f.host) }] : []),
    ...(f.minute != null ? [{ k: 'm', l: `Minute: ${hhmm(f.minute)}`, x: () => toggleMinute(f.minute) }] : []),
    ...(f.status !== 'all' ? [{ k: 'st', l: `Status: ${pretty(f.status)}`, x: () => setStatus('all') }] : []),
  ];
  return (
    <section className="filterbar">
      <div className="search"><Search size={14} /><input placeholder="Search host, user, IP, city..." value={f.query} onChange={e => setQuery(e.target.value)} aria-label="Search" />
        {f.query && <button onClick={() => setQuery('')} aria-label="Clear search"><X size={13} /></button>}</div>
      <div className="chips" role="group" aria-label="Severity">{SEVS.map(s => (
        <button key={s} className={'chip' + (f.severity.includes(s) ? ' on' : '')} onClick={() => toggleSev(s)}><i style={{ background: sevColors[s] }} />{s}</button>))}</div>
      {showStatus && <div className="filter"><span>Status</span><select value={f.status} onChange={e => setStatus(e.target.value)} aria-label="Alert status">
        <option value="all">All</option><option value="active">Active</option><option value="new">New</option><option value="investigating">Investigating</option><option value="closed">Closed</option></select></div>}
      {hasFilter ? <button className="clearall" onClick={clearAll}><X size={12} /> Clear all</button> : null}
      {chips.length > 0 && <div className="activechips">{chips.map(c => <span key={c.k} className="achip">{c.l}<button onClick={c.x} aria-label={`Remove ${c.l}`}><X size={11} /></button></span>)}</div>}
    </section>);
}

function RowLimit({ value, onChange }) {
  return <div className="seg" role="group" aria-label="Rows to display"><label>Rows</label>{ROW_OPTIONS.map(n => <button key={n} className={value === n ? 'on' : ''} onClick={() => onChange(n)}>{n}</button>)}</div>;
}

function DataTable({ kind, rows, limit, f, onOpen, toggleSev, toggleHost, toggleQuery }) {
  const shown = rows.slice(0, limit), nowMs = Date.now();
  const stop = fn => e => { e.stopPropagation(); fn(); };
  const host = r => <><b className={'mono link' + (f.host === r.hostname ? ' on' : '')} title="Filter by host" onClick={stop(() => toggleHost(r.hostname))}>{r.hostname}</b><small>{r.username}</small></>;
  const ip = r => <span className={'mono link' + (f.query === r.source_ip ? ' on' : '')} title="Search this IP" onClick={stop(() => toggleQuery(r.source_ip))}>{r.source_ip}</span>;
  const sev = r => <Sev v={r.severity} onClick={stop(() => toggleSev(r.severity, true))} active={f.severity.includes(r.severity)} />;
  const fresh = r => nowMs - Date.parse(r.timestamp) < 4000 ? 'newrow' : '';
  return (
    <div className="tablewrap"><table>
      {kind === 'alert' ? <>
        <thead><tr><th>SEVERITY</th><th>DETECTION</th><th>HOST / USER</th><th>SOURCE IP</th><th>TIME</th><th>STATUS</th><th /></tr></thead>
        <tbody>{shown.map(a => <tr key={a.id} className={fresh(a)} onClick={() => onOpen(a)}><td>{sev(a)}</td><td><b>{a.title}</b><small>{a.rule_id} · {a.mitre_technique || '—'}</small></td><td>{host(a)}</td><td>{ip(a)}</td><td className="mono">{tm(a.timestamp)}</td><td><Status v={a.status} /></td><td><ChevronRight size={14} /></td></tr>)}
          {!shown.length && <Empty col="7" />}</tbody></> : <>
        <thead><tr><th>TIME</th><th>EVENT</th><th>HOST / USER</th><th>SOURCE IP</th><th>ORIGIN</th><th>SEVERITY</th><th /></tr></thead>
        <tbody>{shown.map(e => <tr key={e.id} className={fresh(e)} onClick={() => onOpen(e)}><td className="mono">{tm(e.timestamp)}</td><td><b>{typeLabel(e.event_type)}</b><small>{e.message}</small></td><td>{host(e)}</td><td>{ip(e)}</td>
          <td>{e.geo ? <>{placeLabel(e.geo)}{geoBadge(e.geo) && <small>{geoBadge(e.geo)}</small>}</> : <small>no location</small>}</td><td>{sev(e)}</td><td><ChevronRight size={14} /></td></tr>)}
          {!shown.length && <Empty col="7" />}</tbody></>}
    </table></div>);
}

function Stat({ icon: Icon, label, value, note, tone, onClick, active, hint, cls = '', children }) {
  return <div className={`stat click ${cls}${active ? ' on' : ''}`} role="button" tabIndex={0} title={hint} onClick={onClick}
    onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onClick(); } }}>
    <div className={'staticon ' + tone}><Icon size={18} /></div><div><label>{label}</label><strong>{value}</strong><small>{note}</small></div>{children}</div>;
}
function Scenario({ icon: Icon, tone, title, desc, onClick }) {
  return <button className="scenario" onClick={onClick}><span className={'scenarioicon ' + tone}><Icon size={17} /></span><span><b>{title}</b><small>{desc}</small></span><ChevronRight size={14} /></button>;
}
function Empty({ col }) {
  return <tr><td colSpan={col}><div className="emptytable"><Shield size={22} /><b>No matching records</b><span>Wait for events, trigger a scenario, or clear filters.</span></div></td></tr>;
}
export default App;