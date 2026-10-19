import { useEffect, useMemo, useRef, useState } from 'react';
import { ChevronDown, ChevronUp, Globe2, Maximize2, Minimize2, RotateCcw, X, ZoomIn, ZoomOut } from 'lucide-react';
import { geoDistance, geoGraticule10, geoNaturalEarth1, geoOrthographic, geoPath } from 'd3-geo';
import { feature, mesh } from 'topojson-client';
import world from 'world-atlas/countries-110m.json';
import { ATTACK_TYPES, Sev, Status, geoKey, placeLabel, sevColors, sevRank, tm, typeLabel, usePersisted } from './common';

const LAND = feature(world, world.objects.land);
const BORDERS = mesh(world, world.objects.countries, (a, b) => a !== b);
const GRAT = geoGraticule10();
const SPHERE = { type: 'Sphere' };
const HQ_DEFAULT = { lat: 14.5995, lon: 120.9842 };   // Manila, Philippines; the backend value (HQ_LAT/HQ_LON) overrides this
const WINDOWS = [[5, '5m'], [15, '15m'], [60, '1h'], [0, 'All']];
const K_MAX = 8, DEG = 180 / Math.PI;
const clamp = (v, a, b) => Math.max(a, Math.min(b, v));

function buildProjection(mode, w, h, v) {
  if (mode === 'globe') {
    return geoOrthographic().scale(Math.min(w, h) / 2 * .92 * v.k).translate([w / 2, h / 2]).rotate([v.lam, v.phi]).clipAngle(90).precision(.5);
  }
  const p = geoNaturalEarth1().fitSize([w, h], SPHERE);
  return p.scale(p.scale() * v.k).translate([w / 2 + v.x, h / 2 + v.y]).precision(.5);
}
function clampFlat(v, size, base) {
  const lim = (span, view) => Math.max(0, (span * v.k - view) / 2) + view * .2;
  const lx = lim(base.bw, size.w), ly = lim(base.bh, size.h);
  return { ...v, x: clamp(v.x, -lx, lx), y: clamp(v.y, -ly, ly) };
}
function applyZoom(v, nk, mode, size, base, rect, cx, cy) {
  const k = clamp(nk, mode === 'globe' ? .7 : 1, K_MAX);
  if (mode === 'globe') return { ...v, k };
  const px = (cx ?? rect.left + rect.width / 2) - rect.left - size.w / 2, py = (cy ?? rect.top + rect.height / 2) - rect.top - size.h / 2, f = k / v.k;
  return clampFlat({ ...v, k, x: px - (px - v.x) * f, y: py - (py - v.y) * f }, size, base);
}

export default function ThreatMap({
  events, base: typeBase, filters, toggleType, selKey, setSelKey, onOpenEvent, alertByEvent,
  minimized, setMinimized, full, setFull, windowMin, setWindowMin, streaming, geoip,
}) {
  const [now, setNow] = useState(Date.now());
  const [mode, setMode] = usePersisted('aegis.mapMode', 'flat', v => v === 'flat' || v === 'globe');
  const [size, setSize] = useState({ w: 800, h: 400 });
  const [v, setV] = useState({ k: 1, x: 0, y: 0, lam: -HQ_DEFAULT.lon, phi: -20 });
  const stageRef = useRef(null), dragRef = useRef(null), ptrs = useRef(new Map()), pinch = useRef(null), moved = useRef(false), tween = useRef(0);
  const live = useRef({});
  const collapsed = minimized && !full;

  const mapBox = useMemo(() => {
    const b = geoPath(geoNaturalEarth1().fitSize([size.w, size.h], SPHERE)).bounds(SPHERE);
    return { bw: b[1][0] - b[0][0], bh: b[1][1] - b[0][1] };
  }, [size]);
  const proj = useMemo(() => buildProjection(mode, size.w, size.h, v), [mode, size, v]);
  const path = useMemo(() => geoPath(proj), [proj]);
  live.current = { mode, size, base: mapBox, full, v };

  useEffect(() => { const t = setInterval(() => setNow(Date.now()), 2000); return () => clearInterval(t); }, []);
  // Track the stage size (ignored while collapsed so the view isn't reset).
  useEffect(() => {
    const el = stageRef.current; if (!el) return;
    const upd = () => { const r = el.getBoundingClientRect(); const w = Math.round(r.width), h = Math.round(r.height); if (w > 0 && h > 0) setSize(s => s.w === w && s.h === h ? s : { w, h }); };
    upd(); if (typeof ResizeObserver === 'undefined') return;
    const ro = new ResizeObserver(upd); ro.observe(el); return () => ro.disconnect();
  }, []);

  const zoomBy = (f, cx, cy) => setV(cur => { const { mode: m, size: s, base: b } = live.current; return applyZoom(cur, cur.k * f, m, s, b, stageRef.current.getBoundingClientRect(), cx, cy); });
  const zoomTo = (k, cx, cy) => setV(cur => { const { mode: m, size: s, base: b } = live.current; return applyZoom(cur, k, m, s, b, stageRef.current.getBoundingClientRect(), cx, cy); });

  // Drag / rotate / pinch use window listeners so a drag keeps working when the pointer leaves the map.
  useEffect(() => {
    const move = e => {
      const pt = ptrs.current.get(e.pointerId); if (!pt) return;
      const ddx = e.clientX - pt.x, ddy = e.clientY - pt.y; pt.x = e.clientX; pt.y = e.clientY;
      if (ptrs.current.size >= 2 && pinch.current) {
        const [a, b] = [...ptrs.current.values()];
        zoomTo(pinch.current.k * (Math.hypot(a.x - b.x, a.y - b.y) || 1) / pinch.current.d, (a.x + b.x) / 2, (a.y + b.y) / 2); return;
      }
      const dr = dragRef.current; if (!dr) return;
      if (!moved.current && Math.abs(e.clientX - dr.sx) + Math.abs(e.clientY - dr.sy) > 4) moved.current = true;
      if (!moved.current) return;
      const { mode: m, size: s, base: b } = live.current;
      if (m === 'globe') setV(cur => { const sc = Math.min(s.w, s.h) / 2 * .92 * cur.k; return { ...cur, lam: cur.lam + ddx / sc * DEG, phi: clamp(cur.phi - ddy / sc * DEG, -90, 90) }; });
      else setV(cur => clampFlat({ ...cur, x: cur.x + ddx, y: cur.y + ddy }, s, b));
    };
    const up = e => {
      ptrs.current.delete(e.pointerId);
      if (ptrs.current.size < 2) pinch.current = null;
      if (ptrs.current.size === 0) { dragRef.current = null; setTimeout(() => { moved.current = false; }, 0); }
    };
    window.addEventListener('pointermove', move); window.addEventListener('pointerup', up); window.addEventListener('pointercancel', up);
    return () => { window.removeEventListener('pointermove', move); window.removeEventListener('pointerup', up); window.removeEventListener('pointercancel', up); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  // Wheel zoom: Ctrl/Cmd + scroll (also trackpad pinch) on the page, plain scroll in full screen, so page scrolling is never trapped.
  useEffect(() => {
    const el = stageRef.current; if (!el) return;
    const on = e => {
      if (!(e.ctrlKey || e.metaKey || live.current.full)) return;
      e.preventDefault();
      const d = e.deltaY * (e.deltaMode === 1 ? 33 : 1);
      zoomBy(Math.exp(-d * (Math.abs(d) < 30 ? .012 : .0022)), e.clientX, e.clientY);
    };
    el.addEventListener('wheel', on, { passive: false }); return () => el.removeEventListener('wheel', on);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const down = e => {
    if (e.pointerType === 'mouse' && e.button !== 0) return;
    cancelAnimationFrame(tween.current);
    ptrs.current.set(e.pointerId, { x: e.clientX, y: e.clientY }); moved.current = false;
    if (ptrs.current.size === 1) dragRef.current = { sx: e.clientX, sy: e.clientY };
    else if (ptrs.current.size === 2) { const [a, b] = [...ptrs.current.values()]; pinch.current = { d: Math.hypot(a.x - b.x, a.y - b.y) || 1, k: live.current.v.k }; moved.current = true; }
  };

  const groups = useMemo(() => {
    const m = new Map();
    for (const e of events) {
      const key = geoKey(e.geo); let g = m.get(key);
      if (!g) { g = { key, label: placeLabel(e.geo), geo: e.geo, lat: e.geo.lat, lon: e.geo.lon, internal: !!e.geo.internal, events: [], max: 'info' }; m.set(key, g); }
      g.events.push(e); if (sevRank[e.severity] > sevRank[g.max]) g.max = e.severity;
    }
    return [...m.values()].sort((a, b) => b.events.length - a.events.length);
  }, [events]);
  const hq = useMemo(() => { const e = events.find(x => x.geo?.internal); return e ? { lat: e.geo.lat, lon: e.geo.lon } : geoip?.hq ? { lat: geoip.hq.lat, lon: geoip.hq.lon } : HQ_DEFAULT; }, [events, geoip]);
  const typeCounts = useMemo(() => { const c = {}; typeBase.forEach(e => { c[e.event_type] = (c[e.event_type] || 0) + 1; }); return c; }, [typeBase]);
  const sel = groups.find(g => g.key === selKey) || null;
  const critical = events.filter(e => e.severity === 'critical').length;

  const flyTo = (lam, phi) => {
    cancelAnimationFrame(tween.current);
    const from = live.current.v, dl = ((lam - from.lam + 540) % 360) - 180, t0 = performance.now();
    const step = t => { const u = Math.min(1, (t - t0) / 450), k = 1 - Math.pow(1 - u, 3); setV(cur => ({ ...cur, lam: from.lam + dl * k, phi: from.phi + (phi - from.phi) * k })); if (u < 1) tween.current = requestAnimationFrame(step); };
    tween.current = requestAnimationFrame(step);
  };
  // Whenever a location gets selected (marker, list row, or "Show on threat map") bring it into view.
  useEffect(() => {
    const g = groups.find(x => x.key === selKey); if (!g || collapsed) return;
    if (mode === 'globe') flyTo(-g.lon, -g.lat);
    else if (live.current.v.k > 1) { const p = proj([g.lon, g.lat]); if (p) setV(cur => clampFlat({ ...cur, x: cur.x + size.w / 2 - p[0], y: cur.y + size.h / 2 - p[1] }, size, mapBox)); }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selKey]);
  useEffect(() => () => cancelAnimationFrame(tween.current), []);

  const reset = () => setV(mode === 'globe' ? { k: 1, x: 0, y: 0, lam: -hq.lon, phi: -20 } : { ...v, k: 1, x: 0, y: 0 });
  const changeMode = m => { if (m !== mode) { setMode(m); setV(cur => ({ ...cur, k: 1, x: 0, y: 0 })); } };
  const pick = g => setSelKey(selKey === g.key ? null : g.key);

  const center = [-v.lam, -v.phi];
  const visible = (lon, lat) => mode !== 'globe' || geoDistance([lon, lat], center) < Math.PI / 2 - .03;
  const hqPt = visible(hq.lon, hq.lat) ? proj([hq.lon, hq.lat]) : null;
  const drawn = [...groups].sort((a, b) => (a.key === selKey) - (b.key === selKey));
  const sources = new Set(events.map(e => e.geo?.source));
  const tags = [];
  if (sources.has('simulated')) tags.push(['simtag', 'SIMULATED GEODATA', 'Placeholder locations for documentation-range IPs']);
  if (sources.has('geoip')) tags.push(['simtag geotag', 'GEOIP · MAXMIND', 'Approximate locations from the MaxMind database']);
  if (!tags.length) tags.push(geoip?.enabled ? ['simtag geotag', 'GEOIP · MAXMIND', 'MaxMind database loaded'] : ['simtag', 'SIMULATED GEODATA', 'No GeoIP database configured']);
  const landD = useMemo(() => path(LAND), [path]), bordersD = useMemo(() => path(BORDERS), [path]);
  const gratD = useMemo(() => path(GRAT), [path]), sphereD = useMemo(() => path(SPHERE), [path]);

  return (
    <>
      {full && <div className="mapfullbackdrop" onClick={() => setFull(false)} />}
      <section className={'panel mapcard' + (full ? ' full' : '')}>
        <div className="maphead">
          <div className="mapttl"><Globe2 size={18} color="#54d8e7" /><div><h2>Threat map</h2><p>Suspicious activity by origin, streamed live</p></div></div>
          {tags.map(([c, t, tip]) => <span key={t} className={c} title={tip}>{t}</span>)}
          <span className="livebadge"><i className={streaming ? 'live' : 'amber'} /> {streaming ? 'LIVE' : 'PAUSED'}</span>
          <div className="minisum">
            <span><b>{groups.length}</b> locations</span><span><b>{events.length}</b> events</span>
            <span className={critical ? 'crit' : ''}><b>{critical}</b> critical</span>
          </div>
          <div className="mapctl">
            <button className="iconbtn" onClick={() => setMinimized(!minimized && !full ? true : false)} disabled={full}
              title={collapsed ? 'Expand threat map' : 'Minimize threat map'} aria-label={collapsed ? 'Expand threat map' : 'Minimize threat map'}>
              {collapsed ? <ChevronDown size={16} /> : <ChevronUp size={16} />}
            </button>
            <button className="iconbtn" onClick={() => setFull(!full)} title={full ? 'Exit full screen (Esc)' : 'Maximize'} aria-label="Toggle full screen">
              {full ? <Minimize2 size={15} /> : <Maximize2 size={15} />}
            </button>
          </div>
        </div>

        <div className={'mapwrap' + (collapsed ? ' min' : '')} aria-hidden={collapsed}><div className="mapinner">
          <div className="maptools">
            <div className="chips">
              {ATTACK_TYPES.map(t => (
                <button key={t} className={'chip' + (filters.types.includes(t) ? ' on' : '')} onClick={() => toggleType(t)}>
                  {typeLabel(t)} <span>{typeCounts[t] || 0}</span>
                </button>))}
            </div>
            <div className="maptoolset">
              <div className="seg" role="group" aria-label="Map view"><label>View</label>
                <button className={mode === 'flat' ? 'on' : ''} onClick={() => changeMode('flat')}>Flat</button>
                <button className={mode === 'globe' ? 'on' : ''} onClick={() => changeMode('globe')}>Globe</button></div>
              <div className="seg" role="group" aria-label="Time window"><label>Window</label>
                {WINDOWS.map(([m, l]) => <button key={m} className={windowMin === m ? 'on' : ''} onClick={() => setWindowMin(m)}>{l}</button>)}</div>
            </div>
          </div>

          <div className="mapgrid">
            <div className="mapstage" ref={stageRef}>
              <svg className="mapsvg" width={size.w} height={size.h} viewBox={`0 0 ${size.w} ${size.h}`} onPointerDown={down} role="img" aria-label="Threat map">
                <defs><radialGradient id="globeglow" cx="40%" cy="35%" r="75%"><stop offset="0%" stopColor="#12304a" /><stop offset="100%" stopColor="#071524" /></radialGradient></defs>
                <path className={'ocean' + (mode === 'globe' ? ' globe' : '')} d={sphereD} />
                <path className="grat" d={gratD} />
                <path className="land" d={landD} />
                <path className="borders" d={bordersD} />
                {mode === 'globe' && <path className="sphereline" d={sphereD} />}
                {groups.filter(g => !g.internal).map(g => {
                  const d = path({ type: 'LineString', coordinates: [[g.lon, g.lat], [hq.lon, hq.lat]] });
                  return d ? <path key={'a' + g.key} className="arc" d={d} stroke={sevColors[g.max]} opacity={selKey && selKey !== g.key ? .18 : .65} /> : null;
                })}
                {hqPt && <g className="hqmark" transform={`translate(${hqPt[0]} ${hqPt[1]})`}><rect x="-4" y="-4" width="8" height="8" transform="rotate(45)" /><text className="mklabel" y="-10" textAnchor="middle">LAB HQ</text></g>}
                {drawn.map(g => {
                  if (!visible(g.lon, g.lat)) return null;
                  const p = proj([g.lon, g.lat]); if (!p) return null;
                  const r = 5 + Math.min(Math.sqrt(g.events.length) * 1.7, 11), on = g.key === selKey, recent = now - Date.parse(g.events[0].timestamp) < 8000;
                  return (
                    <g key={g.key} className={'mk' + (on ? ' sel' : '')} transform={`translate(${p[0]} ${p[1]})`} tabIndex={0} role="button"
                      aria-label={`${g.label}: ${g.events.length} events, highest severity ${g.max}`}
                      onClick={() => { if (!moved.current) pick(g); }}
                      onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); pick(g); } }}>
                      <title>{`${g.label}${g.geo.simulated ? ' (simulated)' : ''} · ${g.events.length} events · ${g.max}`}</title>
                      {recent && <circle className="ring" r={r} stroke={sevColors[g.max]} />}
                      <circle className="core" r={r} fill={sevColors[g.max]} fillOpacity={selKey && !on ? .45 : .92} />
                      <text className="mklabel" y={r + 12} textAnchor="middle">{g.label}</text>
                    </g>);
                })}
              </svg>
              <div className="zoomctl">
                <button className="iconbtn" onClick={() => zoomBy(1.5)} aria-label="Zoom in" title="Zoom in"><ZoomIn size={15} /></button>
                <button className="iconbtn" onClick={() => zoomBy(1 / 1.5)} aria-label="Zoom out" title="Zoom out"><ZoomOut size={15} /></button>
                <button className="iconbtn" onClick={reset} aria-label="Reset view" title="Reset view"><RotateCcw size={14} /></button>
              </div>
              <div className="maplegend">
                {['critical', 'high', 'medium', 'low'].map(k => <span key={k}><i style={{ background: sevColors[k] }} />{k}</span>)}
                <small>{mode === 'globe' ? 'Drag to rotate' : 'Drag to pan'} · {full ? 'scroll' : 'Ctrl + scroll'} to zoom · size = event count</small>
              </div>
              <div className="mapmark">{tags.map(t => t[1]).join(' + ')}</div>
              {!events.length && <div className="mapempty"><Globe2 size={24} /><b>No suspicious events match the current filters</b><span>Widen the time window, clear filters, or trigger a scenario.</span></div>}
            </div>

            <aside className="mapside">
              {sel ? (
                <>
                  <div className="sidehead">
                    <div><small>SELECTED LOCATION</small><h3>{sel.label}</h3></div>
                    <button className="iconbtn" onClick={() => setSelKey(null)} aria-label="Clear selection"><X size={14} /></button>
                  </div>
                  <div className="simnote">{sel.internal ? 'Internal origin: activity started inside the lab network.'
                    : sel.geo.simulated ? 'Simulated placeholder location. Source IPs here are RFC 5737 documentation addresses.'
                    : `Approximate location from MaxMind GeoIP${sel.geo.accuracy_km ? ` (accuracy about ${sel.geo.accuracy_km} km)` : ''}. It shows where an address is registered or routed, not who is behind it.`}</div>
                  <div className="sidestats">
                    <div><b>{sel.events.length}</b><span>events</span></div>
                    <div><b>{new Set(sel.events.map(e => e.source_ip)).size}</b><span>source IPs</span></div>
                    <div><Sev v={sel.max} /><span>highest</span></div>
                  </div>
                  <div className="evlist">
                    {sel.events.slice(0, 40).map(e => {
                      const a = alertByEvent.get(e.id);
                      return (
                        <button key={e.id} className="evitem" onClick={() => onOpenEvent(e)}>
                          <span className="r1"><Sev v={e.severity} /><b>{typeLabel(e.event_type)}</b><em>{tm(e.timestamp)}</em></span>
                          <span className="r2"><span className="mono">{e.source_ip}</span> → {e.username}@{e.hostname}</span>
                          <span className="r3">{e.mitre_technique || '—'} {a && <Status v={a.status} />}</span>
                        </button>);
                    })}
                    {sel.events.length > 40 && <small className="more">+{sel.events.length - 40} more in the event log below</small>}
                  </div>
                </>
              ) : (
                <>
                  <div className="sidehead"><div><small>{selKey ? 'FILTERED OUT' : 'OVERVIEW'}</small><h3>{selKey ? 'Selection hidden by filters' : 'Top origins'}</h3></div></div>
                  {selKey && <div className="simnote">The selected location has no events matching the current filters. <button className="linkbtn" onClick={() => setSelKey(null)}>Clear selection</button></div>}
                  <div className="evlist">
                    {groups.slice(0, 12).map(g => (
                      <button key={g.key} className="srcrow" onClick={() => pick(g)}>
                        <i style={{ background: sevColors[g.max] }} /><span>{g.label}</span><b>{g.events.length}</b>
                      </button>))}
                    {!groups.length && <small className="more">Nothing to show yet.</small>}
                  </div>
                  <small className="sidehint">Click a marker or a row to inspect that origin.</small>
                </>
              )}
            </aside>
          </div>
        </div></div>
      </section>
    </>
  );
}