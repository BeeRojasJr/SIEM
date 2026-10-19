import { useCallback, useEffect, useRef, useState } from 'react';
import { BellOff, Bell, X } from 'lucide-react';
import { usePersisted } from './common';
import { IDLE_TIPS, TYPE_TIPS, streakValue } from './aiUtils';

const SIZE = 58, SHOW_MS = 14000, MIN_GAP_MS = 20000;
const sevRank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const validPos = v => v && typeof v.right === 'number' && typeof v.bottom === 'number';
const clampPos = p => ({ right: Math.max(8, Math.min(window.innerWidth - SIZE - 8, p.right)), bottom: Math.max(8, Math.min(window.innerHeight - SIZE - 8, p.bottom)) });

export default function AiCompanion({ alerts, mood, critical, streak, kudos, hidden, suspend, onOpen, onExplain, onReview }) {
  const [muted, setMuted] = usePersisted('aegis.petMuted', false, v => typeof v === 'boolean');
  const [pos, setPos] = usePersisted('aegis.petPos', { right: 22, bottom: 22 }, validPos);
  const [bubble, setBubble] = useState(null);
  const [hover, setHover] = useState(false);
  const [dragging, setDragging] = useState(false);
  const alertsRef = useRef(alerts), seen = useRef(new Set()), mounted = useRef(Date.now()), lastShown = useRef(0);
  const tipAt = useRef({}), idleIdx = useRef(0), drag = useRef(null), moved = useRef(false), mutedRef = useRef(muted);
  alertsRef.current = alerts; mutedRef.current = muted;

  const show = useCallback(b => {
    const now = Date.now();
    if (b.kind !== 'alert' && b.kind !== 'praise' && now - lastShown.current < MIN_GAP_MS) return;   // never nag (praise answers the user's own action)
    if (mutedRef.current && !(b.kind === 'alert' && b.severity === 'critical')) return;
    lastShown.current = now; setBubble({ ...b, id: now });
  }, []);

  // New alerts -> one coalesced bubble with a matching tip.
  useEffect(() => {
    const fresh = alerts.filter(a => !seen.current.has(a.id));
    fresh.forEach(a => seen.current.add(a.id));
    const recent = fresh.filter(a => Date.parse(a.timestamp) >= mounted.current - 5000);
    if (!recent.length) return;
    const top = [...recent].sort((a, b) => sevRank[b.severity] - sevRank[a.severity])[0];
    const now = Date.now(), tipOk = now - (tipAt.current[top.event_type] || 0) > 60000;
    if (tipOk) tipAt.current[top.event_type] = now;
    show({ kind: 'alert', severity: top.severity, label: recent.length > 1 ? `${recent.length} new alerts` : `New ${top.severity} alert`,
      text: `${top.title} on ${top.hostname}${recent.length > 1 ? ` (+${recent.length - 1} more)` : ''}`, tip: tipOk ? TYPE_TIPS[top.event_type] : null, alertId: top.id });
  }, [alerts, show]);

  // Gentle, infrequent reminders and general tips (rule-based, no AI calls).
  useEffect(() => {
    const t1 = setInterval(() => {
      if (document.hidden) return;
      const stale = alertsRef.current.filter(a => a.status === 'new' && Date.now() - Date.parse(a.timestamp) > 3 * 60000).length;
      if (stale) show({ kind: 'reminder', label: 'Reminder', text: `${stale} alert${stale > 1 ? 's are' : ' is'} still marked New. Pick one and mark it Investigating.`, review: true });
    }, 150000);
    const t2 = setInterval(() => {
      if (document.hidden) return;
      show({ kind: 'tip', label: 'Security tip', text: IDLE_TIPS[idleIdx.current++ % IDLE_TIPS.length] });
    }, 90000);
    return () => { clearInterval(t1); clearInterval(t2); };
  }, [show]);
  useEffect(() => { if (kudos?.nonce) show({ kind: 'praise', label: 'Nice work!', text: kudos.count > 1 ? `${kudos.count}-day triage streak. Keep it going!` : 'Streak started. Triage an alert each day to build it.' }); }, [kudos, show]);

  // Auto-hide the bubble (paused while the pointer is over it).
  useEffect(() => {
    if (!bubble || hover) return;
    const t = setTimeout(() => setBubble(null), SHOW_MS); return () => clearTimeout(t);
  }, [bubble, hover]);

  // Drag to reposition; a click without movement opens the assistant.
  useEffect(() => {
    const move = e => {
      const d = drag.current; if (!d) return;
      if (!moved.current && Math.abs(e.clientX - d.x) + Math.abs(e.clientY - d.y) > 5) { moved.current = true; setDragging(true); }
      if (moved.current) setPos(clampPos({ right: d.right - (e.clientX - d.x), bottom: d.bottom - (e.clientY - d.y) }));
    };
    const up = () => { if (drag.current) { drag.current = null; setDragging(false); setTimeout(() => { moved.current = false; }, 0); } };
    const resize = () => setPos(p => clampPos(p));
    window.addEventListener('pointermove', move); window.addEventListener('pointerup', up); window.addEventListener('pointercancel', up); window.addEventListener('resize', resize);
    return () => { window.removeEventListener('pointermove', move); window.removeEventListener('pointerup', up); window.removeEventListener('pointercancel', up); window.removeEventListener('resize', resize); };
  }, [setPos]);

  if (hidden || suspend) return null;
  const p = clampPos(pos);
  const left = p.right > window.innerWidth / 2, below = p.bottom > window.innerHeight - 260;
  const streakN = streakValue(streak);
  const act = bubble && (bubble.kind === 'alert' ? () => { const a = alertsRef.current.find(x => x.id === bubble.alertId); setBubble(null); a ? onExplain(a) : onOpen(); }
    : bubble.review ? () => { setBubble(null); onReview(); } : null);

  return (
    <div className="petwrap" style={{ right: p.right, bottom: p.bottom }}>
      {bubble && (
        <div className={`petbubble ${bubble.kind} ${left ? 'left' : ''} ${below ? 'below' : ''}`} role="status" aria-live="polite" onMouseEnter={() => setHover(true)} onMouseLeave={() => setHover(false)}>
          <div className="pbhead"><span>{bubble.label}</span><small>{bubble.kind === 'alert' ? 'from your SIEM' : 'rule-based, not AI'}</small>
            <button onClick={() => setBubble(null)} aria-label="Dismiss"><X size={11} /></button></div>
          <p>{bubble.text}</p>
          {bubble.tip && <p className="pbtip"><b>Tip:</b> {bubble.tip}</p>}
          <div className="pbact">
            {act && <button className="primary" onClick={act}>{bubble.kind === 'alert' ? 'Explain it' : 'Review'}</button>}
            <button onClick={() => { setBubble(null); onOpen(); }}>Ask Aegi</button>
            <button className="mute" onClick={() => { setMuted(m => !m); setBubble(null); }} title={muted ? 'Turn tips back on' : 'Mute tips and reminders (critical alerts still show)'} aria-label="Toggle tips">{muted ? <Bell size={11} /> : <BellOff size={11} />}</button>
          </div>
        </div>)}
      <button className={`pet ${mood.label.startsWith('Critical') ? 'alarm' : ''} ${mood.label === 'Thinking' ? 'thinking' : ''} ${dragging ? 'dragging' : ''}`}
        aria-label={`Open AI security assistant. Aegi feels: ${mood.label}`} title={`Aegi · ${mood.label}\nClick to chat · drag to move`}
        onClick={() => { if (!moved.current) { setBubble(null); onOpen(); } }}
        onPointerDown={e => { if (e.button !== 0 && e.pointerType === 'mouse') return; moved.current = false; drag.current = { x: e.clientX, y: e.clientY, right: p.right, bottom: p.bottom }; }}>
        <span className="petface">{mood.emoji}</span>
        {critical > 0 && <span className="petbadge" aria-hidden="true">{critical > 9 ? '9+' : critical}</span>}
        {streakN > 0 && <span className="petstreak" title={`${streakN}-day triage streak`} aria-hidden="true">🔥{streakN}</span>}
      </button>
    </div>
  );
}