import { Fragment } from 'react';
import { typeLabel } from './common';

// ---------- streaming client (talks only to our own backend; the API key never reaches the browser) ----------
export async function streamAnalyst(body, { signal, onMeta, onDelta, onDone, onError }) {
  let res;
  try {
    res = await fetch('/api/ai/stream', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal });
  } catch (e) {
    if (e.name !== 'AbortError') onError({ code: 'offline', message: 'Could not reach the AEGIS backend. Is it running on port 8000?', retryable: true });
    return;
  }
  if (!res.ok) {
    let detail = '';
    try { const j = await res.json(); detail = typeof j.detail === 'string' ? j.detail : 'The request was rejected.'; } catch { /* not JSON */ }
    onError({ code: res.status === 503 ? 'not_configured' : res.status === 429 ? 'rate_limit' : 'http', message: detail || `Backend error (${res.status}).`,
      retryable: res.status === 429 || res.status >= 500 });
    return;
  }
  const reader = res.body.getReader(), dec = new TextDecoder();
  let buf = '', finished = false;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf('\n\n')) >= 0) {
        const block = buf.slice(0, i); buf = buf.slice(i + 2);
        const line = block.split('\n').find(l => l.startsWith('data: '));
        if (!line) continue;
        let ev; try { ev = JSON.parse(line.slice(6)); } catch { continue; }
        if (ev.type === 'meta') onMeta(ev);
        else if (ev.type === 'delta') onDelta(ev.text);
        else if (ev.type === 'done') { finished = true; onDone(ev); }
        else if (ev.type === 'error') { finished = true; onError(ev); }
      }
    }
  } catch (e) {
    if (e.name === 'AbortError') return;
    onError({ code: 'network', message: 'The connection dropped while the answer was streaming.', retryable: true }); return;
  }
  if (!finished) onError({ code: 'network', message: 'The answer ended unexpectedly. Please retry.', retryable: true });
}

// ---------- safe Markdown (React elements only, so model output can never inject HTML) ----------
const TAG_LABEL = { CONFIRMED: 'Confirmed', POTENTIAL: 'Potential', RECOMMENDED: 'AI recommendation' };
const TAG_HELP = { CONFIRMED: 'Stated directly in the SIEM data', POTENTIAL: 'An inference that still needs verification', RECOMMENDED: 'AI-generated advice, not a finding' };
export const Tag = ({ k }) => <span className={'aitag ' + k.toLowerCase()} title={TAG_HELP[k]}>{TAG_LABEL[k]}</span>;

function Inline({ text }) {
  return text.split(/(\*\*[^*]+\*\*|`[^`]+`|\[(?:CONFIRMED|POTENTIAL|RECOMMENDED)\])/g).map((p, i) => {
    if (!p) return null;
    if (p.length > 4 && p.startsWith('**') && p.endsWith('**')) return <strong key={i}>{p.slice(2, -2)}</strong>;
    if (p.length > 2 && p.startsWith('`') && p.endsWith('`')) return <code key={i}>{p.slice(1, -1)}</code>;
    const m = /^\[(CONFIRMED|POTENTIAL|RECOMMENDED)\]$/.exec(p);
    return m ? <Tag key={i} k={m[1]} /> : <Fragment key={i}>{p}</Fragment>;
  });
}
export function Markdown({ text }) {
  const out = []; let list = null;
  const flush = () => { if (!list) return; const L = list; list = null; const items = L.items.map((t, i) => <li key={i}><Inline text={t} /></li>);
    out.push(L.ordered ? <ol key={out.length} start={L.start}>{items}</ol> : <ul key={out.length}>{items}</ul>); };
  for (const raw of text.replace(/\r/g, '').split('\n')) {
    const line = raw.trim(); let m;
    if (!line) { flush(); continue; }
    if ((m = /^(#{1,4})\s+(.*)$/.exec(line))) { flush(); out.push(m[1].length <= 2 ? <h4 key={out.length}><Inline text={m[2]} /></h4> : <h5 key={out.length}><Inline text={m[2]} /></h5>); }
    else if (/^[-*_]{3,}$/.test(line)) { flush(); out.push(<hr key={out.length} />); }
    else if ((m = /^[-*•]\s+(.*)$/.exec(line))) { if (!list || list.ordered) { flush(); list = { ordered: false, items: [] }; } list.items.push(m[1]); }
    else if ((m = /^(\d+)[.)]\s+(.*)$/.exec(line))) { if (!list || !list.ordered) { flush(); list = { ordered: true, start: +m[1], items: [] }; } list.items.push(m[2]); }
    else { flush(); out.push(<p key={out.length}><Inline text={line} /></p>); }
  }
  flush();
  return <div className="aimd">{out}</div>;
}

// The model ends answers with "FOLLOW_UPS: a | b". Hide it from the text and turn it into chips.
const MARK = 'FOLLOW_UPS:';
export function splitFollowUps(text, streaming) {
  const i = text.lastIndexOf(MARK);
  if (i >= 0) {
    const ups = text.slice(i + MARK.length).split('\n')[0].split('|').map(s => s.replace(/^[\s<>*\-]+|[\s<>*]+$/g, '')).filter(s => s && s.length < 140).slice(0, 3);
    return { body: text.slice(0, i).trimEnd(), ups };
  }
  if (streaming) for (let k = MARK.length - 1; k > 0; k--) if (text.endsWith(MARK.slice(0, k))) return { body: text.slice(0, -k).trimEnd(), ups: [] };
  return { body: text, ups: [] };
}

// ---------- companion: rule-based tips (NOT AI-generated, and labelled as such) ----------
export const TYPE_TIPS = {
  authentication_failure: 'Many failed sign-ins in a row can mean password guessing. Account lockout and multi-factor authentication (MFA) shut this down.',
  port_scan: 'Scanning is how attackers map what is exposed. Close unused ports so only needed services face the network.',
  unusual_login_location: 'A successful sign-in from a new place is worth a quick check with the user. If they were not travelling, reset the password and review their MFA devices.',
  powershell_suspicious: 'Attackers like PowerShell because it is built in. Check who ran it and what the command line did, and restrict scripting for normal users.',
  outbound_connection_suspicious: 'Unexpected outbound traffic can be malware calling home. Find which process made the connection and block the destination if it is not business related.',
  malware_indicator: 'Act quickly but calmly: isolate the host (with approval), keep the evidence, and search for the same indicator on other machines.',
};
export const IDLE_TIPS = [
  'Multi-factor authentication blocks most password-guessing attacks, even when a password leaks.',
  'Triage by severity first, then by context: a medium alert on a domain controller can beat a high one on a test laptop.',
  'Write down what you checked as you investigate. Future you (and your teammates) will thank you.',
  'An alert is a clue, not a verdict. Verify before you close it, and note why you closed it.',
  'Least privilege: if an account does not need admin rights, it should not have them.',
  'Phishing is still the top way in. A short reminder to users about suspicious links goes a long way.',
  'Keep systems patched. Many real attacks use bugs that already have fixes.',
  'Backups only count if you have tested restoring them.',
];
export const dayKey = (offset = 0) => { const d = new Date(); d.setDate(d.getDate() + offset); return d.toLocaleDateString('en-CA'); };
export const streakValue = s => (s && s.last && (s.last === dayKey(0) || s.last === dayKey(-1)) ? s.count : 0);
export const bumpStreakState = s => {
  const today = dayKey(0);
  if (s?.last === today) return s;
  return { last: today, count: s?.last === dayKey(-1) ? s.count + 1 : 1 };
};

export function petMood({ connected, run, critical, open, thinking }) {
  if (!connected) return { emoji: '😴', label: 'Offline' };
  if (thinking) return { emoji: '🤔', label: 'Thinking' };
  if (critical > 0) return { emoji: '😱', label: 'Critical alert open' };
  if (open > 5) return { emoji: '😟', label: 'Busy' };
  if (open > 0) return { emoji: '🧐', label: 'Watching' };
  return run ? { emoji: '😎', label: 'All calm' } : { emoji: '😌', label: 'Stream paused' };
}

export const toAiTarget = sel => sel ? {
  kind: sel.status ? 'alert' : 'event', id: sel.id, title: sel.title || typeLabel(sel.event_type),
  severity: sel.severity, hostname: sel.hostname, status: sel.status || null } : null;