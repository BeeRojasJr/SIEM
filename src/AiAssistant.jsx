import { useCallback, useEffect, useRef, useState } from 'react';
import { Check, Copy, Download, Eye, EyeOff, RotateCcw, Send, Sparkles, Square, Trash2, X } from 'lucide-react';
import { Sev } from './common';
import { Markdown, Tag, splitFollowUps, streamAnalyst } from './aiUtils';

const uid = () => Math.random().toString(36).slice(2, 10);
const ALERT_ACTIONS = [
  { label: 'Analyze this alert', task: 'analyze' },
  { label: 'Generate report', task: 'report' },
  { label: 'Explain it simply', task: 'chat', question: 'Explain this in the simplest possible terms, as if I have no security background.' },
  { label: 'What should I check next?', task: 'chat', question: 'What are the most important things I should check next, in priority order?' },
];
const GENERAL_ACTIONS = [
  { label: 'Summarize my environment', task: 'summary' },
  { label: 'What should I look at first?', task: 'chat', question: 'Based on the current alerts, what should I look at first and why?' },
  { label: 'Teach me: brute-force attacks', task: 'chat', question: 'Explain brute-force attacks simply: how they work, how to spot them, and how to stop them.' },
  { label: 'How do I triage an alert?', task: 'chat', question: 'Give me a simple step-by-step method for triaging a security alert.' },
];

async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return true; } catch {
    try { const t = document.createElement('textarea'); t.value = text; document.body.appendChild(t); t.select(); const ok = document.execCommand('copy'); t.remove(); return ok; } catch { return false; }
  }
}

function SetupHelp() {
  return (
    <div className="aisetup">
      <b>AI assistant is not set up yet</b>
      <ol>
        <li>Create a file named <code>.env</code> next to <code>package.json</code>.</li>
        <li>Add one line: <code>GROQ_API_KEY=your_key_here</code></li>
        <li>Restart the backend (stop uvicorn with Ctrl+C and start it again).</li>
      </ol>
      <small>The key stays on the backend and is never sent to the browser.</small>
    </div>
  );
}

function Message({ m, last, onRetry, onAsk }) {
  const [copied, setCopied] = useState(false);
  if (m.role === 'user') return <div className="aimsg me"><div className="aibubble">{m.content}</div></div>;
  const streaming = m.status === 'streaming';
  const { body, ups } = splitFollowUps(m.raw || '', streaming);
  const copy = async () => { if (await copyText(body)) { setCopied(true); setTimeout(() => setCopied(false), 1500); } };
  const download = () => {
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([body], { type: 'text/markdown' }));
    a.download = `aegis-${m.task}-${m.id}.md`; a.click(); URL.revokeObjectURL(a.href);
  };
  return (
    <div className="aimsg bot">
      <div className="aibubble">
        {streaming && !body && <div className="aithinking"><span /><span /><span /><em>Analyzing the SIEM data…</em></div>}
        {body && <Markdown text={body} />}
        {streaming && body && <span className="aicursor" />}
        {m.status === 'stopped' && <div className="ainote">Stopped. The answer above is incomplete.</div>}
        {m.truncated && <div className="ainote">The answer hit the length limit and was cut off. <button className="linkbtn" onClick={() => onAsk('Continue from where you stopped.')}>Continue</button></div>}
        {m.status === 'error' && (
          m.error?.code === 'not_configured' ? <SetupHelp /> :
          <div className="aierror" role="alert"><b>{m.error?.code === 'rate_limit' ? 'Slow down a moment' : m.error?.code === 'offline' ? 'Backend unreachable' : 'The AI could not answer'}</b>
            <span>{m.error?.message}</span>{m.error?.retryable && <button onClick={() => onRetry(m)}><RotateCcw size={12} /> Retry</button>}</div>)}
        {m.meta && (
          <details className="aimeta"><summary>Data used ({m.meta.used.length})</summary>
            <ul>{m.meta.used.map((u, i) => <li key={i}>{u}</li>)}</ul>
            {m.meta.missing?.length > 0 && <p><b>Not in the SIEM data</b> (so the AI cannot know it): {m.meta.missing.join(', ')}.</p>}
            {m.meta.synthetic && <p>This environment is a simulator: events are synthetic.</p>}
          </details>)}
        {(m.status === 'done' || m.status === 'stopped') && body && (
          <div className="aiactions"><button onClick={copy}>{copied ? <Check size={12} /> : <Copy size={12} />} {copied ? 'Copied' : 'Copy'}</button>
            {(m.task === 'report' || m.task === 'analyze') && <button onClick={download}><Download size={12} /> Download .md</button>}</div>)}
      </div>
      {last && m.status === 'done' && ups.length > 0 && <div className="aiups">{ups.map(u => <button key={u} onClick={() => onAsk(u)}>{u}</button>)}</div>}
    </div>
  );
}

export default function AiAssistant({ open, onClose, target, onClearTarget, auto, status, mood, petHidden, onTogglePet, onBusy, shifted }) {
  const [threads, setThreads] = useState({});
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const abortRef = useRef(null), bodyRef = useRef(null), lastAuto = useRef(0), inputRef = useRef(null);
  const key = target ? `${target.kind}:${target.id}` : 'general';
  const live = useRef({});
  live.current = { key, target, threads, busy };
  const msgs = threads[key] || [];
  const unconfigured = status && status.configured === false;

  const patch = useCallback((k, id, fn) => setThreads(t => ({ ...t, [k]: (t[k] || []).map(m => m.id === id ? { ...m, ...fn(m) } : m) })), []);

  const send = useCallback((task, question, label) => {
    const { key: k, target: tgt, threads: all, busy: wasBusy } = live.current;
    if (wasBusy) abortRef.current?.abort();
    const history = task === 'chat' ? (all[k] || []).filter(m => m.status === 'done').slice(-8).map(m => ({ role: m.role, content: m.role === 'user' ? m.content : splitFollowUps(m.raw || '', false).body })) : [];
    const aid = uid(), req = { task, question, label };
    setThreads(t => ({ ...t, [k]: [...(t[k] || []).map(m => m.status === 'streaming' ? { ...m, status: 'stopped' } : m),
      { id: uid(), role: 'user', status: 'done', content: label || question }, { id: aid, role: 'assistant', status: 'streaming', raw: '', task, req, meta: null, error: null, truncated: false }] }));
    const ctl = new AbortController(); abortRef.current = ctl;
    setBusy(true); onBusy?.(true);
    const end = () => { if (abortRef.current === ctl) { setBusy(false); onBusy?.(false); } };
    streamAnalyst({ task, kind: tgt?.kind, id: tgt?.id, question, history }, {
      signal: ctl.signal,
      onMeta: ev => patch(k, aid, () => ({ meta: { used: ev.used || [], missing: ev.missing || [], synthetic: !!ev.synthetic } })),
      onDelta: text => patch(k, aid, m => ({ raw: m.raw + text })),
      onDone: ev => { patch(k, aid, () => ({ status: 'done', truncated: !!ev.truncated })); end(); },
      onError: err => { patch(k, aid, () => ({ status: 'error', error: err })); end(); },
    }).finally(() => { if (ctl.signal.aborted) { patch(k, aid, m => m.status === 'streaming' ? { status: 'stopped' } : {}); end(); } });
  }, [patch, onBusy]);

  const stop = () => { abortRef.current?.abort(); };
  const retry = m => {
    const { key: k } = live.current;
    setThreads(t => { const list = t[k] || []; const i = list.findIndex(x => x.id === m.id); return { ...t, [k]: list.filter((_, j) => j !== i && j !== i - 1) }; });
    send(m.req.task, m.req.question, m.req.label);
  };
  const ask = q => { if (!unconfigured) send('chat', q, q); };
  const clearThread = () => { abortRef.current?.abort(); setThreads(t => ({ ...t, [key]: [] })); };
  const submit = () => { const q = input.trim(); if (!q || unconfigured) return; setInput(''); send('chat', q, q); };

  // Requests launched from the drawer or the companion arrive as {nonce, task}.
  useEffect(() => {
    if (!open || !auto || auto.nonce === lastAuto.current) return;
    lastAuto.current = auto.nonce;
    if (!unconfigured) send(auto.task, auto.question, auto.label);
  }, [open, auto, send, unconfigured]);
  useEffect(() => { if (open) setTimeout(() => inputRef.current?.focus(), 250); }, [open]);
  useEffect(() => { const el = bodyRef.current; if (el && el.scrollHeight - el.scrollTop - el.clientHeight < 160) el.scrollTop = el.scrollHeight; }, [msgs]);
  useEffect(() => () => abortRef.current?.abort(), []);

  const actions = target ? ALERT_ACTIONS : GENERAL_ACTIONS;
  return (
    <aside className={'aipanel' + (open ? ' open' : '') + (shifted ? ' shifted' : '')} aria-hidden={!open} aria-label="AI security analyst">
      <div className="aihead">
        <div className="aipet" title={mood.label}>{mood.emoji}</div>
        <div className="aititle"><b>Aegi <em>· AI analyst</em></b>
          <small><i className={status === undefined ? 'amber' : status?.configured ? 'live' : 'amber'} />{status === undefined ? 'Checking…' : status === null ? 'Backend offline' : status.configured ? status.model : 'Not configured'}</small></div>
        <button className="iconbtn" onClick={onTogglePet} title={petHidden ? 'Show floating companion' : 'Hide floating companion'} aria-label="Toggle floating companion">{petHidden ? <Eye size={14} /> : <EyeOff size={14} />}</button>
        <button className="iconbtn" onClick={clearThread} disabled={!msgs.length} title="Clear this conversation" aria-label="Clear conversation"><Trash2 size={14} /></button>
        <button className="iconbtn" onClick={onClose} aria-label="Close AI analyst"><X size={15} /></button>
      </div>

      <div className="aictx">
        {target ? (<><span className="aictxlabel">{target.kind === 'alert' ? 'ALERT' : 'EVENT'}</span><Sev v={target.severity} /><b title={target.title}>{target.title}</b><small>{target.hostname}</small>
          <button className="iconbtn" onClick={onClearTarget} title="Stop focusing on this alert" aria-label="Clear alert context"><X size={12} /></button></>)
          : (<><span className="aictxlabel">CONTEXT</span><b>Whole SIEM overview</b><small>Select an alert and press “Analyze with AI” for a deep dive</small></>)}
      </div>
      <div className="ailegend"><Tag k="CONFIRMED" /><Tag k="POTENTIAL" /><Tag k="RECOMMENDED" /></div>

      <div className="aibody" ref={bodyRef}>
        {status === null && <div className="aierror" role="alert"><b>Backend unreachable</b><span>Start the FastAPI backend on port 8000, then reopen this panel.</span></div>}
        {unconfigured && <SetupHelp />}
        {!msgs.length && !unconfigured && status !== null && (
          <div className="aiempty"><div className="aibig">{mood.emoji}</div>
            <b>{target ? 'Ready to look into this with you' : 'Hi, I’m Aegi'}</b>
            <p>{target ? 'I use only the data in your SIEM. Anything I can’t see, I’ll say so. Press “Analyze this alert” to start.' : 'I can explain alerts in plain language, suggest investigation steps, and teach security basics. Pick a prompt below or ask me anything.'}</p></div>)}
        {msgs.map((m, i) => <Message key={m.id} m={m} last={i === msgs.length - 1} onRetry={retry} onAsk={ask} />)}
      </div>

      <div className="aifoot">
        <div className="aichips">{actions.map(a => <button key={a.label} disabled={unconfigured || status === null} onClick={() => send(a.task, a.question, a.label)}>{a.label}</button>)}</div>
        <div className="aiinput">
          <textarea ref={inputRef} rows={1} maxLength={1500} value={input} placeholder={unconfigured ? 'Set up GROQ_API_KEY to chat…' : 'Ask a follow-up or any security question…'} disabled={unconfigured || status === null}
            onChange={e => setInput(e.target.value)} onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); submit(); } }} aria-label="Message" />
          {busy ? <button className="send stop" onClick={stop} aria-label="Stop generating" title="Stop"><Square size={13} /></button>
            : <button className="send" onClick={submit} disabled={!input.trim() || unconfigured || status === null} aria-label="Send"><Send size={14} /></button>}
        </div>
        <small className="aidisc"><Sparkles size={10} /> AI-generated. Verify before acting. Lab data is simulated.</small>
      </div>
    </aside>
  );
}