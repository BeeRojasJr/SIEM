import { useEffect, useState } from 'react';

export const SEVS = ['critical', 'high', 'medium', 'low', 'info'];
export const sevColors = { critical: '#fb7185', high: '#fb923c', medium: '#facc15', low: '#38bdf8', info: '#64748b' };
export const sevRank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
export const TYPE_LABEL = {
  authentication_failure: 'Failed login / brute force',
  port_scan: 'Network scanning',
  unusual_login_location: 'Unusual login location',
  powershell_suspicious: 'Suspicious PowerShell',
  outbound_connection_suspicious: 'Unusual outbound connection',
  malware_indicator: 'Malware indicator',
};
export const ATTACK_TYPES = Object.keys(TYPE_LABEL);
export const pretty = s => (s || '').replaceAll('_', ' ').replace(/\b\w/g, c => c.toUpperCase());
export const typeLabel = t => TYPE_LABEL[t] || pretty(t);
export const tm = s => s ? new Date(s).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—';
// Group markers by ~0.1 degree cell so different cities that share a name never merge.
export const geoKey = g => g ? (g.internal ? '__hq' : `${g.lat.toFixed(1)},${g.lon.toFixed(1)}`) : null;
export const placeLabel = g => !g ? '—' : g.internal ? 'Lab network' : g.country_code && !g.simulated ? `${g.city}, ${g.country_code}` : g.city;
export const geoBadge = g => !g ? '' : g.simulated ? 'simulated' : g.source === 'geoip' ? 'GeoIP' : '';
export const isSim = e => (e.source || 'simulator') === 'simulator';

export function Sev({ v, onClick, active }) {
  const cls = 'sev ' + (v || 'info') + (onClick ? ' clickable' : '') + (active ? ' on' : '');
  return onClick
    ? <button type="button" className={cls} onClick={onClick} title="Filter by this severity"><i />{v || 'info'}</button>
    : <span className={cls}><i />{v || 'info'}</span>;
}
export const Status = ({ v }) => <span className={'status ' + v}>{pretty(v)}</span>;

export function usePersisted(key, init, valid) {
  const [v, set] = useState(() => {
    try { const r = JSON.parse(localStorage.getItem(key)); if (r !== null && (!valid || valid(r))) return r; } catch { /* ignore */ }
    return init;
  });
  useEffect(() => { try { localStorage.setItem(key, JSON.stringify(v)); } catch { /* ignore */ } }, [key, v]);
  return [v, set];
}