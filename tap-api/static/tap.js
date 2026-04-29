// Live-Refresh des Status: alle 5s state-JSON ziehen + Timestamps formatieren.
function fmt(epoch) {
  if (!epoch) return '–';
  const d = new Date(epoch * 1000);
  const diff = Math.round((Date.now() - d.getTime()) / 1000);
  if (diff < 5) return 'gerade eben';
  if (diff < 60) return diff + ' s';
  if (diff < 3600) return Math.round(diff / 60) + ' min';
  if (diff < 86400) return Math.round(diff / 3600) + ' h';
  return d.toLocaleString();
}
function formatAllTs() {
  document.querySelectorAll('[data-ts]').forEach(el => {
    const ts = el.getAttribute('data-ts');
    if (ts && ts !== 'None') el.textContent = fmt(parseFloat(ts));
  });
}
async function refreshState() {
  try {
    const r = await fetch('/api/state');
    if (!r.ok) return;
    const s = await r.json();
    document.querySelectorAll('.status-connected, .status-reconnecting, .status-down, .status-starting, .status-unknown, .status-error').forEach(e => {
      e.className = 'value status-' + (s.connection || 'unknown');
      e.textContent = s.connection || 'unknown';
    });
  } catch (e) { /* leise – beim nächsten Tick weiter */ }
}
formatAllTs();
setInterval(formatAllTs, 1000);
setInterval(refreshState, 5000);
