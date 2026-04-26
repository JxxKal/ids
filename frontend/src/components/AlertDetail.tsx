import { useEffect, useState } from 'react';
import { Network } from 'lucide-react';
import { clearFeedback, setFeedback } from '../api';
import type { Alert } from '../types';
import { AlertFlowPopup } from './AlertFlowPopup';
import { showHostConnections } from './HostConnectionDrawer';
import { PcapPreview } from './PcapPreview';
import { SeverityBadge } from './SeverityBadge';
import { TrustBadge } from './TrustBadge';

interface Props {
  alert: Alert;
  onClose: () => void;
  onUpdate: (a: Alert) => void;
}

function Row({ label, value }: { label: string; value?: string | number | null }) {
  if (value == null) return null;
  return (
    <div className="flex gap-3 py-1.5 border-b border-slate-800/50">
      <span className="w-40 shrink-0 text-[10px] text-slate-500 uppercase tracking-wider font-mono">{label}</span>
      <span className="text-slate-200 text-xs break-all font-mono">{String(value)}</span>
    </div>
  );
}

// IP-Zeile mit explizitem Trigger-Button für den HostConnectionDrawer.
// IP bleibt als Plain-Text lesbar, daneben ein klar beschrifteter Button
// "Host-Graph" – damit ist der Einstieg auf einen Blick sichtbar (vorher
// war's nur ein subtiles Network-Icon auf der IP, das User übersehen haben).
// Die IP selbst ist zusätzlich klickbar als Power-User-Shortcut.
function IpRow({ label, value }: { label: string; value?: string | null }) {
  if (!value) return null;
  return (
    <div className="flex gap-3 py-1.5 border-b border-slate-800/50 items-center">
      <span className="w-40 shrink-0 text-[10px] text-slate-500 uppercase tracking-wider font-mono">{label}</span>
      <button
        type="button"
        onClick={() => showHostConnections(value)}
        title="Klick = alle Verbindungen dieses Hosts in einem Zeitfenster"
        className="text-slate-200 text-xs break-all font-mono hover:text-cyan-300 transition-colors"
      >
        {value}
      </button>
      <button
        type="button"
        onClick={() => showHostConnections(value)}
        title="Alle Verbindungen dieses Hosts (Zeitfenster 15 min – 24 h, mit Time-Slider)"
        className="ml-auto inline-flex items-center gap-1.5 px-2 py-0.5 rounded
                   text-[10px] font-mono uppercase tracking-wider
                   bg-cyan-500/10 text-cyan-300 border border-cyan-500/40
                   hover:bg-cyan-500/20 hover:border-cyan-500/60
                   transition-colors whitespace-nowrap"
      >
        <Network size={11} />
        Host-Graph
      </button>
    </div>
  );
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <div className="pt-4 pb-2 text-[10px] text-slate-500 uppercase tracking-[0.14em] font-mono">
      {children}
    </div>
  );
}

const SEV_BORDER: Record<string, string> = {
  critical: '#ef4444',
  high:     '#dc2626',
  medium:   '#f97316',
  low:      '#22c55e',
};

export function AlertDetail({ alert, onClose, onUpdate }: Props) {
  const [note, setNote]         = useState('');
  const [loading, setLoading]   = useState(false);
  const [showGraph, setShowGraph] = useState(false);
  const [showPcap, setShowPcap] = useState(false);
  // Edit-Modus: Operator hat ein bestehendes Feedback und will es korrigieren
  // oder die Notiz nachschärfen. Toggle blendet den TP/FP-/Eingabe-Block
  // wieder ein und befüllt die Notiz mit dem bisherigen Wert.
  const [editing, setEditing]   = useState(false);

  // ESC schließt – konsistent mit AlertFlowPopup, HostConnectionDrawer.
  // Greift nur, wenn keine Sub-Modals offen sind, weil die ihren eigenen
  // ESC-Handler haben und sonst beide gleichzeitig zugemacht würden.
  useEffect(() => {
    if (showGraph || showPcap) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose, showGraph, showPcap]);

  const giveFeedback = async (fb: 'fp' | 'tp') => {
    setLoading(true);
    try {
      const updated = await setFeedback(alert.alert_id, fb, note || undefined);
      onUpdate(updated);
      setEditing(false);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const removeFeedback = async () => {
    if (!confirm('Feedback komplett entfernen?\n\nDas zugehörige Training-Sample wird ebenfalls aus der DB gelöscht, damit es das ML-Modell beim nächsten Retrain nicht mehr beeinflusst.')) return;
    setLoading(true);
    try {
      const updated = await clearFeedback(alert.alert_id);
      onUpdate(updated);
      setEditing(false);
      setNote('');
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const startEdit = () => {
    setNote(alert.feedback_note ?? '');
    setEditing(true);
  };

  const enr = alert.enrichment;

  return (
    <div
      className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4"
      onClick={onClose}
    >
      <div
        className="cyjan-card w-full max-w-3xl max-h-[90vh] rounded-xl flex flex-col"
        onClick={e => e.stopPropagation()}
        style={{ borderLeft: `4px solid ${SEV_BORDER[alert.severity] ?? '#0ea5e9'}` }}
      >
        {/* Header – flex-none, bleibt fix oben. Vorher hatte die ganze Card
            overflow-y-auto und Header/Body waren Geschwister im selben
            Scroll-Container, deshalb bewegte sich der Header beim Scrollen
            mit. Jetzt: card = flex-col, header = flex-none, body = flex-1
            min-h-0 overflow-y-auto. */}
        <div className="flex-none flex items-center justify-between px-5 py-4 border-b border-slate-800">
          <div className="flex items-center gap-3 flex-wrap">
            <SeverityBadge severity={alert.severity} />
            <span className="font-semibold text-cyan-100 font-mono">{alert.rule_id}</span>
            <span className="text-[10px] text-slate-500 uppercase tracking-wider font-mono px-2 py-0.5 rounded border border-slate-700">{alert.source}</span>
          </div>
          <button
            onClick={onClose}
            title="Schließen"
            className="text-[11px] px-3 py-1 rounded border border-slate-600/30 text-slate-300 hover:border-cyan-500/50 hover:text-cyan-300 transition-colors"
          >
            ESC · ✕
          </button>
        </div>

        <div className="flex-1 min-h-0 overflow-y-auto px-5 py-4">
          <p className="text-slate-300 text-xs mb-4 leading-relaxed">{alert.description}</p>

          <SectionTitle>Alert</SectionTitle>
          <Row label="Alert ID"    value={alert.alert_id} />
          <Row label="Timestamp"   value={new Date(alert.ts).toLocaleString()} />
          <Row label="Score"       value={alert.score.toFixed(3)} />
          <Row label="Proto"       value={alert.proto} />
          <IpRow label="Src IP"    value={alert.src_ip} />
          <Row   label="Src Port"  value={alert.src_port} />
          <IpRow label="Dst IP"    value={alert.dst_ip} />
          <Row   label="Dst Port"  value={alert.dst_port} />

          {enr && (
            <>
              <SectionTitle>Enrichment</SectionTitle>
              <div className="flex gap-4 py-1 border-b border-slate-800">
                <div className="flex flex-col gap-1 flex-1">
                  <span className="text-xs text-slate-500">Quelle</span>
                  <div className="flex items-center gap-1.5">
                    <TrustBadge trusted={enr.src_trusted ?? false} source={enr.src_trust_source} />
                    {enr.src_display_name && <span className="text-xs text-slate-300">{enr.src_display_name}</span>}
                  </div>
                </div>
                <div className="flex flex-col gap-1 flex-1">
                  <span className="text-xs text-slate-500">Ziel</span>
                  <div className="flex items-center gap-1.5">
                    <TrustBadge trusted={enr.dst_trusted ?? false} source={enr.dst_trust_source} />
                    {enr.dst_display_name && <span className="text-xs text-slate-300">{enr.dst_display_name}</span>}
                  </div>
                </div>
              </div>
              <Row label="Src Hostname"  value={enr.src_hostname} />
              <Row label="Dst Hostname"  value={enr.dst_hostname} />
              <Row label="Src Network"   value={enr.src_network ? `${enr.src_network.name} (${enr.src_network.cidr})` : undefined} />
              <Row label="Dst Network"   value={enr.dst_network ? `${enr.dst_network.name} (${enr.dst_network.cidr})` : undefined} />
              <Row label="Src Ping"      value={enr.src_ping_ms != null ? `${enr.src_ping_ms} ms` : undefined} />
              <Row label="Dst Ping"      value={enr.dst_ping_ms != null ? `${enr.dst_ping_ms} ms` : undefined} />
              <Row label="Src ASN"       value={enr.src_asn ? `AS${enr.src_asn.number} ${enr.src_asn.org}` : undefined} />
              <Row label="Dst ASN"       value={enr.dst_asn ? `AS${enr.dst_asn.number} ${enr.dst_asn.org}` : undefined} />
              <Row label="Src Geo"       value={enr.src_geo ? [enr.src_geo.city, enr.src_geo.country].filter(Boolean).join(', ') : undefined} />
              <Row label="Dst Geo"       value={enr.dst_geo ? [enr.dst_geo.city, enr.dst_geo.country].filter(Boolean).join(', ') : undefined} />
            </>
          )}

          {alert.tags.length > 0 && (
            <>
              <SectionTitle>Tags</SectionTitle>
              <div className="flex flex-wrap gap-1.5">
                {alert.tags.map(t => (
                  <span key={t} className="bg-orange-900/30 text-orange-300 border border-orange-700/40 px-2 py-0.5 rounded-full text-[10px] font-mono uppercase tracking-wider">{t}</span>
                ))}
              </div>
            </>
          )}
        </div>

        {/* Feedback-Status Banner (wenn bereits gesetzt) */}
        {alert.feedback && (
          <div className={`mx-4 mt-3 rounded-lg border px-3 py-2.5 text-xs ${
            alert.feedback === 'fp'
              ? 'bg-green-950/30 border-green-700/40'
              : 'bg-red-950/30 border-red-700/40'
          }`}>
            <div className="flex items-center gap-2 mb-1">
              <span className={`font-semibold ${alert.feedback === 'fp' ? 'text-green-300' : 'text-red-300'}`}>
                {alert.feedback === 'fp' ? '✓ False Positive – Falschalarm bestätigt' : '⚠ True Positive – Angriff bestätigt'}
              </span>
              {alert.feedback_ts && (
                <span className="text-slate-600 ml-auto">{new Date(alert.feedback_ts).toLocaleString()}</span>
              )}
            </div>
            {alert.feedback_note && (
              <p className="text-slate-400 mb-1.5">Notiz: {alert.feedback_note}</p>
            )}
            <p className="text-slate-600 flex items-center gap-1">
              <span className="text-cyan-700">⬡</span>
              Dieses Feedback fließt beim nächsten Modell-Retrain in das KI-Training ein
              {alert.source !== 'ml'
                ? ' (nur ML-Alerts werden als Trainings-Sample verwendet).'
                : '.'}
            </p>
          </div>
        )}

        {/* Actions */}
        <div className="flex items-center gap-2 px-5 py-4 border-t border-slate-800 flex-wrap">
          {showGraph && (
            <AlertFlowPopup alert={alert} onClose={() => setShowGraph(false)} />
          )}
          {alert.src_ip && alert.dst_ip && (
            <button
              onClick={() => setShowGraph(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-mono bg-cyan-500/15 text-cyan-200 border border-cyan-500/50 hover:bg-cyan-500/25 transition-colors"
              title="Alle Verbindungen zwischen Quelle und Ziel im ±5-min-Fenster"
            >
              <svg className="w-3.5 h-3.5" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
                <circle cx="3" cy="8" r="2" />
                <circle cx="13" cy="8" r="2" />
                <line x1="5" y1="8" x2="11" y2="8" />
                <line x1="9" y1="6" x2="11" y2="8" />
                <line x1="9" y1="10" x2="11" y2="8" />
              </svg>
              Verbindungsgraph
            </button>
          )}
          {alert.pcap_available && (
            <>
              <button
                onClick={() => setShowPcap(true)}
                className="px-3 py-1.5 rounded text-xs font-mono bg-cyan-500/15 text-cyan-200 border border-cyan-500/50 hover:bg-cyan-500/25 transition-colors"
              >
                ⧉ PCAP Vorschau
              </button>
              {showPcap && (
                <PcapPreview alertId={alert.alert_id} onClose={() => setShowPcap(false)} />
              )}
            </>
          )}

          {(!alert.feedback || editing) ? (
            <>
              <input
                className="cyjan-input flex-1 text-xs min-w-[180px]"
                placeholder="Notiz (optional)"
                value={note}
                onChange={e => setNote(e.target.value)}
              />
              <button
                onClick={() => giveFeedback('tp')}
                disabled={loading}
                className={`px-3 py-1.5 rounded text-xs font-mono border transition-colors disabled:opacity-50 ${
                  alert.feedback === 'tp'
                    ? 'bg-red-900/60 text-red-100 border-red-500/70 ring-1 ring-red-500/40'
                    : 'bg-red-900/40 text-red-200 border-red-700/50 hover:bg-red-900/60'
                }`}
              >
                ⚠ True Positive
              </button>
              <button
                onClick={() => giveFeedback('fp')}
                disabled={loading}
                className={`px-3 py-1.5 rounded text-xs font-mono border transition-colors disabled:opacity-50 ${
                  alert.feedback === 'fp'
                    ? 'bg-green-900/60 text-green-100 border-green-500/70 ring-1 ring-green-500/40'
                    : 'bg-green-900/40 text-green-200 border-green-700/50 hover:bg-green-900/60'
                }`}
              >
                ✓ False Positive
              </button>
              {editing && (
                <button
                  onClick={() => { setEditing(false); setNote(''); }}
                  disabled={loading}
                  className="px-3 py-1.5 rounded text-xs font-mono bg-slate-800 text-slate-300 border border-slate-700 hover:bg-slate-700/80 transition-colors disabled:opacity-50"
                >
                  Abbrechen
                </button>
              )}
            </>
          ) : (
            <>
              <span className="text-xs text-slate-500 italic font-mono mr-auto">
                Feedback gesetzt – ML-Sample ist hinterlegt.
              </span>
              <button
                onClick={startEdit}
                disabled={loading}
                className="px-3 py-1.5 rounded text-xs font-mono bg-cyan-500/15 text-cyan-200 border border-cyan-500/50 hover:bg-cyan-500/25 transition-colors disabled:opacity-50"
                title="Label oder Notiz korrigieren"
              >
                ✎ Ändern
              </button>
              <button
                onClick={removeFeedback}
                disabled={loading}
                className="px-3 py-1.5 rounded text-xs font-mono bg-slate-800/80 text-slate-300 border border-slate-700 hover:bg-red-950/40 hover:text-red-200 hover:border-red-700/50 transition-colors disabled:opacity-50"
                title="Feedback entfernen + Training-Sample aus ML-Pool löschen"
              >
                ✕ Entfernen
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
