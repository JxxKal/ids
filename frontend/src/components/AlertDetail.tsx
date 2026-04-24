import { useState } from 'react';
import { setFeedback } from '../api';
import type { Alert } from '../types';
import { AlertFlowPopup } from './AlertFlowPopup';
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

  const giveFeedback = async (fb: 'fp' | 'tp') => {
    setLoading(true);
    try {
      const updated = await setFeedback(alert.alert_id, fb, note || undefined);
      onUpdate(updated);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const enr = alert.enrichment;

  return (
    <div
      className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4"
      onClick={onClose}
    >
      <div
        className="cyjan-card w-full max-w-3xl max-h-[90vh] overflow-y-auto rounded-xl"
        onClick={e => e.stopPropagation()}
        style={{ borderLeft: `4px solid ${SEV_BORDER[alert.severity] ?? '#0ea5e9'}` }}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800">
          <div className="flex items-center gap-3 flex-wrap">
            <SeverityBadge severity={alert.severity} />
            <span className="font-semibold text-cyan-100 font-mono">{alert.rule_id}</span>
            <span className="text-[10px] text-slate-500 uppercase tracking-wider font-mono px-2 py-0.5 rounded border border-slate-700">{alert.source}</span>
          </div>
          <button
            onClick={onClose}
            className="text-slate-500 hover:text-cyan-300 hover:bg-slate-800 rounded w-7 h-7 flex items-center justify-center leading-none transition-colors"
          >
            ×
          </button>
        </div>

        <div className="px-5 py-4">
          <p className="text-slate-300 text-xs mb-4 leading-relaxed">{alert.description}</p>

          <SectionTitle>Alert</SectionTitle>
          <Row label="Alert ID"    value={alert.alert_id} />
          <Row label="Timestamp"   value={new Date(alert.ts).toLocaleString()} />
          <Row label="Score"       value={alert.score.toFixed(3)} />
          <Row label="Proto"       value={alert.proto} />
          <Row label="Src IP"      value={alert.src_ip} />
          <Row label="Dst IP"      value={alert.dst_ip} />
          <Row label="Dst Port"    value={alert.dst_port} />

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

          {!alert.feedback ? (
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
                className="px-3 py-1.5 rounded text-xs font-mono bg-red-900/40 text-red-200 border border-red-700/50 hover:bg-red-900/60 disabled:opacity-50 transition-colors"
              >
                ⚠ True Positive
              </button>
              <button
                onClick={() => giveFeedback('fp')}
                disabled={loading}
                className="px-3 py-1.5 rounded text-xs font-mono bg-green-900/40 text-green-200 border border-green-700/50 hover:bg-green-900/60 disabled:opacity-50 transition-colors"
              >
                ✓ False Positive
              </button>
            </>
          ) : (
            <span className="text-xs text-slate-600 italic font-mono">
              Feedback gesetzt – Buttons deaktiviert.
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
