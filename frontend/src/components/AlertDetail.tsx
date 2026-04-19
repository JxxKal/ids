import { useState } from 'react';
import { pcapUrl, setFeedback } from '../api';
import type { Alert } from '../types';
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
    <div className="flex gap-2 py-1 border-b border-slate-800">
      <span className="w-36 shrink-0 text-slate-500 text-xs">{label}</span>
      <span className="text-slate-200 text-xs break-all">{String(value)}</span>
    </div>
  );
}

export function AlertDetail({ alert, onClose, onUpdate }: Props) {
  const [note, setNote]     = useState('');
  const [loading, setLoading] = useState(false);

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
        className="card w-full max-w-2xl max-h-[90vh] overflow-y-auto"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <SeverityBadge severity={alert.severity} />
            <span className="font-semibold text-slate-100">{alert.rule_id}</span>
            <span className="text-slate-500 text-xs">{alert.source}</span>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200 text-lg leading-none">×</button>
        </div>

        <div className="px-4 py-3 space-y-1">
          <p className="text-slate-400 text-xs mb-3">{alert.description}</p>

          <Row label="Alert ID"    value={alert.alert_id} />
          <Row label="Timestamp"   value={new Date(alert.ts).toLocaleString()} />
          <Row label="Score"       value={alert.score.toFixed(3)} />
          <Row label="Proto"       value={alert.proto} />
          <Row label="Src IP"      value={alert.src_ip} />
          <Row label="Dst IP"      value={alert.dst_ip} />
          <Row label="Dst Port"    value={alert.dst_port} />

          {enr && (
            <>
              <div className="pt-2 pb-1 text-xs text-slate-500 uppercase tracking-wider">Enrichment</div>
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
            <div className="flex flex-wrap gap-1 pt-2">
              {alert.tags.map(t => (
                <span key={t} className="bg-slate-800 text-slate-400 px-1.5 py-0.5 rounded text-xs">{t}</span>
              ))}
            </div>
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
        <div className="flex items-center gap-2 px-4 py-3 border-t border-slate-800 mt-3">
          {alert.pcap_available && (
            <a href={pcapUrl(alert.alert_id)} download className="btn-primary">
              PCAP herunterladen
            </a>
          )}

          {!alert.feedback ? (
            <>
              <input
                className="input flex-1 text-xs"
                placeholder="Notiz (optional)"
                value={note}
                onChange={e => setNote(e.target.value)}
              />
              <button onClick={() => giveFeedback('tp')} disabled={loading} className="btn-danger">
                ⚠ True Positive
              </button>
              <button onClick={() => giveFeedback('fp')} disabled={loading} className="btn-success">
                ✓ False Positive
              </button>
            </>
          ) : (
            <span className="text-xs text-slate-600 italic">
              Feedback wurde gesetzt – Buttons deaktiviert.
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
