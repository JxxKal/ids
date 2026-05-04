import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Download, FileJson, Printer, ChevronLeft, ChevronRight } from 'lucide-react';
import {
  fetchWeeklyReport,
  weeklyReportCsvUrl,
  getToken,
  type WeeklyReport,
  type WeeklyReportDay,
} from '../api';
import { countryFlag } from '../lib/country';

// ── ISO-Wochen-Helfer ────────────────────────────────────────────────────────

function isoWeek(d: Date): { year: number; week: number } {
  // ISO-Woche-Berechnung nach https://en.wikipedia.org/wiki/ISO_week_date
  // — Mittwoch des aktuellen ISO-Jahres bestimmen, dann von dort aus
  // die KW. Browser haben kein eingebautes ISO-Wochen-API.
  const tmp = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()));
  const dow = tmp.getUTCDay() || 7;       // Mo=1 … So=7
  tmp.setUTCDate(tmp.getUTCDate() + 4 - dow);
  const yearStart = new Date(Date.UTC(tmp.getUTCFullYear(), 0, 1));
  const week = Math.ceil((((tmp.getTime() - yearStart.getTime()) / 86_400_000) + 1) / 7);
  return { year: tmp.getUTCFullYear(), week };
}

function fmtWeek(year: number, week: number): string {
  return `${year}-W${String(week).padStart(2, '0')}`;
}

function shiftWeek(year: number, week: number, delta: number): { year: number; week: number } {
  // Verschiebe um delta Wochen über das Datum vom Montag der Woche.
  // Vermeidet das fragile Wraparound 53→1 / -1→52 von Hand.
  let d: Date;
  try {
    // Date.fromisocalendar gibt's nicht in JS; wir bauen über Donnerstag
    // (4. Tag der ISO-Woche) — der ist garantiert im richtigen ISO-Jahr.
    const jan4 = new Date(Date.UTC(year, 0, 4));
    const jan4dow = jan4.getUTCDay() || 7;
    const wkMonday = new Date(jan4);
    wkMonday.setUTCDate(jan4.getUTCDate() - (jan4dow - 1) + (week - 1) * 7);
    d = wkMonday;
  } catch {
    d = new Date();
  }
  d.setUTCDate(d.getUTCDate() + delta * 7);
  return isoWeek(d);
}

// ── Severity-Konstanten ──────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  critical: '#ef4444',
  high:     '#dc2626',
  medium:   '#f97316',
  low:      '#22c55e',
};
const SEV_ORDER = ['critical', 'high', 'medium', 'low'] as const;

// ── Kleine SVG-Charts ────────────────────────────────────────────────────────

function SeverityDonut({ counts, size = 120 }: {
  counts: { critical: number; high: number; medium: number; low: number };
  size?: number;
}) {
  const total = counts.critical + counts.high + counts.medium + counts.low;
  const r     = size / 2 - 8;
  const cx    = size / 2;
  const cy    = size / 2;
  if (total === 0) {
    return (
      <svg viewBox={`0 0 ${size} ${size}`} width={size} height={size}>
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="#1e293b" strokeWidth="14" />
        <text x={cx} y={cy + 5} textAnchor="middle" fill="#64748b" fontSize="14" fontFamily="monospace">0</text>
      </svg>
    );
  }
  // Anteile in Bogenlängen umrechnen.
  const circ = 2 * Math.PI * r;
  let offset = 0;
  const segs = SEV_ORDER.map(sev => {
    const v = counts[sev];
    const dash = (v / total) * circ;
    const seg = (
      <circle
        key={sev}
        cx={cx} cy={cy} r={r} fill="none"
        stroke={SEV_COLOR[sev]}
        strokeWidth="14"
        strokeDasharray={`${dash} ${circ}`}
        strokeDashoffset={-offset}
        transform={`rotate(-90 ${cx} ${cy})`}
      />
    );
    offset += dash;
    return seg;
  });
  return (
    <svg viewBox={`0 0 ${size} ${size}`} width={size} height={size}>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="#1e293b" strokeWidth="14" />
      {segs}
      <text x={cx} y={cy - 2} textAnchor="middle" fill="#cbd5e1" fontSize="20" fontWeight="600" fontFamily="monospace">
        {total}
      </text>
      <text x={cx} y={cy + 16} textAnchor="middle" fill="#64748b" fontSize="10" fontFamily="monospace">
        ALERTS
      </text>
    </svg>
  );
}

function StackedDailyBars({ days }: { days: WeeklyReportDay[] }) {
  const W = 700;
  const H = 180;
  const PAD = { top: 12, right: 12, bottom: 28, left: 36 };
  const innerW = W - PAD.left - PAD.right;
  const innerH = H - PAD.top - PAD.bottom;

  const dayTotals = days.map(d => d.critical + d.high + d.medium + d.low);
  const max = Math.max(1, ...dayTotals);
  const barW = innerW / days.length - 6;

  return (
    <svg viewBox={`0 0 ${W} ${H}`} width="100%" preserveAspectRatio="xMidYMid meet">
      {/* Y-Gridlines + Achse */}
      {[0, 0.25, 0.5, 0.75, 1].map(t => {
        const y = PAD.top + innerH * (1 - t);
        return (
          <g key={t}>
            <line x1={PAD.left} y1={y} x2={PAD.left + innerW} y2={y}
              stroke="#1e293b" strokeWidth="0.5" strokeDasharray={t === 0 ? '' : '2 4'} />
            <text x={PAD.left - 6} y={y + 3} textAnchor="end" fill="#64748b"
              fontSize="9" fontFamily="monospace">
              {Math.round(max * t)}
            </text>
          </g>
        );
      })}

      {days.map((d, i) => {
        const x = PAD.left + i * (innerW / days.length) + 3;
        let yCursor = PAD.top + innerH;  // bottom of bar
        const segs: React.ReactElement[] = [];
        for (const sev of SEV_ORDER.slice().reverse()) {  // unten low → oben critical
          const v = (d as unknown as Record<string, number>)[sev];
          if (v <= 0) continue;
          const segH = (v / max) * innerH;
          yCursor -= segH;
          segs.push(
            <rect
              key={sev}
              x={x} y={yCursor}
              width={barW} height={segH}
              fill={SEV_COLOR[sev]}
            >
              <title>{`${d.date} · ${sev}: ${v}`}</title>
            </rect>
          );
        }
        const dayLabel = new Date(d.date).toLocaleDateString(undefined, { weekday: 'short', day: 'numeric' });
        return (
          <g key={d.date}>
            {segs}
            <text x={x + barW / 2} y={H - PAD.bottom + 14} textAnchor="middle"
              fill="#94a3b8" fontSize="10" fontFamily="monospace">
              {dayLabel}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

// ── Trend-Pfeil ──────────────────────────────────────────────────────────────

function TrendBadge({ trend }: { trend: { delta_pct: number | null; direction: string; prev: number } }) {
  if (trend.delta_pct === null) {
    return <span className="text-slate-500 text-xs">–</span>;
  }
  const arrow = trend.direction === 'up' ? '↑' : trend.direction === 'down' ? '↓' : '→';
  const color = trend.direction === 'up'   ? 'text-red-300'
              : trend.direction === 'down' ? 'text-green-300'
              :                              'text-slate-400';
  return (
    <span className={`text-xs font-mono ${color}`} title={`Vorwoche: ${trend.prev}`}>
      {arrow} {Math.abs(trend.delta_pct).toFixed(1)} %
    </span>
  );
}

// ── Severity-Badge mini ──────────────────────────────────────────────────────

function SevPill({ sev }: { sev: string | null | undefined }) {
  const s = (sev || 'low').toLowerCase();
  return (
    <span
      className="inline-block w-2 h-2 rounded-full align-middle mr-1.5"
      style={{ backgroundColor: SEV_COLOR[s] || '#64748b' }}
    />
  );
}

// ── Hauptkomponente ─────────────────────────────────────────────────────────

export function WeeklyReportPage() {
  const { t } = useTranslation();
  const today = new Date();
  const initial = isoWeek(today);
  const [weekY, setWeekY] = useState(initial.year);
  const [weekN, setWeekN] = useState(initial.week);
  const [report, setReport] = useState<WeeklyReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const weekStr = fmtWeek(weekY, weekN);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError('');
    fetchWeeklyReport(weekStr)
      .then(r => { if (alive) setReport(r); })
      .catch(e => { if (alive) setError(e instanceof Error ? e.message : String(e)); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [weekStr]);

  const goPrev = () => { const w = shiftWeek(weekY, weekN, -1); setWeekY(w.year); setWeekN(w.week); };
  const goNext = () => { const w = shiftWeek(weekY, weekN, +1); setWeekY(w.year); setWeekN(w.week); };
  const goCurrent = () => { const w = isoWeek(new Date()); setWeekY(w.year); setWeekN(w.week); };

  const handlePrint = () => window.print();

  const downloadJson = async () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url;
    a.download = `cyjan-weekly-${weekStr}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const downloadCsv = () => {
    // CSV-ZIP kommt vom Backend. Token muss als Header mit, also fetch +
    // blob-Download statt direkter <a download> (der könnte kein Authorization
    // mitschicken).
    const token = getToken();
    fetch(weeklyReportCsvUrl(weekStr), {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
      .then(async r => {
        if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
        return r.blob();
      })
      .then(blob => {
        const url = URL.createObjectURL(blob);
        const a   = document.createElement('a');
        a.href = url;
        a.download = `cyjan-weekly-${weekStr}.zip`;
        a.click();
        URL.revokeObjectURL(url);
      })
      .catch(e => alert(`CSV-Download fehlgeschlagen: ${e}`));
  };

  const fromDate = useMemo(() => report ? new Date(report.week.from) : null, [report]);
  const toDate   = useMemo(() => report ? new Date(report.week.to)   : null, [report]);

  return (
    <div className="space-y-5 print:space-y-3">
      {/* Toolbar — wird im Print ausgeblendet */}
      <div className="flex items-center gap-3 flex-wrap print:hidden">
        <h1 className="text-lg font-semibold text-slate-200">{t('weeklyReport.title')}</h1>
        <div className="flex items-center gap-1 ml-auto">
          <button onClick={goPrev} title={t('weeklyReport.prev')}
            className="p-1.5 rounded border border-slate-700 hover:border-slate-500 text-slate-400 hover:text-slate-200">
            <ChevronLeft size={14} />
          </button>
          <span className="text-sm font-mono text-cyan-300 px-2">{weekStr}</span>
          <button onClick={goNext} title={t('weeklyReport.next')}
            className="p-1.5 rounded border border-slate-700 hover:border-slate-500 text-slate-400 hover:text-slate-200">
            <ChevronRight size={14} />
          </button>
          <button onClick={goCurrent} title={t('weeklyReport.current')}
            className="ml-1 px-2 py-1 rounded border border-cyan-700 text-cyan-300 hover:bg-cyan-500/15 text-xs font-mono">
            {t('weeklyReport.currentLabel')}
          </button>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={handlePrint} title={t('weeklyReport.print')}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded border border-slate-700 text-slate-300 hover:border-cyan-600 hover:text-cyan-200 text-xs">
            <Printer size={13} /> {t('weeklyReport.printLabel')}
          </button>
          <button onClick={downloadJson} disabled={!report} title={t('weeklyReport.downloadJson')}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded border border-slate-700 text-slate-300 hover:border-cyan-600 hover:text-cyan-200 text-xs disabled:opacity-40">
            <FileJson size={13} /> JSON
          </button>
          <button onClick={downloadCsv} disabled={!report} title={t('weeklyReport.downloadCsv')}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded border border-slate-700 text-slate-300 hover:border-cyan-600 hover:text-cyan-200 text-xs disabled:opacity-40">
            <Download size={13} /> CSV
          </button>
        </div>
      </div>

      {loading && <p className="text-slate-500 text-sm">{t('common.loading')}</p>}
      {error   && <p className="text-red-400 text-sm">{error}</p>}

      {report && fromDate && toDate && (
        <div className="space-y-5 print:text-black">
          {/* Print-Header */}
          <div className="hidden print:block text-black">
            <h1 className="text-2xl font-bold mb-1">Cyjan IDS — {t('weeklyReport.title')} {weekStr}</h1>
            <p className="text-sm text-gray-700">
              {fromDate.toLocaleDateString()} – {toDate.toLocaleDateString()}  ·  Erstellt: {new Date(report.week.generated).toLocaleString()}
            </p>
            <hr className="my-3" />
          </div>

          {/* ── Block 1: Executive Summary ───────────────────────────── */}
          <section className="cyjan-card rounded-lg p-4 print:shadow-none print:border-gray-300 print:border print:bg-white">
            <h2 className="text-sm font-semibold text-cyan-200 print:text-black mb-3 uppercase tracking-wider">
              {t('weeklyReport.summary.title')}
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-center">
              <div className="flex items-center justify-center">
                <SeverityDonut counts={report.summary.by_severity} />
              </div>
              <div className="md:col-span-2 space-y-2">
                <p className="text-base text-slate-200 print:text-black">{report.summary.headline}</p>
                <div className="flex items-baseline gap-3 flex-wrap text-xs">
                  <span className="text-slate-400 print:text-gray-700">
                    {t('weeklyReport.summary.totalLabel')}:{' '}
                    <span className="text-slate-200 print:text-black font-mono text-base">
                      {report.summary.alerts_total}
                    </span>
                  </span>
                  <TrendBadge trend={report.summary.alerts_total_trend} />
                </div>
                <div className="flex flex-wrap gap-3 text-xs font-mono">
                  {SEV_ORDER.map(sev => {
                    const cur  = report.summary.by_severity[sev];
                    const prev = report.summary.by_severity_prev[sev];
                    return (
                      <span key={sev} className="text-slate-400 print:text-gray-700">
                        <span style={{ color: SEV_COLOR[sev] }}>●</span>{' '}
                        <span className="capitalize">{sev}:</span>{' '}
                        <span className="text-slate-200 print:text-black">{cur}</span>
                        <span className="text-slate-600 print:text-gray-500">  (prev {prev})</span>
                      </span>
                    );
                  })}
                </div>
              </div>
            </div>
          </section>

          {/* ── Block 2: Detection ──────────────────────────────────── */}
          <section className="cyjan-card rounded-lg p-4 print:shadow-none print:border-gray-300 print:border print:bg-white">
            <h2 className="text-sm font-semibold text-cyan-200 print:text-black mb-3 uppercase tracking-wider">
              {t('weeklyReport.detection.title')}
            </h2>

            <div className="mb-4">
              <p className="text-xs text-slate-500 print:text-gray-700 mb-1.5">
                {t('weeklyReport.detection.dailyTitle')}
              </p>
              <div className="bg-slate-950/50 print:bg-white rounded p-2 border border-slate-800/50 print:border-gray-300">
                <StackedDailyBars days={report.detection.daily} />
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div>
                <p className="text-xs text-slate-500 print:text-gray-700 mb-1.5">
                  {t('weeklyReport.detection.topRulesTitle')}
                </p>
                <table className="w-full text-xs font-mono">
                  <thead><tr className="text-slate-500 print:text-gray-600">
                    <th className="text-left pb-1">Rule</th>
                    <th className="text-left pb-1">Source</th>
                    <th className="text-right pb-1">Anzahl</th>
                  </tr></thead>
                  <tbody>
                    {report.detection.top_rules.length === 0 && (
                      <tr><td colSpan={3} className="text-slate-600 italic py-2">{t('common.empty')}</td></tr>
                    )}
                    {report.detection.top_rules.map(r => (
                      <tr key={r.rule_id} className="border-t border-slate-800/50 print:border-gray-200">
                        <td className="py-1 text-slate-200 print:text-black">
                          <SevPill sev={r.severity} />{r.rule_id}
                        </td>
                        <td className="py-1 text-slate-400 print:text-gray-700">{r.source}</td>
                        <td className="py-1 text-right text-slate-200 print:text-black">{r.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div>
                <p className="text-xs text-slate-500 print:text-gray-700 mb-1.5">
                  {t('weeklyReport.detection.topSourcesTitle')}
                </p>
                <table className="w-full text-xs font-mono">
                  <thead><tr className="text-slate-500 print:text-gray-600">
                    <th className="text-left pb-1">Source-IP</th>
                    <th className="text-right pb-1">Anzahl</th>
                  </tr></thead>
                  <tbody>
                    {report.detection.top_sources.length === 0 && (
                      <tr><td colSpan={2} className="text-slate-600 italic py-2">{t('common.empty')}</td></tr>
                    )}
                    {report.detection.top_sources.map(r => (
                      <tr key={r.src_ip} className="border-t border-slate-800/50 print:border-gray-200">
                        <td className="py-1 text-slate-200 print:text-black">
                          <SevPill sev={r.max_severity} />
                          {r.display_name || r.hostname || r.src_ip}
                          {(r.display_name || r.hostname) && (
                            <span className="text-slate-600 print:text-gray-500 ml-2 text-[10px]">{r.src_ip}</span>
                          )}
                        </td>
                        <td className="py-1 text-right text-slate-200 print:text-black">{r.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="mt-4">
              <p className="text-xs text-slate-500 print:text-gray-700 mb-1.5">
                {t('weeklyReport.detection.topExternalTitle')}
              </p>
              <table className="w-full text-xs font-mono">
                <thead><tr className="text-slate-500 print:text-gray-600">
                  <th className="text-left pb-1">Ziel</th>
                  <th className="text-left pb-1">Land</th>
                  <th className="text-left pb-1">ASN</th>
                  <th className="text-right pb-1">Anzahl</th>
                </tr></thead>
                <tbody>
                  {report.detection.top_external_dests.length === 0 && (
                    <tr><td colSpan={4} className="text-slate-600 italic py-2">{t('weeklyReport.detection.noExternal')}</td></tr>
                  )}
                  {report.detection.top_external_dests.map(d => (
                    <tr key={d.dst_ip} className="border-t border-slate-800/50 print:border-gray-200">
                      <td className="py-1 text-slate-200 print:text-black">{d.dst_ip}</td>
                      <td className="py-1 text-slate-300 print:text-gray-800">
                        {countryFlag(d.country_code)} {d.country || d.country_code || '–'}
                      </td>
                      <td className="py-1 text-slate-400 print:text-gray-700">{d.asn || '–'}</td>
                      <td className="py-1 text-right text-slate-200 print:text-black">{d.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          {/* ── Block 3: Operations ──────────────────────────────────── */}
          <section className="cyjan-card rounded-lg p-4 print:shadow-none print:border-gray-300 print:border print:bg-white">
            <h2 className="text-sm font-semibold text-cyan-200 print:text-black mb-3 uppercase tracking-wider">
              {t('weeklyReport.ops.title')}
            </h2>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              <div>
                <p className="text-xs text-slate-500 print:text-gray-700 mb-1.5">
                  {t('weeklyReport.ops.tapsTitle')}
                </p>
                <table className="w-full text-xs font-mono">
                  <thead><tr className="text-slate-500 print:text-gray-600">
                    <th className="text-left pb-1">Tap</th>
                    <th className="text-right pb-1">Alerts</th>
                    <th className="text-left pb-1 pl-2">Status</th>
                  </tr></thead>
                  <tbody>
                    {report.ops.taps.length === 0 && (
                      <tr><td colSpan={3} className="text-slate-600 italic py-2">{t('weeklyReport.ops.noTaps')}</td></tr>
                    )}
                    {report.ops.taps.map(tap => {
                      const ageMs = tap.last_seen ? Date.now() - new Date(tap.last_seen).getTime() : Infinity;
                      const live  = ageMs < 90_000;
                      return (
                        <tr key={tap.id} className="border-t border-slate-800/50 print:border-gray-200">
                          <td className="py-1 text-slate-200 print:text-black">{tap.name}</td>
                          <td className="py-1 text-right text-slate-200 print:text-black">{tap.alerts_week}</td>
                          <td className="py-1 pl-2 text-[10px] uppercase">
                            {tap.status === 'revoked' ? (
                              <span className="text-red-300">revoked</span>
                            ) : live ? (
                              <span className="text-green-300">online</span>
                            ) : (
                              <span className="text-slate-500">offline</span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              <div>
                <p className="text-xs text-slate-500 print:text-gray-700 mb-1.5">
                  {t('weeklyReport.ops.mlTitle')}
                </p>
                <div className="space-y-1 text-xs font-mono">
                  <Row label={t('weeklyReport.ops.fpMarked')}    value={report.ops.ml.fp_marked} />
                  <Row label={t('weeklyReport.ops.tpMarked')}    value={report.ops.ml.tp_marked} />
                  <Row label={t('weeklyReport.ops.tunerCycles')} value={report.ops.ml.tuner_cycles} />
                </div>
              </div>

              <div>
                <p className="text-xs text-slate-500 print:text-gray-700 mb-1.5">
                  {t('weeklyReport.ops.suricataTitle')}
                </p>
                <table className="w-full text-xs font-mono">
                  <tbody>
                    {report.ops.suricata_top_sids.length === 0 && (
                      <tr><td colSpan={2} className="text-slate-600 italic py-2">{t('common.empty')}</td></tr>
                    )}
                    {report.ops.suricata_top_sids.map(s => (
                      <tr key={s.sid} className="border-t border-slate-800/50 print:border-gray-200">
                        <td className="py-1 text-slate-200 print:text-black truncate" title={s.sid}>{s.sid}</td>
                        <td className="py-1 text-right text-slate-200 print:text-black">{s.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </section>

          {/* ── Block 4: Audit ───────────────────────────────────────── */}
          <section className="cyjan-card rounded-lg p-4 print:shadow-none print:border-gray-300 print:border print:bg-white">
            <h2 className="text-sm font-semibold text-cyan-200 print:text-black mb-3 uppercase tracking-wider">
              {t('weeklyReport.audit.title')}
            </h2>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div>
                <p className="text-xs text-slate-500 print:text-gray-700 mb-1.5">
                  {t('weeklyReport.audit.activeUsersTitle')}
                </p>
                <table className="w-full text-xs font-mono">
                  <tbody>
                    {report.audit.active_users.length === 0 && (
                      <tr><td colSpan={2} className="text-slate-600 italic py-2">{t('weeklyReport.audit.noUsers')}</td></tr>
                    )}
                    {report.audit.active_users.map(u => (
                      <tr key={u.username} className="border-t border-slate-800/50 print:border-gray-200">
                        <td className="py-1 text-slate-200 print:text-black">{u.username}</td>
                        <td className="py-1 text-right text-slate-400 print:text-gray-700">
                          {new Date(u.last_login).toLocaleString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div>
                <p className="text-xs text-slate-500 print:text-gray-700 mb-1.5">
                  {t('weeklyReport.audit.changesTitle')}
                </p>
                <div className="space-y-1 text-xs font-mono">
                  <Row label={t('weeklyReport.audit.whitelistAdds')} value={report.audit.whitelist_adds} />
                </div>
              </div>
            </div>
          </section>

          <p className="text-[10px] text-slate-600 print:text-gray-500 italic text-center">
            Cyjan IDS · {weekStr} · {new Date(report.week.generated).toLocaleString()}
          </p>
        </div>
      )}
    </div>
  );
}

function Row({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="flex justify-between border-b border-slate-800/50 print:border-gray-200 py-0.5">
      <span className="text-slate-400 print:text-gray-700">{label}</span>
      <span className="text-slate-200 print:text-black tabular-nums">{value}</span>
    </div>
  );
}
