import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { fetchVersion } from '../api';
import { changelogFor, type ChangelogEntry } from '../changelog';

const ACK_KEY = 'ids_ack_version';

// Popup beim ersten Login in eine neue Version: zeigt die Highlights dieser
// Version. „Gelesen — nicht mehr anzeigen" merkt die Version in localStorage,
// danach erscheint es erst beim nächsten Update wieder. Das X (bzw. „Später")
// schließt nur für diese Sitzung — beim nächsten Login käme es erneut.
export function VersionNotesPopup() {
  const { t } = useTranslation();
  const [entry, setEntry] = useState<ChangelogEntry | null>(null);

  useEffect(() => {
    let alive = true;
    fetchVersion()
      .then(({ version }) => {
        if (!alive || !version || version === 'demo') return;
        const acked = localStorage.getItem(ACK_KEY);
        if (acked === version) return;             // diese Version schon quittiert
        const e = changelogFor(version);
        if (e) setEntry(e);                        // nur zeigen, wenn es Notizen gibt
      })
      .catch(() => {});
    return () => { alive = false; };
  }, []);

  if (!entry) return null;

  const acknowledge = () => {
    localStorage.setItem(ACK_KEY, entry.version);
    setEntry(null);
  };
  const dismiss = () => setEntry(null);  // nur diese Sitzung

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-[70] p-4"
         onClick={dismiss}>
      <div className="card w-full max-w-lg p-0 overflow-hidden" onClick={e => e.stopPropagation()}>
        <div className="px-5 py-4 border-b border-slate-800 bg-gradient-to-r from-cyan-500/10 to-transparent">
          <div className="text-[11px] uppercase tracking-wider text-cyan-400 font-mono">
            {t('versionNotes.badge')}
          </div>
          <h2 className="text-lg font-semibold text-slate-100 mt-0.5">
            {entry.version} — {entry.title}
          </h2>
          <div className="text-xs text-slate-500 font-mono mt-0.5">{entry.date}</div>
        </div>

        <ul className="px-5 py-4 space-y-2 max-h-[50vh] overflow-y-auto">
          {entry.notes.map((n, i) => (
            <li key={i} className="flex gap-2 text-sm text-slate-300 leading-relaxed">
              <span className="text-cyan-500 shrink-0 mt-0.5">›</span>
              <span>{n}</span>
            </li>
          ))}
        </ul>

        <div className="px-5 py-3 border-t border-slate-800 flex justify-end gap-2">
          <button onClick={dismiss} className="btn-ghost text-xs">
            {t('versionNotes.later')}
          </button>
          <button onClick={acknowledge}
                  className="px-3 py-1.5 rounded text-xs font-medium bg-cyan-700 hover:bg-cyan-600 text-white transition-colors">
            {t('versionNotes.ack')}
          </button>
        </div>
      </div>
    </div>
  );
}
