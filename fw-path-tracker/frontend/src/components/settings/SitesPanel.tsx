import { Plus, Trash2 } from 'lucide-react';
import { useEffect, useState } from 'react';
import { getConfig, patchConfig } from '../../api';
import { de } from '../../i18n/de';

interface Override {
  name: string;
  cidr: string;
  device: string;
  vdom: string;
}

export default function SitesPanel() {
  const [overrides, setOverrides] = useState<Override[]>([]);
  const [status, setStatus] = useState<string | null>(null);

  useEffect(() => {
    getConfig('sites').then((cfg) =>
      setOverrides(((cfg.overrides as Override[]) ?? [])));
  }, []);

  const update = (i: number, k: keyof Override, v: string) =>
    setOverrides((list) => list.map((o, idx) => (idx === i ? { ...o, [k]: v } : o)));

  async function save() {
    try {
      await patchConfig('sites', { overrides: overrides.filter((o) => o.cidr && o.device) });
      setStatus(de.settings.saved);
    } catch (e) {
      setStatus(`${de.common.error}: ${e instanceof Error ? e.message : e}`);
    }
  }

  return (
    <div className="fwpt-card space-y-3">
      <h2 className="font-medium text-slate-100">{de.settings.sites}</h2>
      <p className="text-xs text-slate-500">
        Manuelle Overrides für das Prefix→Firewall-Mapping (gewinnen immer gegen
        FMG-Daten). Normalfall: leer — das Mapping kommt aus connected Networks
        + statischen Routen des FMG-Syncs.
      </p>
      {overrides.map((o, i) => (
        <div key={i} className="flex flex-wrap items-center gap-2">
          <input className="fwpt-input !w-36" placeholder="Name" value={o.name}
            onChange={(e) => update(i, 'name', e.target.value)} />
          <input className="fwpt-input !w-40 font-mono" placeholder="10.1.0.0/20" value={o.cidr}
            onChange={(e) => update(i, 'cidr', e.target.value)} />
          <input className="fwpt-input !w-36" placeholder="Gerät" value={o.device}
            onChange={(e) => update(i, 'device', e.target.value)} />
          <input className="fwpt-input !w-28" placeholder="VDOM" value={o.vdom}
            onChange={(e) => update(i, 'vdom', e.target.value)} />
          <button type="button" className="text-slate-500 hover:text-red-400"
            onClick={() => setOverrides((l) => l.filter((_, idx) => idx !== i))}>
            <Trash2 size={16} />
          </button>
        </div>
      ))}
      <div className="flex items-center gap-2">
        <button type="button" className="fwpt-btn-ghost"
          onClick={() => setOverrides((l) => [...l, { name: '', cidr: '', device: '', vdom: 'root' }])}>
          <Plus size={14} /> Override
        </button>
        <button type="button" className="fwpt-btn" onClick={save}>{de.settings.save}</button>
        {status && <span className="text-sm text-slate-400">{status}</span>}
      </div>
    </div>
  );
}
