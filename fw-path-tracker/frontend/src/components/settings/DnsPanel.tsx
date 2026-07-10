import { useEffect, useState } from 'react';
import { getConfig, patchConfig } from '../../api';
import { de } from '../../i18n/de';

function toList(s: string): string[] {
  return s.split(',').map((x) => x.trim()).filter(Boolean);
}

export default function DnsPanel() {
  const [resolvers, setResolvers] = useState('');
  const [domains, setDomains] = useState('');
  const [status, setStatus] = useState<string | null>(null);

  useEffect(() => {
    getConfig('dns').then((cfg) => {
      setResolvers(((cfg.resolvers as string[]) ?? []).join(', '));
      setDomains(((cfg.search_domains as string[]) ?? []).join(', '));
    });
  }, []);

  async function save() {
    try {
      await patchConfig('dns', { resolvers: toList(resolvers), search_domains: toList(domains) });
      setStatus(de.settings.saved);
    } catch (e) {
      setStatus(`${de.common.error}: ${e instanceof Error ? e.message : e}`);
    }
  }

  return (
    <div className="fwpt-card space-y-3">
      <h2 className="font-medium text-slate-100">{de.settings.dns}</h2>
      <div>
        <label className="mb-1 block text-xs text-slate-400">
          Resolver (kommagetrennt, leer = System-Resolver)
        </label>
        <input className="fwpt-input" value={resolvers} placeholder="10.0.0.53, 10.0.1.53"
          onChange={(e) => setResolvers(e.target.value)} />
      </div>
      <div>
        <label className="mb-1 block text-xs text-slate-400">Suchdomains (kommagetrennt)</label>
        <input className="fwpt-input" value={domains} placeholder="corp.example, dmz.example"
          onChange={(e) => setDomains(e.target.value)} />
      </div>
      <div className="flex items-center gap-2">
        <button type="button" className="fwpt-btn" onClick={save}>{de.settings.save}</button>
        {status && <span className="text-sm text-slate-400">{status}</span>}
      </div>
    </div>
  );
}
