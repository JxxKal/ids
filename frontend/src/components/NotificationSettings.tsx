// ── NotificationSettings — Channels-CRUD + Test + Delivery-Log ──────────────
//
// UI für notification_channels: pro User mehrere Channels mit Type-spezifischer
// Config, Severity-Filter, Test-Button, Delivery-Log.
//
// Type-Liste kommt vom Backend (GET /api/notifications/types) — Phase 2
// (Cyjan-Cloud-Companion-App) liefert zusätzliche Types ohne Frontend-Change.

import { useEffect, useState } from 'react';
import {
  fetchNotificationTypes, fetchNotificationChannels, createNotificationChannel,
  updateNotificationChannel, deleteNotificationChannel, testNotificationChannel,
  fetchNotificationDeliveries,
} from '../api';
import type {
  NotificationChannel, NotificationChannelCreate, NotificationDelivery,
  NotificationTypesInfo, SeverityLevel,
} from '../types';

const TYPE_ICON: Record<string, string> = {
  webhook: '🪝',
  ntfy:    '📱',
  email:   '✉️',
  'cyjan-cloud': '☁️',   // Phase 2 reserved
};


export function NotificationSettings() {
  const [info, setInfo]           = useState<NotificationTypesInfo | null>(null);
  const [channels, setChannels]   = useState<NotificationChannel[]>([]);
  const [creating, setCreating]   = useState(false);
  const [editing, setEditing]     = useState<NotificationChannel | null>(null);
  const [deliveries, setDeliveries] = useState<NotificationDelivery[]>([]);
  const [showDeliveries, setShowDeliveries] = useState<string | null>(null);
  const [error, setError]         = useState<string | null>(null);
  const [msg, setMsg]             = useState<string | null>(null);

  const reload = async () => {
    setError(null);
    try {
      setInfo(await fetchNotificationTypes());
      setChannels(await fetchNotificationChannels());
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Fetch failed');
    }
  };

  useEffect(() => { reload(); }, []);

  async function handleToggle(ch: NotificationChannel) {
    try {
      await updateNotificationChannel(ch.id, { enabled: !ch.enabled });
      reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Toggle failed');
    }
  }

  async function handleDelete(ch: NotificationChannel) {
    if (!confirm(`Channel "${ch.name}" wirklich löschen?`)) return;
    try {
      await deleteNotificationChannel(ch.id);
      setMsg(`Channel "${ch.name}" gelöscht`);
      setTimeout(() => setMsg(null), 3000);
      reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Delete failed');
    }
  }

  async function handleTest(ch: NotificationChannel) {
    setMsg(null); setError(null);
    try {
      const r = await testNotificationChannel(ch.id);
      setMsg(`Test-Push an "${r.channel}" verschickt. Schaue im Delivery-Log unten.`);
      setTimeout(() => setMsg(null), 5000);
      // Auto-open delivery log for that channel
      setShowDeliveries(ch.id);
      const log = await fetchNotificationDeliveries(ch.id, 10);
      setDeliveries(log);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Test failed');
    }
  }

  async function loadDeliveries(channelId: string | null) {
    setShowDeliveries(channelId);
    if (channelId) {
      try {
        setDeliveries(await fetchNotificationDeliveries(channelId, 20));
      } catch {
        setDeliveries([]);
      }
    } else {
      setDeliveries([]);
    }
  }

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-sm font-semibold text-slate-200">Benachrichtigungen</h2>
        <p className="text-xs text-slate-500 mt-1">
          Per-Channel-Routing für Alerts. Push aufs Handy via{' '}
          <a href="https://ntfy.sh" target="_blank" rel="noreferrer" className="text-cyan-300 hover:underline">ntfy.sh</a>
          {' '}(installierbare App für iOS/Android), Webhook für Slack/Teams/Discord, oder Email für SOC-Mailbox.
          Severity-Filter + Throttling pro Channel.
        </p>
      </div>

      {error && <div className="text-red-400 text-xs bg-red-500/10 border border-red-500/30 rounded p-2 break-words">{error}</div>}
      {msg   && <div className="text-emerald-300 text-xs bg-emerald-500/10 border border-emerald-500/30 rounded p-2">{msg}</div>}

      {/* Channel-Liste */}
      <div className="space-y-2">
        {channels.length === 0 && !creating && (
          <p className="text-xs text-slate-600 italic py-4 text-center">
            Noch keine Channels. Klick "+ Neuer Channel" um anzufangen.
          </p>
        )}
        {channels.map(ch => (
          <ChannelCard key={ch.id} channel={ch}
            onEdit={() => setEditing(ch)}
            onTest={() => handleTest(ch)}
            onToggle={() => handleToggle(ch)}
            onDelete={() => handleDelete(ch)}
            onShowDeliveries={() => loadDeliveries(showDeliveries === ch.id ? null : ch.id)}
            showingDeliveries={showDeliveries === ch.id}
          />
        ))}
        {showDeliveries && (
          <DeliveryLog deliveries={deliveries} channelId={showDeliveries} />
        )}
      </div>

      {/* Neuer Channel */}
      {!creating && !editing && (
        <button onClick={() => setCreating(true)} className="btn-primary text-xs">
          + Neuer Channel
        </button>
      )}

      {(creating || editing) && info && (
        <ChannelForm
          types={info.types}
          severityLevels={info.severity_levels}
          sourceOptions={info.source_options}
          initial={editing}
          onSave={async (data) => {
            try {
              if (editing) {
                await updateNotificationChannel(editing.id, data);
              } else {
                await createNotificationChannel(data as NotificationChannelCreate);
              }
              setCreating(false); setEditing(null);
              setMsg(editing ? 'Channel aktualisiert' : 'Channel angelegt');
              setTimeout(() => setMsg(null), 3000);
              reload();
            } catch (e) {
              setError(e instanceof Error ? e.message : 'Save failed');
            }
          }}
          onCancel={() => { setCreating(false); setEditing(null); }}
        />
      )}
    </div>
  );
}


function ChannelCard({
  channel: ch, onEdit, onTest, onToggle, onDelete, onShowDeliveries, showingDeliveries,
}: {
  channel:          NotificationChannel;
  onEdit:           () => void;
  onTest:           () => void;
  onToggle:         () => void;
  onDelete:         () => void;
  onShowDeliveries: () => void;
  showingDeliveries: boolean;
}) {
  const icon = TYPE_ICON[ch.type] || '🔔';
  const target =
    ch.type === 'webhook' ? String(ch.config?.url || '?') :
    ch.type === 'ntfy'    ? `${ch.config?.server || 'https://ntfy.sh'}/${ch.config?.topic || '?'}` :
    ch.type === 'email'   ? String(ch.config?.to || '?') :
    JSON.stringify(ch.config);

  return (
    <div className={`border rounded p-3 ${ch.enabled ? 'border-slate-700 bg-slate-800/30' : 'border-slate-800 bg-slate-900/50 opacity-60'}`}>
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="flex-1 min-w-0">
          <div className="flex items-baseline gap-2 flex-wrap">
            <span className="text-xl">{icon}</span>
            <span className="font-semibold text-slate-200 text-sm">{ch.name}</span>
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-700/60 text-slate-400 font-mono">{ch.type}</span>
            <span className={`text-[10px] px-1.5 py-0.5 rounded ${
              ch.severity_min === 'critical' ? 'bg-red-500/15 text-red-300' :
              ch.severity_min === 'high'     ? 'bg-amber-500/15 text-amber-300' :
              ch.severity_min === 'medium'   ? 'bg-yellow-500/15 text-yellow-300' :
                                                'bg-slate-500/15 text-slate-400'
            }`}>≥ {ch.severity_min}</span>
            {!ch.enabled && <span className="text-[10px] text-slate-500 italic">disabled</span>}
          </div>
          <p className="text-[11px] text-slate-500 mt-1 font-mono break-all">{target}</p>
          <div className="flex gap-3 text-[10px] text-slate-600 mt-1 flex-wrap">
            {ch.rule_prefix_filter && <span>rule: {ch.rule_prefix_filter}</span>}
            {ch.source_filter && ch.source_filter.length > 0 && <span>sources: {ch.source_filter.join(',')}</span>}
            <span>throttle: {ch.throttle_seconds}s</span>
            {ch.last_used && <span>last: {new Date(ch.last_used).toLocaleString()}</span>}
          </div>
        </div>
        <div className="flex gap-1 flex-wrap">
          <button onClick={onTest} className="btn-ghost text-[11px]" title="Test-Push senden">Test</button>
          <button onClick={onEdit} className="btn-ghost text-[11px]">Edit</button>
          <button onClick={onToggle} className="btn-ghost text-[11px]">{ch.enabled ? 'Disable' : 'Enable'}</button>
          <button onClick={onShowDeliveries} className={`btn-ghost text-[11px] ${showingDeliveries ? 'text-cyan-300' : ''}`}>Log</button>
          <button onClick={onDelete} className="text-red-400 hover:text-red-300 text-[11px] px-2">Del</button>
        </div>
      </div>
    </div>
  );
}


function ChannelForm({
  types, severityLevels, sourceOptions, initial, onSave, onCancel,
}: {
  types:          string[];
  severityLevels: SeverityLevel[];
  sourceOptions:  string[];
  initial:        NotificationChannel | null;
  onSave:         (data: Partial<NotificationChannelCreate>) => Promise<void>;
  onCancel:       () => void;
}) {
  const [name,         setName]         = useState(initial?.name ?? '');
  const [type,         setType]         = useState<string>(initial?.type ?? 'ntfy');
  const [severityMin,  setSeverityMin]  = useState<SeverityLevel>(initial?.severity_min ?? 'high');
  const [rulePrefix,   setRulePrefix]   = useState(initial?.rule_prefix_filter ?? '');
  const [sources,      setSources]      = useState<string[]>(initial?.source_filter ?? []);
  const [throttle,     setThrottle]     = useState(initial?.throttle_seconds ?? 30);
  const [config,       setConfig]       = useState<Record<string, string>>(() => {
    const c = (initial?.config || {}) as Record<string, string>;
    return {
      url:        String(c.url ?? ''),
      topic:      String(c.topic ?? ''),
      server:     String(c.server ?? 'https://ntfy.sh'),
      auth_token: String(c.auth_token ?? ''),
      to:         String(c.to ?? ''),
      subject:    String(c.subject ?? ''),
    };
  });
  const [saving, setSaving] = useState(false);

  const cleanConfig = (): Record<string, unknown> => {
    if (type === 'webhook') {
      return { url: config.url };
    }
    if (type === 'ntfy') {
      const out: Record<string, unknown> = { topic: config.topic, server: config.server || 'https://ntfy.sh' };
      if (config.auth_token) out.auth_token = config.auth_token;
      return out;
    }
    if (type === 'email') {
      const out: Record<string, unknown> = { to: config.to };
      if (config.subject) out.subject = config.subject;
      return out;
    }
    return {};
  };

  async function handleSubmit() {
    setSaving(true);
    try {
      const data: Partial<NotificationChannelCreate> = {
        name, type, config: cleanConfig(),
        severity_min: severityMin,
        rule_prefix_filter: rulePrefix.trim() || null,
        source_filter: sources.length ? sources : null,
        throttle_seconds: throttle,
      };
      await onSave(data);
    } finally { setSaving(false); }
  }

  function toggleSource(src: string) {
    setSources(s => s.includes(src) ? s.filter(x => x !== src) : [...s, src]);
  }

  return (
    <div className="border border-cyan-700/40 bg-cyan-500/5 rounded p-3 space-y-3">
      <h3 className="text-xs font-semibold text-cyan-300">
        {initial ? 'Channel bearbeiten' : 'Neuer Channel'}
      </h3>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
        <div className="flex flex-col gap-1">
          <label className="text-slate-400">Name</label>
          <input className="input" value={name} onChange={e => setName(e.target.value)}
            placeholder="z.B. 'Mein Handy via ntfy'" />
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-slate-400">Type</label>
          <select className="input" value={type} onChange={e => setType(e.target.value)} disabled={!!initial}>
            {types.map(t => <option key={t} value={t}>{TYPE_ICON[t] || '🔔'} {t}</option>)}
          </select>
        </div>

        {/* Type-spezifische Felder */}
        {type === 'webhook' && (
          <div className="flex flex-col gap-1 sm:col-span-2">
            <label className="text-slate-400">Webhook-URL</label>
            <input className="input font-mono" value={config.url}
              onChange={e => setConfig({...config, url: e.target.value})}
              placeholder="https://hooks.slack.com/services/..." />
          </div>
        )}
        {type === 'ntfy' && (
          <>
            <div className="flex flex-col gap-1">
              <label className="text-slate-400">Topic</label>
              <input className="input font-mono" value={config.topic}
                onChange={e => setConfig({...config, topic: e.target.value})}
                placeholder="cyjan-mein-handy-xyz123" />
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-slate-400">Server (default ntfy.sh)</label>
              <input className="input font-mono" value={config.server}
                onChange={e => setConfig({...config, server: e.target.value})}
                placeholder="https://ntfy.sh" />
            </div>
            <div className="flex flex-col gap-1 sm:col-span-2">
              <label className="text-slate-400">Auth-Token (optional, für self-hosted ntfy)</label>
              <input className="input font-mono" type="password" value={config.auth_token}
                onChange={e => setConfig({...config, auth_token: e.target.value})}
                placeholder="leer wenn ntfy.sh public" />
              <p className="text-[10px] text-slate-600">
                ntfy-App installieren: <a href="https://ntfy.sh" target="_blank" rel="noreferrer" className="text-cyan-300 hover:underline">ntfy.sh</a>{' '}
                · Topic im App-Subscribe eingeben · IDS pusht hierhin
              </p>
            </div>
          </>
        )}
        {type === 'email' && (
          <>
            <div className="flex flex-col gap-1">
              <label className="text-slate-400">Empfänger</label>
              <input className="input font-mono" value={config.to}
                onChange={e => setConfig({...config, to: e.target.value})}
                placeholder="soc@example.com" />
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-slate-400">Subject (optional)</label>
              <input className="input" value={config.subject}
                onChange={e => setConfig({...config, subject: e.target.value})}
                placeholder="default: '[SEVERITY] rule_id'" />
            </div>
          </>
        )}

        {/* Filter */}
        <div className="flex flex-col gap-1">
          <label className="text-slate-400">Severity ≥</label>
          <select className="input" value={severityMin} onChange={e => setSeverityMin(e.target.value as SeverityLevel)}>
            {severityLevels.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-slate-400">Throttle (Sek.)</label>
          <input className="input" type="number" min={0} max={3600}
            value={throttle} onChange={e => setThrottle(parseInt(e.target.value) || 30)} />
        </div>
        <div className="flex flex-col gap-1 sm:col-span-2">
          <label className="text-slate-400">Rule-Prefix-Filter (optional)</label>
          <input className="input font-mono" value={rulePrefix}
            onChange={e => setRulePrefix(e.target.value)}
            placeholder="SURICATA: oder MODBUS_ oder leer = alle" />
        </div>
        <div className="flex flex-col gap-1 sm:col-span-2">
          <label className="text-slate-400">Sources (leer = alle)</label>
          <div className="flex gap-2 flex-wrap">
            {sourceOptions.map(s => (
              <label key={s} className="flex items-center gap-1 cursor-pointer">
                <input type="checkbox" className="accent-cyan-500"
                  checked={sources.includes(s)} onChange={() => toggleSource(s)} />
                <span className="text-slate-300 text-xs">{s}</span>
              </label>
            ))}
          </div>
        </div>
      </div>

      <div className="flex gap-2 justify-end">
        <button onClick={onCancel} className="btn-ghost text-xs">Abbrechen</button>
        <button onClick={handleSubmit} disabled={saving || !name.trim()} className="btn-primary text-xs">
          {saving ? 'Speichere…' : 'Speichern'}
        </button>
      </div>
    </div>
  );
}


function DeliveryLog({ deliveries }: { deliveries: NotificationDelivery[]; channelId: string }) {
  return (
    <div className="border border-slate-800 bg-slate-900/30 rounded p-3 ml-4">
      <p className="text-[10px] uppercase tracking-wider text-slate-500 mb-2">
        Delivery-Log (letzte {deliveries.length})
      </p>
      {deliveries.length === 0 && (
        <p className="text-[11px] text-slate-600 italic">Noch keine Einträge.</p>
      )}
      <div className="space-y-1">
        {deliveries.map(d => (
          <div key={d.id} className="flex items-baseline gap-2 text-[11px] flex-wrap py-0.5 border-b border-slate-800/40 last:border-b-0">
            <span className="text-slate-500 font-mono text-[10px] whitespace-nowrap">
              {new Date(d.ts).toLocaleString()}
            </span>
            <span className={`px-1.5 py-0.5 rounded text-[10px] whitespace-nowrap ${
              d.status === 'sent'         ? 'bg-emerald-500/15 text-emerald-300' :
              d.status === 'failed'       ? 'bg-red-500/15 text-red-300' :
              d.status === 'rate_limited' ? 'bg-amber-500/15 text-amber-300' :
              d.status === 'filtered'     ? 'bg-slate-500/15 text-slate-400' :
                                            'bg-slate-500/15 text-slate-400'
            }`}>{d.status}</span>
            {d.rule_id && <span className="font-mono text-slate-400 truncate">{d.rule_id}</span>}
            {d.status_code && <span className="text-slate-500 text-[10px]">HTTP {d.status_code}</span>}
            {d.latency_ms != null && <span className="text-slate-500 tabular-nums text-[10px]">{d.latency_ms} ms</span>}
            {d.error && <span className="text-red-400 truncate">{d.error}</span>}
          </div>
        ))}
      </div>
    </div>
  );
}
