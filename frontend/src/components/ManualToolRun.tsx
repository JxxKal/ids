// ── ManualToolRun — direkter kali-Tool-Aufruf mit Form ──────────────────────
//
// Eigenständige Komponente. Tool/Args-Defaults werden beim Tool-Wechsel
// resetted, außer der User hat die Args manuell editiert.

import { useState } from 'react';
import { runRedTeamTool } from '../api';
import type { RedTeamRunRequest, RedTeamRunResponse } from '../types';


type ToolName = RedTeamRunRequest['tool'];

const TOOL_DEFAULTS: Record<ToolName, string> = {
  ping:   '-c 1 -W 2',
  nmap:   '-sS -p 22,80,443 -Pn',
  hping3: '-c 3 -S -p 80',
  hydra:  '-l admin -P /dev/null -t 1 -f',
  ncat:   '-z -w 2',
};


export function ManualToolRun({
  onRunComplete,
}: {
  onRunComplete?: () => void;
}) {
  const [tool, setToolRaw]                  = useState<ToolName>('ping');
  const [argsStr, setArgsStr]               = useState(TOOL_DEFAULTS.ping);
  const [argsManuallyEdited, setEdited]     = useState(false);
  const [targetIp, setTargetIp]             = useState('192.0.2.254');
  const [timeoutSec, setTimeoutSec]         = useState(30);
  const [attachIface, setAttachIface]       = useState(false);
  const [expectedRuleId, setExpectedRuleId] = useState('');
  const [running, setRunning]               = useState(false);
  const [result, setResult]                 = useState<RedTeamRunResponse | null>(null);
  const [err, setErr]                       = useState<string | null>(null);

  function setTool(t: ToolName) {
    setToolRaw(t);
    if (!argsManuallyEdited) setArgsStr(TOOL_DEFAULTS[t]);
  }

  async function handleRun() {
    setRunning(true); setResult(null); setErr(null);
    try {
      const r = await runRedTeamTool({
        tool, target_ip: targetIp,
        args: argsStr.split(/\s+/).filter(Boolean),
        timeout_sec: timeoutSec,
        attach_iface: attachIface,
        expected_alert_rule_id: expectedRuleId.trim() || null,
      });
      setResult(r);
      onRunComplete?.();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Run fehlgeschlagen');
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="border border-slate-800 rounded p-3 space-y-3">
      <div className="flex items-baseline justify-between flex-wrap gap-2">
        <h3 className="text-[11px] uppercase tracking-wider text-slate-500">
          Manueller Tool-Run
        </h3>
        <p className="text-[10px] text-slate-600">
          Direkter kali-Aufruf — nur RFC-5737 TEST-NETs erlaubt.
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
        <div className="flex flex-col gap-1">
          <label className="text-slate-400">Tool</label>
          <select className="input" value={tool}
            onChange={e => setTool(e.target.value as ToolName)}>
            <option value="ping">ping</option>
            <option value="nmap">nmap</option>
            <option value="hping3">hping3</option>
            <option value="hydra">hydra</option>
            <option value="ncat">ncat</option>
          </select>
        </div>
        <div className="flex flex-col gap-1 sm:col-span-2">
          <label className="text-slate-400">Target-IP (TEST-NET)</label>
          <input className="input font-mono" value={targetIp}
            onChange={e => setTargetIp(e.target.value)} placeholder="192.0.2.254" />
          <span className="text-[10px] text-slate-600">
            <code>192.0.2.254</code> = Host-Peer (pingbar). <code>192.0.2.1</code> = kali selbst.
            Andere TEST-NET-IPs (z.B. <code>192.0.2.10</code>) sind unbeantwortet,
            werden aber vom Sniffer mitgelesen — gut für Detection-Tests.
          </span>
        </div>
        <div className="flex flex-col gap-1 sm:col-span-3">
          <label className="text-slate-400">Args (Space-separated, Tool-Whitelist serverseitig)</label>
          <input className="input font-mono" value={argsStr}
            onChange={e => { setArgsStr(e.target.value); setEdited(true); }}
            placeholder="-c 1 -W 2" />
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-slate-400">Timeout (s)</label>
          <input className="input" type="number" min={5} max={120}
            value={timeoutSec} onChange={e => setTimeoutSec(parseInt(e.target.value) || 30)} />
        </div>
        <div className="flex flex-col gap-1 sm:col-span-2">
          <label className="text-slate-400">Expected Alert Rule (optional)</label>
          <input className="input font-mono" value={expectedRuleId}
            onChange={e => setExpectedRuleId(e.target.value)} placeholder="SCAN_001" />
        </div>
        <label className="flex items-center gap-2 cursor-pointer text-xs sm:col-span-3">
          <input type="checkbox" className="accent-cyan-500"
            checked={attachIface} onChange={e => setAttachIface(e.target.checked)} />
          <span className={attachIface ? 'text-cyan-300' : 'text-slate-500'}>
            veth-Handover (cyjan-inject) aktivieren
          </span>
        </label>
      </div>

      <div className="flex justify-between items-center flex-wrap gap-2">
        <div>
          {err && <span className="text-xs text-red-400 break-words">{err}</span>}
          {result && (
            <span className={`text-xs ${result.exit_code === 0 ? 'text-emerald-400' : 'text-amber-400'}`}>
              exit={result.exit_code} · {result.duration_ms} ms · {result.matched_alerts.length} alerts
            </span>
          )}
        </div>
        <button className="btn-primary text-xs"
          disabled={running || !targetIp.trim()}
          onClick={handleRun}>
          {running ? 'Läuft…' : 'Run'}
        </button>
      </div>

      {result && (
        <div className="space-y-2 mt-2">
          {result.stdout_excerpt && (
            <pre className="text-[10px] bg-slate-900/60 border border-slate-800 rounded p-2 overflow-x-auto font-mono text-slate-300">{result.stdout_excerpt}</pre>
          )}
          {result.stderr_excerpt && (
            <pre className="text-[10px] bg-red-500/5 border border-red-500/30 rounded p-2 overflow-x-auto font-mono text-red-300">{result.stderr_excerpt}</pre>
          )}
        </div>
      )}
    </div>
  );
}
