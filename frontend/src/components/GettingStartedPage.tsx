import { Trans, useTranslation } from 'react-i18next';
import {
  Activity, Brain, ChevronRight, Compass, Database, Filter,
  Globe, Network, Package, Server, ShieldCheck, Workflow,
} from 'lucide-react';
import type { NavTab } from './Sidebar';

interface Props {
  onNavigate: (tab: NavTab) => void;
}

/**
 * Erste-Schritte-Handbuch. Sechs aufeinander aufbauende Schritte als
 * <details>-Akkordeon. Pro Schritt ein "Jetzt öffnen"-Button, der via
 * onNavigate in den entsprechenden Tab springt — alle Texte aus i18n.
 */
export function GettingStartedPage({ onNavigate }: Props) {
  const { t } = useTranslation();

  const STEPS: {
    id: string;
    icon: JSX.Element;
    color: string;
    actions?: { label: string; tab: NavTab }[];
  }[] = [
    {
      id: 'networks',
      icon: <Network size={18} />,
      color: 'cyan',
      actions: [
        { label: t('gettingStarted.steps.networks.openNetworks'), tab: 'networks' },
        { label: t('gettingStarted.steps.networks.openHosts'),    tab: 'hosts' },
      ],
    },
    {
      id: 'resolver',
      icon: <Globe size={18} />,
      color: 'cyan',
      actions: [{ label: t('gettingStarted.steps.resolver.open'), tab: 'settings' }],
    },
    {
      id: 'ml',
      icon: <Brain size={18} />,
      color: 'amber',
      actions: [{ label: t('gettingStarted.steps.ml.open'), tab: 'settings' }],
    },
    {
      id: 'dashboard',
      icon: <Filter size={18} />,
      color: 'cyan',
      actions: [{ label: t('gettingStarted.steps.dashboard.open'), tab: 'dashboard' }],
    },
    {
      id: 'boundary',
      icon: <ShieldCheck size={18} />,
      color: 'violet',
      actions: [{ label: t('gettingStarted.steps.boundary.open'), tab: 'settings' }],
    },
    {
      id: 'updates',
      icon: <Package size={18} />,
      color: 'slate',
      actions: [{ label: t('gettingStarted.steps.updates.open'), tab: 'settings' }],
    },
  ];

  const COLOR_STYLES: Record<string, string> = {
    cyan:   'border-cyan-500/40 bg-cyan-900/15',
    amber:  'border-amber-500/40 bg-amber-900/15',
    violet: 'border-violet-500/40 bg-violet-900/15',
    slate:  'border-slate-500/40 bg-slate-800/30',
  };
  const ICON_STYLES: Record<string, string> = {
    cyan:   'bg-cyan-500/15 text-cyan-300',
    amber:  'bg-amber-500/15 text-amber-300',
    violet: 'bg-violet-500/15 text-violet-300',
    slate:  'bg-slate-700/40 text-slate-300',
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div className="rounded-lg border border-cyan-500/40 bg-cyan-900/10 p-5">
        <div className="flex items-start gap-3">
          <div className="rounded-lg bg-cyan-500/15 p-2 text-cyan-300">
            <Compass size={24} />
          </div>
          <div className="flex-1">
            <h1 className="text-xl font-semibold text-slate-100">{t('gettingStarted.title')}</h1>
            <p className="text-sm text-slate-400 mt-1">{t('gettingStarted.subtitle')}</p>
          </div>
        </div>
        <p className="text-xs text-slate-400 mt-3 leading-relaxed">
          <Trans i18nKey="gettingStarted.intro" components={{ strong: <strong className="text-slate-200" /> }} />
        </p>
      </div>

      {/* Pipeline-Übersicht */}
      <div className="rounded-lg border border-slate-700/50 bg-slate-900/40 p-4">
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3 flex items-center gap-2">
          <Workflow size={16} className="text-slate-400" />
          {t('gettingStarted.pipelineTitle')}
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] text-slate-400">
          <div className="rounded border border-slate-700 bg-slate-900/60 p-2 text-center">
            <Activity size={14} className="inline text-cyan-400 mb-1" /><br />
            <span className="text-cyan-300 font-mono">sniffer</span>
          </div>
          <div className="rounded border border-slate-700 bg-slate-900/60 p-2 text-center">
            <Filter size={14} className="inline text-cyan-400 mb-1" /><br />
            <span className="text-cyan-300 font-mono">flow-aggregator</span>
          </div>
          <div className="rounded border border-slate-700 bg-slate-900/60 p-2 text-center">
            <Brain size={14} className="inline text-amber-400 mb-1" /><br />
            <span className="text-amber-300 font-mono">signature + ml</span>
          </div>
          <div className="rounded border border-slate-700 bg-slate-900/60 p-2 text-center">
            <Database size={14} className="inline text-violet-400 mb-1" /><br />
            <span className="text-violet-300 font-mono">alert-manager</span>
          </div>
        </div>
        <p className="text-[11px] text-slate-500 mt-3 leading-relaxed">{t('gettingStarted.pipelineNote')}</p>
      </div>

      {/* Schritte */}
      {STEPS.map((step, idx) => (
        <details
          key={step.id}
          open={idx === 0}
          className={`rounded-lg border ${COLOR_STYLES[step.color]} group`}
        >
          <summary className="cursor-pointer select-none p-4 flex items-center gap-3 list-none">
            <div className={`rounded-lg p-2 ${ICON_STYLES[step.color]}`}>{step.icon}</div>
            <div className="flex-1 min-w-0">
              <div className="text-[10px] uppercase tracking-wider text-slate-500 font-mono">
                {t('gettingStarted.stepLabel', { num: idx + 1 })}
              </div>
              <div className="text-sm font-semibold text-slate-100">
                {t(`gettingStarted.steps.${step.id}.title`)}
              </div>
            </div>
            <ChevronRight size={18} className="text-slate-500 transition-transform group-open:rotate-90" />
          </summary>
          <div className="px-4 pb-4 space-y-3 text-[13px] text-slate-300 leading-relaxed border-t border-slate-700/40 pt-3">
            <p className="text-slate-400">
              <Trans
                i18nKey={`gettingStarted.steps.${step.id}.description`}
                components={{
                  strong: <strong className="text-slate-200" />,
                  code: <code className="px-1 py-0.5 rounded bg-slate-800 text-cyan-300 text-[12px] font-mono" />,
                  em: <em className="text-amber-300" />,
                }}
              />
            </p>
            {/* Bullet-Liste — kommt aus returnObjects */}
            {(() => {
              const bullets = t(`gettingStarted.steps.${step.id}.bullets`, { returnObjects: true, defaultValue: [] }) as unknown;
              if (!Array.isArray(bullets) || bullets.length === 0) return null;
              return (
                <ul className="list-disc pl-5 space-y-1 text-slate-400">
                  {bullets.map((_b, i) => (
                    <li key={i}>
                      <Trans
                        i18nKey={`gettingStarted.steps.${step.id}.bullets.${i}`}
                        components={{
                          strong: <strong className="text-slate-200" />,
                          code: <code className="px-1 py-0.5 rounded bg-slate-800 text-cyan-300 text-[12px] font-mono" />,
                          em: <em className="text-amber-300" />,
                        }}
                      />
                    </li>
                  ))}
                </ul>
              );
            })()}
            {step.actions && step.actions.length > 0 && (
              <div className="flex flex-wrap gap-2 pt-1">
                {step.actions.map((a, i) => (
                  <button
                    key={i}
                    type="button"
                    onClick={() => onNavigate(a.tab)}
                    className="px-3 py-1.5 rounded text-xs font-medium border bg-cyan-500/15 text-cyan-200 border-cyan-500/50 hover:bg-cyan-500/25 transition-colors flex items-center gap-1.5"
                  >
                    {a.label}
                    <ChevronRight size={12} />
                  </button>
                ))}
              </div>
            )}
          </div>
        </details>
      ))}

      {/* Footer-Hinweis auf Vollarchitektur */}
      <div className="rounded-lg border border-slate-700/50 bg-slate-900/40 p-4 text-[12px] text-slate-400">
        <div className="flex items-start gap-2">
          <Server size={14} className="text-slate-500 mt-0.5 shrink-0" />
          <div>
            <Trans
              i18nKey="gettingStarted.footer"
              components={{
                a: <a
                  className="text-cyan-300 underline hover:text-cyan-200 font-mono"
                  href="https://github.com/JxxKal/ids/blob/main/CLAUDE.md"
                  target="_blank"
                  rel="noopener noreferrer"
                />,
                lab: <a
                  className="text-cyan-300 underline hover:text-cyan-200 font-mono"
                  href="https://github.com/JxxKal/ids/blob/main/docs/cyjankali/lab.html"
                  target="_blank"
                  rel="noopener noreferrer"
                />,
              }}
            />
          </div>
        </div>
      </div>
    </div>
  );
}
