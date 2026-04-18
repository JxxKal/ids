import { Component, type ReactNode } from 'react';

interface Props { children: ReactNode }
interface State { error: Error | null }

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  render() {
    if (this.state.error) {
      return (
        <div className="flex flex-col items-center justify-center h-full gap-4 text-sm">
          <p className="text-red-400 font-medium">Rendering-Fehler</p>
          <pre className="text-xs text-slate-500 max-w-lg whitespace-pre-wrap">
            {this.state.error.message}
          </pre>
          <button
            onClick={() => this.setState({ error: null })}
            className="btn-primary"
          >
            Neu laden
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
