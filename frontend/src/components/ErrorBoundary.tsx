import { Component, type ReactNode } from 'react';
import { withTranslation, type WithTranslation } from 'react-i18next';

interface Props extends WithTranslation { children: ReactNode }
interface State { error: Error | null }

class ErrorBoundaryInner extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  render() {
    const { t } = this.props;
    if (this.state.error) {
      return (
        <div className="flex flex-col items-center justify-center h-full gap-4 text-sm">
          <p className="text-red-400 font-medium">{t('errorBoundary.title')}</p>
          <pre className="text-xs text-slate-500 max-w-lg whitespace-pre-wrap">
            {this.state.error.message}
          </pre>
          <button
            onClick={() => this.setState({ error: null })}
            className="btn-primary"
          >
            {t('errorBoundary.reload')}
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

export const ErrorBoundary = withTranslation()(ErrorBoundaryInner);
