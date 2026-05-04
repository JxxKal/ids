import ReactDOM from 'react-dom/client';
import App from './App';
import { HelpModeProvider } from './hooks/useHelpMode';
import './i18n';
import './i18n/extras';
import './index.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <HelpModeProvider>
    <App />
  </HelpModeProvider>,
);
