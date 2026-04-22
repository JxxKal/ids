const KEY = 'cyjan:demo';

export function isDemoMode(): boolean {
  return typeof window !== 'undefined' && localStorage.getItem(KEY) === '1';
}

export function enableDemoMode(): void {
  localStorage.setItem(KEY, '1');
}

export function disableDemoMode(): void {
  localStorage.removeItem(KEY);
}
