// Demo-Mode (ids-Muster): ?demo=1 aktiviert, localStorage hält den Zustand.
export function isDemoMode(): boolean {
  if (new URLSearchParams(window.location.search).has('demo')) {
    localStorage.setItem('fwpt-demo', '1');
    return true;
  }
  return localStorage.getItem('fwpt-demo') === '1';
}

export function leaveDemoMode(): void {
  localStorage.removeItem('fwpt-demo');
}
