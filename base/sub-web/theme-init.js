// Apply the default system theme before the application and stylesheet paint.
(() => {
  let mode = 'auto';
  try { mode = localStorage.getItem('subweb-theme-mode') || 'auto'; } catch { /* unavailable storage */ }
  const dark = mode === 'dark' || (mode !== 'light' && window.matchMedia('(prefers-color-scheme: dark)').matches);
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
})();
