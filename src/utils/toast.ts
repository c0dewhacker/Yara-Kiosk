export function showToast(msg: string, type: 'error' | 'info' | 'success' = 'error'): void {
  const existing = document.getElementById('toast-container');
  const container = existing ?? (() => {
    const el = document.createElement('div');
    el.id = 'toast-container';
    el.className = 'fixed bottom-6 right-6 z-50 flex flex-col gap-3';
    document.body.appendChild(el);
    return el;
  })();

  const colourClass = type === 'error'
    ? 'bg-danger/20 border border-danger text-white'
    : type === 'success'
    ? 'bg-success/20 border border-success text-white'
    : 'bg-warning/20 border border-warning text-white';

  const toast = document.createElement('div');
  toast.className = `${colourClass} px-4 py-3 rounded-xl text-sm font-sans shadow-lg opacity-0 transition-opacity duration-300 backdrop-blur`;
  toast.textContent = msg;
  container.appendChild(toast);

  requestAnimationFrame(() => {
    toast.classList.remove('opacity-0');
    toast.classList.add('opacity-100');
  });

  setTimeout(() => {
    toast.classList.remove('opacity-100');
    toast.classList.add('opacity-0');
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}
