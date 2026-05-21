const MAP: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#039;',
};

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, c => MAP[c]!);
}
