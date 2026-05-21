export function formatBytes(n: number): string {
  if (n === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(n) / Math.log(1024));
  const val = (n / Math.pow(1024, i)).toFixed(1);
  return `${val} ${units[i]}`;
}
