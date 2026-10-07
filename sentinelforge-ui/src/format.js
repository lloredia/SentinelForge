export const severityColors = {
  critical: { bg: '#ff0040', text: '#fff', glow: '0 0 20px rgba(255,0,64,0.6)' },
  high: { bg: '#ff6b00', text: '#fff', glow: '0 0 20px rgba(255,107,0,0.5)' },
  medium: { bg: '#ffd000', text: '#000', glow: '0 0 20px rgba(255,208,0,0.4)' },
  low: { bg: '#00d4aa', text: '#000', glow: '0 0 20px rgba(0,212,170,0.4)' },
  unknown: { bg: '#404040', text: '#888', glow: 'none' },
};

export const iocIcons = {
  ip: '◉',
  domain: '◈',
  url: '⛓',
  hash: '#',
  email: '@',
  cve: '⚠',
};

export function formatDate(dateStr) {
  if (!dateStr) return '—';
  const date = new Date(dateStr);
  return date.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function severityStyle(severity) {
  return severityColors[severity] || severityColors.unknown;
}
