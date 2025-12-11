const formatter = new Intl.DateTimeFormat('en-US', {
  year: 'numeric',
  month: 'short',
  day: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit'
});

export const formatDateTime = (isoString) => {
  if (!isoString) return 'Unknown';
  try {
    return formatter.format(new Date(isoString));
  } catch (error) {
    return isoString;
  }
};

export const formatRelative = (isoString) => {
  if (!isoString) return 'Unknown';
  const now = Date.now();
  const diff = now - new Date(isoString).getTime();
  const minutes = Math.round(diff / 60000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} hr ago`;
  const days = Math.round(hours / 24);
  if (days < 30) return `${days} day${days === 1 ? '' : 's'} ago`;
  const months = Math.round(days / 30);
  return `${months} mo ago`;
};
