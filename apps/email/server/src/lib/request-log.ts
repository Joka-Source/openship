export function safeRequestLogPath(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return url.split('?')[0] || '/';
  }
}
