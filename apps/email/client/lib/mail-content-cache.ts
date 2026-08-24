export const MAIL_CONTENT_CACHE_VERSION = 2;

export function mailContentQueryKey(
  id: string | undefined,
  shouldLoadImages: boolean,
  theme: string | undefined,
) {
  return ['email-content', MAIL_CONTENT_CACHE_VERSION, id, shouldLoadImages, theme] as const;
}

export function shouldPersistQueryKey(queryKey: readonly unknown[]): boolean {
  const head = queryKey[0];

  // Processed HTML is security- and rendering-policy output, not durable mail
  // state. Persisting it kept the pre-fix, style-stripped body alive for a day
  // after a deployment. Reject both the versioned key and the legacy shape.
  if (head === 'email-content') return false;

  const path = Array.isArray(head) ? head : [];
  const root = typeof path[0] === 'string' ? path[0] : '';
  return root !== 'mail' && root !== 'drafts';
}
