import { describe, expect, it } from 'bun:test';

import { mailContentQueryKey, shouldPersistQueryKey } from './mail-content-cache';

describe('mail content cache policy', () => {
  it('versions processed message HTML so stale sanitizer output is not restored', () => {
    expect(mailContentQueryKey('message-1', false, 'light')).toEqual([
      'email-content',
      2,
      'message-1',
      false,
      'light',
    ]);
  });

  it('never persists processed message HTML', () => {
    expect(shouldPersistQueryKey(mailContentQueryKey('message-1', false, 'light'))).toBe(false);
    expect(shouldPersistQueryKey(['email-content', 'legacy-message-1'])).toBe(false);
  });

  it('continues excluding tRPC mail and draft queries while retaining settings', () => {
    expect(shouldPersistQueryKey([['mail', 'get'], { input: { id: 'message-1' } }])).toBe(false);
    expect(shouldPersistQueryKey([['drafts', 'list']])).toBe(false);
    expect(shouldPersistQueryKey([['settings', 'get']])).toBe(true);
  });
});
