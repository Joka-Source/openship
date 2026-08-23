import { describe, expect, it } from 'bun:test';
import { revokeAndDeleteSession } from '../src/lib/session';

describe('OAuth logout', () => {
  it('attempts refresh-grant revocation before deleting the local session', async () => {
    const events: string[] = [];
    const revoked = await revokeAndDeleteSession(
      'session-id',
      async () => {
        events.push('revoke');
      },
      async () => {
        events.push('delete');
      },
    );

    expect(revoked).toBe(true);
    expect(events).toEqual(['revoke', 'delete']);
  });

  it('still deletes local state when the provider rejects an expired or replayed grant', async () => {
    const events: string[] = [];
    const revoked = await revokeAndDeleteSession(
      'session-id',
      async () => {
        events.push('revoke');
        throw new Error('provider rejected grant');
      },
      async () => {
        events.push('delete');
      },
    );

    expect(revoked).toBe(false);
    expect(events).toEqual(['revoke', 'delete']);
  });
});
