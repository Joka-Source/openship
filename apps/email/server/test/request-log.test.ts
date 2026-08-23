import { describe, expect, it } from 'bun:test';
import { safeRequestLogPath } from '../src/lib/request-log';

describe('request logging', () => {
  it('never includes callback codes, state, or other query values', () => {
    expect(
      safeRequestLogPath('https://mail.jjty.in/auth/jtyid/callback?code=private&state=private'),
    ).toBe('/auth/jtyid/callback');
    expect(safeRequestLogPath('https://mail.jjty.in/mail/inbox?search=private')).toBe(
      '/mail/inbox',
    );
  });
});
