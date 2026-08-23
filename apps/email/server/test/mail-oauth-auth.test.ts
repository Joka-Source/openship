import { describe, expect, it } from 'bun:test';
import { imapClientOptions } from '../src/lib/imap';
import { smtpTransportOptions } from '../src/lib/smtp';

describe('mail authentication shape', () => {
  it('keeps password IMAP and SMTP authentication unchanged', () => {
    const imap = imapClientOptions({
      host: 'mail.jjty.in',
      port: 993,
      user: 'person@jjty.in',
      pass: 'password-value',
    });
    const smtp = smtpTransportOptions({
      host: 'mail.jjty.in',
      port: 465,
      user: 'person@jjty.in',
      pass: 'password-value',
    });

    expect(imap.auth).toEqual({ user: 'person@jjty.in', pass: 'password-value' });
    expect(smtp.auth).toEqual({ user: 'person@jjty.in', pass: 'password-value' });
  });

  it('uses access-token authentication for OAuth IMAP and SMTP', () => {
    const imap = imapClientOptions({
      host: 'mail.jjty.in',
      port: 993,
      user: 'person@jjty.in',
      accessToken: 'access-value',
    });
    const smtp = smtpTransportOptions({
      host: 'mail.jjty.in',
      port: 465,
      user: 'person@jjty.in',
      accessToken: 'access-value',
    });

    expect(imap.auth).toEqual({ user: 'person@jjty.in', accessToken: 'access-value' });
    expect(smtp.auth).toEqual({
      type: 'OAuth2',
      user: 'person@jjty.in',
      accessToken: 'access-value',
    });
  });
});
