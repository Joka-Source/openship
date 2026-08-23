import { describe, expect, it } from 'bun:test';
import {
  assertJtyidIdentityContinuity,
  jtyidSessionExpiry,
  resolveJtyidSessionMatch,
  resolvePasswordSessionMatch,
} from '../src/lib/session';

const identity = {
  subject: 'provider-subject',
  jtyid: `person_${'a'.repeat(24)}`,
  email: 'person@jjty.in',
  name: null,
  authenticatedAt: new Date('2026-08-01T00:00:00.000Z'),
};

describe('JTYID session identity continuity', () => {
  it('reuses a session only when immutable subject and JTYID both match', () => {
    const match = resolveJtyidSessionMatch(
      [
        {
          id: 'session-id',
          authMode: 'jtyid',
          providerSubject: identity.subject,
          jtyid: identity.jtyid,
          email: identity.email,
        },
      ],
      identity,
    );

    expect(match?.id).toBe('session-id');
  });

  it('rejects a subject change for an existing JTYID', () => {
    expect(() =>
      resolveJtyidSessionMatch(
        [
          {
            id: 'session-id',
            authMode: 'jtyid',
            providerSubject: 'different-subject',
            jtyid: identity.jtyid,
            email: identity.email,
          },
        ],
        identity,
      ),
    ).toThrow('OIDC session identity rejected');
  });

  it('rejects a JTYID change for an existing provider subject', () => {
    expect(() =>
      resolveJtyidSessionMatch(
        [
          {
            id: 'session-id',
            authMode: 'jtyid',
            providerSubject: identity.subject,
            jtyid: `person_${'b'.repeat(24)}`,
            email: identity.email,
          },
        ],
        identity,
      ),
    ).toThrow('OIDC session identity rejected');
  });

  it('does not auto-link a password or different-subject session by email', () => {
    const rows = [
      {
        id: 'password-id',
        authMode: 'password',
        providerSubject: null,
        jtyid: null,
        email: identity.email,
      },
      {
        id: 'other-oauth-id',
        authMode: 'jtyid',
        providerSubject: 'different-subject',
        jtyid: `person_${'b'.repeat(24)}`,
        email: identity.email,
      },
    ];

    expect(resolveJtyidSessionMatch(rows, identity)).toBeNull();
  });

  it('rejects provider-subject or JTYID changes found outside the current browser session list', () => {
    expect(() =>
      assertJtyidIdentityContinuity(
        [
          {
            id: 'other-browser-id',
            authMode: 'jtyid',
            providerSubject: 'different-subject',
            jtyid: identity.jtyid,
            email: identity.email,
          },
        ],
        identity,
      ),
    ).toThrow('OIDC session identity rejected');
    expect(() =>
      assertJtyidIdentityContinuity(
        [
          {
            id: 'other-browser-id',
            authMode: 'jtyid',
            providerSubject: identity.subject,
            jtyid: `person_${'b'.repeat(24)}`,
            email: identity.email,
          },
        ],
        identity,
      ),
    ).toThrow('OIDC session identity rejected');
  });
});

describe('JTYID absolute session lifetime', () => {
  it('never extends beyond 30 days from the original signed auth_time', () => {
    const authenticatedAt = new Date('2026-08-01T00:00:00.000Z');
    const now = new Date('2026-08-20T00:00:00.000Z');

    expect(jtyidSessionExpiry(authenticatedAt, now, 60 * 24 * 60 * 60)).toEqual(
      new Date('2026-08-31T00:00:00.000Z'),
    );
  });
});

describe('password fallback identity', () => {
  it('reuses only password sessions and never overwrites an OAuth session with the same email', () => {
    const rows = [
      {
        id: 'oauth-id',
        authMode: 'jtyid',
        providerSubject: identity.subject,
        jtyid: identity.jtyid,
        email: identity.email,
      },
      {
        id: 'password-id',
        authMode: 'password',
        providerSubject: null,
        jtyid: null,
        email: identity.email,
      },
    ];

    expect(resolvePasswordSessionMatch(rows, identity.email)?.id).toBe('password-id');
    expect(resolvePasswordSessionMatch(rows.slice(0, 1), identity.email)).toBeNull();
  });
});
