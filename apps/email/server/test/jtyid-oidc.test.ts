import { describe, expect, it } from 'bun:test';
import { generateKeyPairSync, sign } from 'node:crypto';
import {
  OidcStateStore,
  buildAuthorizationUrl,
  validateOidcIdentity,
  validateRefreshedIdentity,
  verifyIdToken,
  type OidcConfig,
} from '../src/lib/jtyid-oidc';

const config: OidcConfig = {
  issuer: 'https://id.jjty.in/application/o/openship-mail/',
  clientId: 'openship-mail',
  clientSecret: 'not-a-real-secret',
  redirectUri: 'https://mail.jjty.in/auth/jtyid/callback',
  authorizationEndpoint: 'https://id.jjty.in/application/o/authorize/',
  tokenEndpoint: 'https://id.jjty.in/application/o/token/',
  userinfoEndpoint: 'https://id.jjty.in/application/o/userinfo/',
  jwksUri: 'https://id.jjty.in/application/o/openship-mail/jwks/',
  revocationEndpoint: 'https://id.jjty.in/application/o/revoke/',
};

describe('JTYID authorization request', () => {
  it('uses the exact public callback, offline access, and PKCE S256', () => {
    const url = new URL(
      buildAuthorizationUrl(config, {
        state: 'state-value',
        nonce: 'nonce-value',
        challenge: 'challenge-value',
      }),
    );

    expect(url.origin + url.pathname).toBe('https://id.jjty.in/application/o/authorize/');
    expect(url.searchParams.get('client_id')).toBe('openship-mail');
    expect(url.searchParams.get('redirect_uri')).toBe('https://mail.jjty.in/auth/jtyid/callback');
    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('scope')).toBe('openid profile email jtyid offline_access');
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('max_age')).toBe(String(30 * 24 * 60 * 60));
  });
});

describe('OIDC state', () => {
  it('is accepted once and rejected on replay', () => {
    const store = new OidcStateStore({ ttlMs: 60_000 });
    const transaction = store.issue('/mail/inbox', 1_000);

    expect(store.consume(transaction.state, transaction.browserBinding, 2_000)?.returnTo).toBe(
      '/mail/inbox',
    );
    expect(store.consume(transaction.state, transaction.browserBinding, 2_001)).toBeNull();
  });

  it('rejects expired state', () => {
    const store = new OidcStateStore({ ttlMs: 1_000 });
    const transaction = store.issue('/mail/inbox', 1_000);

    expect(store.consume(transaction.state, transaction.browserBinding, 2_001)).toBeNull();
  });

  it('rejects state presented without the initiating browser binding', () => {
    const store = new OidcStateStore({ ttlMs: 60_000 });
    const transaction = store.issue('/mail/inbox', 1_000);

    expect(store.consume(transaction.state, 'different-browser', 2_000)).toBeNull();
  });
});

describe('JTYID identity boundary', () => {
  const validClaims = {
    sub: 'provider-subject',
    jtyid: `person_${'a'.repeat(24)}`,
    nonce: 'nonce-value',
    auth_time: 1_000,
  };
  const validUserinfo = {
    sub: 'provider-subject',
    jtyid: `person_${'a'.repeat(24)}`,
    email: 'person@jjty.in',
    email_verified: true,
  };

  it('accepts only a canonical JTYID and verified lowercase jjty.in email', () => {
    expect(validateOidcIdentity(validClaims, validUserinfo, 1_100)).toEqual({
      subject: 'provider-subject',
      jtyid: `person_${'a'.repeat(24)}`,
      email: 'person@jjty.in',
      name: null,
      authenticatedAt: new Date(1_000_000),
    });
  });

  it.each([
    ['subject mismatch', validClaims, { ...validUserinfo, sub: 'other-subject' }],
    ['noncanonical JTYID', { ...validClaims, jtyid: 'person_invalid' }, validUserinfo],
    ['JTYID mismatch', validClaims, { ...validUserinfo, jtyid: `person_${'b'.repeat(24)}` }],
    ['unverified email', validClaims, { ...validUserinfo, email_verified: false }],
    ['uppercase email', validClaims, { ...validUserinfo, email: 'Person@jjty.in' }],
    ['foreign email', validClaims, { ...validUserinfo, email: 'person@example.com' }],
  ])('rejects %s', (_name, claims, userinfo) => {
    expect(() => validateOidcIdentity(claims, userinfo, 1_100)).toThrow('OIDC identity rejected');
  });

  it('rejects missing, future, or already-older-than-30-day auth_time', () => {
    expect(() =>
      validateOidcIdentity({ ...validClaims, auth_time: undefined }, validUserinfo, 1_100),
    ).toThrow('OIDC identity rejected');
    expect(() =>
      validateOidcIdentity({ ...validClaims, auth_time: 1_200 }, validUserinfo, 1_100),
    ).toThrow('OIDC identity rejected');
    expect(() =>
      validateOidcIdentity(
        { ...validClaims, auth_time: 1_100 - 30 * 24 * 60 * 60 - 1 },
        validUserinfo,
        1_100,
      ),
    ).toThrow('OIDC identity rejected');
  });

  it('rejects subject or JTYID rotation reported during token refresh', () => {
    expect(() =>
      validateRefreshedIdentity(
        { subject: 'provider-subject', jtyid: `person_${'a'.repeat(24)}`, email: 'person@jjty.in' },
        { ...validUserinfo, sub: 'different-subject' },
      ),
    ).toThrow('OIDC identity rejected');
    expect(() =>
      validateRefreshedIdentity(
        { subject: 'provider-subject', jtyid: `person_${'a'.repeat(24)}`, email: 'person@jjty.in' },
        { ...validUserinfo, jtyid: `person_${'b'.repeat(24)}` },
      ),
    ).toThrow('OIDC identity rejected');
  });
});

describe('ID-token verification', () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const publicJwk = publicKey.export({ format: 'jwk' });
  const fetchJwks = async () =>
    new Response(
      JSON.stringify({ keys: [{ ...publicJwk, kid: 'test-key', alg: 'RS256', use: 'sig' }] }),
    );

  function signedToken(overrides: Record<string, unknown> = {}) {
    const now = Math.floor(Date.now() / 1_000);
    const header = Buffer.from(
      JSON.stringify({ alg: 'RS256', kid: 'test-key', typ: 'JWT' }),
    ).toString('base64url');
    const payload = Buffer.from(
      JSON.stringify({
        iss: config.issuer,
        aud: config.clientId,
        sub: 'provider-subject',
        nonce: 'nonce-value',
        iat: now,
        auth_time: now,
        exp: now + 300,
        jtyid: `person_${'a'.repeat(24)}`,
        ...overrides,
      }),
    ).toString('base64url');
    const signature = sign('RSA-SHA256', Buffer.from(`${header}.${payload}`), privateKey).toString(
      'base64url',
    );
    return `${header}.${payload}.${signature}`;
  }

  it('verifies JWKS signature, issuer, audience, nonce, and expiry', async () => {
    const compact = signedToken();

    const claims = await verifyIdToken(compact, config, 'nonce-value', fetchJwks);
    expect(claims.sub).toBe('provider-subject');
  });

  it.each([
    ['issuer', { iss: 'https://issuer.invalid/' }],
    ['audience', { aud: 'different-client' }],
    ['nonce', { nonce: 'different-nonce' }],
    ['expiry', { exp: 1 }],
    ['not-before type', { nbf: 'not-a-numeric-date' }],
  ])('rejects a signed token with the wrong %s', async (_name, overrides) => {
    await expect(
      verifyIdToken(signedToken(overrides), config, 'nonce-value', fetchJwks),
    ).rejects.toThrow('ID token rejected');
  });

  it('rejects a token whose signed payload was modified', async () => {
    const compact = signedToken();
    const [header, payload, signature] = compact.split('.');
    const claims = JSON.parse(Buffer.from(payload!, 'base64url').toString('utf8'));
    claims.sub = 'modified-subject';
    const tamperedPayload = Buffer.from(JSON.stringify(claims)).toString('base64url');

    await expect(
      verifyIdToken(`${header}.${tamperedPayload}.${signature}`, config, 'nonce-value', fetchJwks),
    ).rejects.toThrow('ID token rejected');
  });
});
