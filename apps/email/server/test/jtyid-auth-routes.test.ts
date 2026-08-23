import { describe, expect, it } from 'bun:test';
import { randomBytes } from 'node:crypto';
import { createJtyidAuthRoutes, JTYID_STATE_COOKIE } from '../src/routes/jtyid-auth';
import { OidcStateStore, type OidcConfig } from '../src/lib/jtyid-oidc';

const config: OidcConfig = {
  issuer: 'https://id.jjty.in/application/o/openship-mail/',
  clientId: 'openship-mail',
  clientSecret: randomBytes(32).toString('hex'),
  redirectUri: 'https://mail.jjty.in/auth/jtyid/callback',
  authorizationEndpoint: 'https://id.jjty.in/application/o/authorize/',
  tokenEndpoint: 'https://id.jjty.in/application/o/token/',
  userinfoEndpoint: 'https://id.jjty.in/application/o/userinfo/',
  jwksUri: 'https://id.jjty.in/application/o/openship-mail/jwks/',
  revocationEndpoint: 'https://id.jjty.in/application/o/revoke/',
};

function fixture() {
  const stateStore = new OidcStateStore();
  const accessToken = randomBytes(32).toString('base64url');
  const refreshToken = randomBytes(32).toString('base64url');
  let probed = false;
  let completed = 0;
  const routes = createJtyidAuthRoutes({
    config,
    stateStore,
    exchangeCode: async () => ({
      accessToken,
      refreshToken,
      expiresIn: 600,
      idToken: randomBytes(32).toString('base64url'),
    }),
    verifyToken: async (_token, nonce) => ({
      sub: 'provider-subject',
      nonce,
      auth_time: Math.floor(Date.now() / 1_000),
      jtyid: `person_${'a'.repeat(24)}`,
    }),
    getUserinfo: async () => ({
      sub: 'provider-subject',
      jtyid: `person_${'a'.repeat(24)}`,
      email: 'person@jjty.in',
      email_verified: true,
    }),
    probeMailbox: async () => {
      probed = true;
      return true;
    },
    completeLogin: async () => {
      completed += 1;
    },
  });
  return { routes, stateStore, wasProbed: () => probed, completionCount: () => completed };
}

describe('JTYID Hono routes', () => {
  it('emits the exact callback URI from the public authorization route', async () => {
    const { routes } = fixture();
    const response = await routes.request('https://mail.jjty.in/jtyid?returnTo=%2Fmail%2Finbox');
    const location = new URL(response.headers.get('location')!);

    expect(response.status).toBe(302);
    expect(location.searchParams.get('client_id')).toBe('openship-mail');
    expect(location.searchParams.get('redirect_uri')).toBe(
      'https://mail.jjty.in/auth/jtyid/callback',
    );
  });

  it('probes OAuth IMAP before completing the callback session', async () => {
    const { routes, stateStore, wasProbed, completionCount } = fixture();
    const transaction = stateStore.issue('/mail/inbox');
    const response = await routes.request(
      `https://mail.jjty.in/jtyid/callback?code=opaque-code&state=${encodeURIComponent(transaction.state)}`,
      { headers: { cookie: `${JTYID_STATE_COOKIE}=${transaction.browserBinding}` } },
    );

    expect(response.status).toBe(302);
    expect(response.headers.get('location')).toBe('/mail/inbox');
    expect(wasProbed()).toBe(true);
    expect(completionCount()).toBe(1);
  });

  it('fails generically and never mints a session when state is replayed', async () => {
    const { routes, stateStore, completionCount } = fixture();
    const transaction = stateStore.issue('/mail/inbox');
    const callback = `https://mail.jjty.in/jtyid/callback?code=opaque-code&state=${encodeURIComponent(transaction.state)}`;
    const headers = { cookie: `${JTYID_STATE_COOKIE}=${transaction.browserBinding}` };
    await routes.request(callback, { headers });
    const replay = await routes.request(callback, { headers });

    expect(replay.status).toBe(302);
    expect(replay.headers.get('location')).toBe('/login?error=jtyid');
    expect(completionCount()).toBe(1);
  });

  it('does not mint a session when the OAuth access token fails the IMAP probe', async () => {
    const base = fixture();
    let completed = false;
    const routes = createJtyidAuthRoutes({
      config,
      stateStore: base.stateStore,
      exchangeCode: async () => ({
        accessToken: randomBytes(32).toString('base64url'),
        refreshToken: randomBytes(32).toString('base64url'),
        expiresIn: 600,
        idToken: randomBytes(32).toString('base64url'),
      }),
      verifyToken: async (_token, nonce) => ({
        sub: 'provider-subject',
        nonce,
        auth_time: Math.floor(Date.now() / 1_000),
        jtyid: `person_${'a'.repeat(24)}`,
      }),
      getUserinfo: async () => ({
        sub: 'provider-subject',
        jtyid: `person_${'a'.repeat(24)}`,
        email: 'person@jjty.in',
        email_verified: true,
      }),
      probeMailbox: async () => false,
      completeLogin: async () => {
        completed = true;
      },
    });
    const transaction = base.stateStore.issue('/mail/inbox');
    const response = await routes.request(
      `https://mail.jjty.in/jtyid/callback?code=opaque-code&state=${encodeURIComponent(transaction.state)}`,
      { headers: { cookie: `${JTYID_STATE_COOKIE}=${transaction.browserBinding}` } },
    );

    expect(response.headers.get('location')).toBe('/login?error=jtyid');
    expect(completed).toBe(false);
  });
});
