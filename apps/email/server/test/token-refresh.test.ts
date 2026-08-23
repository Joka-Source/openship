import { describe, expect, it } from 'bun:test';
import { randomBytes } from 'node:crypto';
import {
  RefreshCoordinator,
  refreshOidcTokens,
  revokeRefreshToken,
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

describe('OAuth token refresh', () => {
  it('uses the confidential refresh-token grant without exposing input in an error', async () => {
    let requestBody = '';
    let authorization = '';
    const result = await refreshOidcTokens(config, 'refresh-value', async (_url, init) => {
      requestBody = String(init?.body);
      authorization = new Headers(init?.headers).get('authorization') ?? '';
      return new Response(
        JSON.stringify({
          access_token: 'new-access',
          refresh_token: 'new-refresh',
          expires_in: 600,
        }),
      );
    });

    expect(new URLSearchParams(requestBody).get('grant_type')).toBe('refresh_token');
    expect(authorization.startsWith('Basic ')).toBe(true);
    expect(result).toEqual({
      accessToken: 'new-access',
      refreshToken: 'new-refresh',
      expiresIn: 600,
    });
  });

  it('serializes concurrent refreshes for one session', async () => {
    const coordinator = new RefreshCoordinator();
    let calls = 0;
    const refresh = () =>
      coordinator.run('session-id', async () => {
        calls += 1;
        await Promise.resolve();
        return 'access-value';
      });

    expect(await Promise.all([refresh(), refresh(), refresh()])).toEqual([
      'access-value',
      'access-value',
      'access-value',
    ]);
    expect(calls).toBe(1);
  });

  it('rejects an expired or replayed refresh grant with a generic error', async () => {
    const rejectedGrant = randomBytes(32).toString('base64url');
    const attempt = refreshOidcTokens(
      config,
      rejectedGrant,
      async () => new Response(JSON.stringify({ error: 'invalid_grant' }), { status: 400 }),
    );

    await expect(attempt).rejects.toThrow('OIDC token request failed');
  });

  it('rejects a refresh response that does not rotate the refresh grant', async () => {
    const currentGrant = randomBytes(32).toString('base64url');
    await expect(
      refreshOidcTokens(config, currentGrant, async () =>
        new Response(JSON.stringify({ access_token: 'new-access', expires_in: 600 })),
      ),
    ).rejects.toThrow('OIDC token request failed');
    await expect(
      refreshOidcTokens(config, currentGrant, async () =>
        new Response(
          JSON.stringify({
            access_token: 'new-access',
            refresh_token: currentGrant,
            expires_in: 600,
          }),
        ),
      ),
    ).rejects.toThrow('OIDC token request failed');
  });

  it('revokes the refresh grant through the confidential client endpoint', async () => {
    const grant = randomBytes(32).toString('base64url');
    let body = '';
    let authorization = '';
    await revokeRefreshToken(config, grant, async (_url, init) => {
      body = String(init?.body);
      authorization = new Headers(init?.headers).get('authorization') ?? '';
      return new Response(null, { status: 200 });
    });

    expect(new URLSearchParams(body).get('token_type_hint')).toBe('refresh_token');
    expect(authorization.startsWith('Basic ')).toBe(true);
  });
});
