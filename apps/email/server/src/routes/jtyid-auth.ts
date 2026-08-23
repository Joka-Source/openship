import { Hono, type Context } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import {
  OidcStateStore,
  buildAuthorizationUrl,
  exchangeAuthorizationCode,
  fetchUserinfo,
  validateOidcIdentity,
  verifyIdToken,
  type OidcConfig,
  type OidcIdentity,
} from '../lib/jtyid-oidc';

interface CallbackTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  idToken: string;
}

export const JTYID_STATE_COOKIE = 'zero_jtyid_state';

export interface JtyidAuthDependencies {
  config: OidcConfig;
  stateStore?: OidcStateStore;
  exchangeCode?: (code: string, verifier: string) => Promise<CallbackTokens>;
  verifyToken?: (idToken: string, nonce: string) => Promise<Record<string, unknown>>;
  getUserinfo?: (accessToken: string) => Promise<Record<string, unknown>>;
  probeMailbox: (identity: OidcIdentity, accessToken: string) => Promise<boolean>;
  completeLogin: (
    context: Context,
    identity: OidcIdentity,
    tokens: Omit<CallbackTokens, 'idToken'>,
  ) => Promise<void>;
}

export function createJtyidAuthRoutes(dependencies: JtyidAuthDependencies): Hono {
  const routes = new Hono();
  const stateStore = dependencies.stateStore ?? new OidcStateStore();
  const exchangeCode =
    dependencies.exchangeCode ??
    ((code, verifier) => exchangeAuthorizationCode(dependencies.config, code, verifier));
  const verifyToken =
    dependencies.verifyToken ??
    ((token, nonce) => verifyIdToken(token, dependencies.config, nonce));
  const getUserinfo =
    dependencies.getUserinfo ?? ((token) => fetchUserinfo(dependencies.config, token));

  routes.get('/jtyid', (context) => {
    const transaction = stateStore.issue(context.req.query('returnTo'));
    setCookie(context, JTYID_STATE_COOKIE, transaction.browserBinding, {
      httpOnly: true,
      secure: dependencies.config.redirectUri.startsWith('https://'),
      sameSite: 'Lax',
      path: '/auth/jtyid/callback',
      maxAge: 10 * 60,
    });
    const location = buildAuthorizationUrl(dependencies.config, transaction);
    context.header('Cache-Control', 'no-store');
    return context.redirect(location, 302);
  });

  routes.get('/jtyid/callback', async (context) => {
    const fail = () => {
      deleteCookie(context, JTYID_STATE_COOKIE, { path: '/auth/jtyid/callback' });
      context.header('Cache-Control', 'no-store');
      return context.redirect('/login?error=jtyid', 302);
    };

    try {
      if (context.req.query('error')) return fail();
      const code = context.req.query('code');
      const state = context.req.query('state');
      if (!code || !state) return fail();
      const browserBinding = getCookie(context, JTYID_STATE_COOKIE);
      if (!browserBinding) return fail();
      const transaction = stateStore.consume(state, browserBinding);
      if (!transaction) return fail();
      deleteCookie(context, JTYID_STATE_COOKIE, { path: '/auth/jtyid/callback' });

      const tokens = await exchangeCode(code, transaction.verifier);
      const claims = await verifyToken(tokens.idToken, transaction.nonce);
      const userinfo = await getUserinfo(tokens.accessToken);
      const identity = validateOidcIdentity(claims, userinfo);
      if (!(await dependencies.probeMailbox(identity, tokens.accessToken))) return fail();
      await dependencies.completeLogin(context, identity, {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        expiresIn: tokens.expiresIn,
      });
      context.header('Cache-Control', 'no-store');
      return context.redirect(transaction.returnTo, 302);
    } catch {
      return fail();
    }
  });

  return routes;
}
