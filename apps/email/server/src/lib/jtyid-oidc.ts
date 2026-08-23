import {
  createHash,
  createPublicKey,
  randomBytes,
  timingSafeEqual,
  verify as verifySignature,
  type JsonWebKey,
} from 'node:crypto';

export interface OidcConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  userinfoEndpoint: string;
  jwksUri: string;
  revocationEndpoint: string;
}

export interface OidcTransaction {
  state: string;
  nonce: string;
  verifier: string;
  challenge: string;
  browserBinding: string;
  returnTo: string;
  expiresAt: number;
}

type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

const OIDC_SCOPES = 'openid profile email jtyid offline_access';
const MAX_CLOCK_SKEW_SECONDS = 30;

function randomValue(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

function safeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

export class OidcStateStore {
  private readonly transactions = new Map<string, OidcTransaction>();

  constructor(
    private readonly options: { ttlMs: number; maxEntries?: number } = {
      ttlMs: 10 * 60_000,
      maxEntries: 2_048,
    },
  ) {}

  issue(returnTo = '/mail/inbox', now = Date.now()): OidcTransaction {
    for (const [state, transaction] of this.transactions) {
      if (transaction.expiresAt < now) this.transactions.delete(state);
    }
    const maxEntries = this.options.maxEntries ?? 2_048;
    while (this.transactions.size >= maxEntries) {
      const oldest = this.transactions.keys().next().value;
      if (typeof oldest !== 'string') break;
      this.transactions.delete(oldest);
    }
    const verifier = randomValue();
    const transaction: OidcTransaction = {
      state: randomValue(),
      nonce: randomValue(),
      verifier,
      challenge: createHash('sha256').update(verifier).digest('base64url'),
      browserBinding: randomValue(),
      returnTo: sanitizeReturnTo(returnTo),
      expiresAt: now + this.options.ttlMs,
    };
    this.transactions.set(transaction.state, transaction);
    return transaction;
  }

  consume(state: string, browserBinding: string, now = Date.now()): OidcTransaction | null {
    const transaction = this.transactions.get(state);
    if (!transaction) return null;
    if (transaction.expiresAt < now) {
      this.transactions.delete(state);
      return null;
    }
    if (
      !safeEqual(transaction.state, state) ||
      !safeEqual(transaction.browserBinding, browserBinding)
    )
      return null;
    this.transactions.delete(state);
    return transaction;
  }
}

export function sanitizeReturnTo(value: string | null | undefined): string {
  if (!value?.startsWith('/') || value.startsWith('//')) return '/mail/inbox';
  if (/[\\\x00-\x1f]/.test(value) || /%2f%2f|%5c/i.test(value)) return '/mail/inbox';
  try {
    const url = new URL(value, 'https://mail.invalid');
    return url.origin === 'https://mail.invalid'
      ? `${url.pathname}${url.search}${url.hash}`
      : '/mail/inbox';
  } catch {
    return '/mail/inbox';
  }
}

export function buildAuthorizationUrl(
  config: OidcConfig,
  values: { state: string; nonce: string; challenge: string },
): string {
  const url = new URL(config.authorizationEndpoint);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', config.clientId);
  url.searchParams.set('redirect_uri', config.redirectUri);
  url.searchParams.set('scope', OIDC_SCOPES);
  url.searchParams.set('state', values.state);
  url.searchParams.set('nonce', values.nonce);
  url.searchParams.set('code_challenge', values.challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  url.searchParams.set('max_age', String(30 * 24 * 60 * 60));
  return url.toString();
}

interface TokenEndpointResponse {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  idToken: string;
}

function confidentialHeaders(config: OidcConfig): Record<string, string> {
  return {
    accept: 'application/json',
    'content-type': 'application/x-www-form-urlencoded',
    authorization: `Basic ${Buffer.from(`${config.clientId}:${config.clientSecret}`).toString('base64')}`,
  };
}

async function readTokenResponse(response: Response): Promise<TokenEndpointResponse> {
  const body = (await response.json().catch(() => null)) as Record<string, unknown> | null;
  const accessToken = body?.access_token;
  const refreshToken = body?.refresh_token;
  const expiresIn = body?.expires_in;
  const idToken = body?.id_token ?? '';
  if (
    !response.ok ||
    typeof accessToken !== 'string' ||
    !accessToken ||
    typeof refreshToken !== 'string' ||
    !refreshToken ||
    typeof expiresIn !== 'number' ||
    !Number.isFinite(expiresIn) ||
    expiresIn <= 0 ||
    typeof idToken !== 'string'
  ) {
    throw new Error('OIDC token request failed');
  }
  return { accessToken, refreshToken, expiresIn, idToken };
}

export async function exchangeAuthorizationCode(
  config: OidcConfig,
  code: string,
  verifier: string,
  fetchImpl: FetchLike = fetch,
): Promise<TokenEndpointResponse> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: config.redirectUri,
    code_verifier: verifier,
  });
  const response = await fetchImpl(config.tokenEndpoint, {
    method: 'POST',
    headers: confidentialHeaders(config),
    body,
  });
  const tokens = await readTokenResponse(response);
  if (!tokens.idToken) throw new Error('OIDC token request failed');
  return tokens;
}

export async function refreshOidcTokens(
  config: OidcConfig,
  refreshToken: string,
  fetchImpl: FetchLike = fetch,
): Promise<Omit<TokenEndpointResponse, 'idToken'>> {
  const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken });
  const response = await fetchImpl(config.tokenEndpoint, {
    method: 'POST',
    headers: confidentialHeaders(config),
    body,
  });
  const tokens = await readTokenResponse(response);
  if (safeEqual(tokens.refreshToken, refreshToken)) throw new Error('OIDC token request failed');
  return {
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
    expiresIn: tokens.expiresIn,
  };
}

export async function revokeRefreshToken(
  config: OidcConfig,
  refreshToken: string,
  fetchImpl: FetchLike = fetch,
): Promise<void> {
  const response = await fetchImpl(config.revocationEndpoint, {
    method: 'POST',
    headers: confidentialHeaders(config),
    body: new URLSearchParams({ token: refreshToken, token_type_hint: 'refresh_token' }),
  });
  if (!response.ok) throw new Error('OIDC revocation failed');
}

export class RefreshCoordinator {
  private readonly pending = new Map<string, Promise<unknown>>();

  run<T>(key: string, refresh: () => Promise<T>): Promise<T> {
    const current = this.pending.get(key) as Promise<T> | undefined;
    if (current) return current;
    const next = refresh().finally(() => {
      if (this.pending.get(key) === next) this.pending.delete(key);
    });
    this.pending.set(key, next);
    return next;
  }
}

function decodeJsonPart(part: string): Record<string, unknown> {
  try {
    const decoded = JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
    if (!decoded || typeof decoded !== 'object' || Array.isArray(decoded)) throw new Error();
    return decoded as Record<string, unknown>;
  } catch {
    throw new Error('ID token rejected');
  }
}

export async function verifyIdToken(
  compact: string,
  config: OidcConfig,
  expectedNonce: string,
  fetchImpl: FetchLike = fetch,
  now = Math.floor(Date.now() / 1_000),
): Promise<Record<string, unknown>> {
  try {
    const parts = compact.split('.');
    if (parts.length !== 3) throw new Error();
    const [encodedHeader, encodedPayload, encodedSignature] = parts as [string, string, string];
    const header = decodeJsonPart(encodedHeader);
    const payload = decodeJsonPart(encodedPayload);
    if (header.alg !== 'RS256' || typeof header.kid !== 'string' || !header.kid) throw new Error();

    const jwksResponse = await fetchImpl(config.jwksUri, {
      headers: { accept: 'application/json' },
    });
    const jwks = (await jwksResponse.json().catch(() => null)) as { keys?: JsonWebKey[] } | null;
    if (!jwksResponse.ok || !Array.isArray(jwks?.keys)) throw new Error();
    const jwk = jwks.keys.find(
      (candidate) =>
        candidate.kid === header.kid &&
        candidate.kty === 'RSA' &&
        (candidate.alg === undefined || candidate.alg === 'RS256') &&
        (candidate.use === undefined || candidate.use === 'sig'),
    );
    if (!jwk) throw new Error();
    const validSignature = verifySignature(
      'RSA-SHA256',
      Buffer.from(`${encodedHeader}.${encodedPayload}`),
      createPublicKey({ key: jwk, format: 'jwk' }),
      Buffer.from(encodedSignature, 'base64url'),
    );
    if (!validSignature) throw new Error();

    const audience = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (payload.iss !== config.issuer || !audience.includes(config.clientId)) throw new Error();
    if (audience.length > 1 && payload.azp !== config.clientId) throw new Error();
    if (payload.azp !== undefined && payload.azp !== config.clientId) throw new Error();
    if (typeof payload.sub !== 'string' || !payload.sub) throw new Error();
    if (typeof payload.exp !== 'number' || payload.exp <= now - MAX_CLOCK_SKEW_SECONDS)
      throw new Error();
    if (typeof payload.iat !== 'number' || payload.iat > now + MAX_CLOCK_SKEW_SECONDS)
      throw new Error();
    if (
      payload.nbf !== undefined &&
      (typeof payload.nbf !== 'number' || payload.nbf > now + MAX_CLOCK_SKEW_SECONDS)
    )
      throw new Error();
    if (typeof payload.nonce !== 'string' || !safeEqual(payload.nonce, expectedNonce))
      throw new Error();
    return payload;
  } catch {
    throw new Error('ID token rejected');
  }
}

export async function fetchUserinfo(
  config: OidcConfig,
  accessToken: string,
  fetchImpl: FetchLike = fetch,
): Promise<Record<string, unknown>> {
  const response = await fetchImpl(config.userinfoEndpoint, {
    headers: { accept: 'application/json', authorization: `Bearer ${accessToken}` },
  });
  const body = await response.json().catch(() => null);
  if (!response.ok || !body || typeof body !== 'object' || Array.isArray(body)) {
    throw new Error('OIDC userinfo request failed');
  }
  return body as Record<string, unknown>;
}

export interface OidcIdentity {
  subject: string;
  jtyid: string;
  email: string;
  name: string | null;
  authenticatedAt: Date;
}

const CANONICAL_JTYID = /^person_[0-9a-f]{24}$/;
const LOWERCASE_JJTY_EMAIL = /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@jjty\.in$/;

export function validateOidcIdentity(
  claims: Record<string, unknown>,
  userinfo: Record<string, unknown>,
  now = Math.floor(Date.now() / 1_000),
): OidcIdentity {
  const subject = claims.sub;
  const userinfoSubject = userinfo.sub;
  const jtyid = claims.jtyid;
  const userinfoJtyid = userinfo.jtyid;
  const email = userinfo.email;
  const authTime = claims.auth_time;
  const name =
    typeof userinfo.name === 'string' && userinfo.name.trim()
      ? userinfo.name.trim().slice(0, 200)
      : null;
  if (
    typeof subject !== 'string' ||
    !subject ||
    userinfoSubject !== subject ||
    typeof jtyid !== 'string' ||
    !CANONICAL_JTYID.test(jtyid) ||
    (userinfoJtyid !== undefined && userinfoJtyid !== jtyid) ||
    typeof email !== 'string' ||
    email !== email.toLowerCase() ||
    !LOWERCASE_JJTY_EMAIL.test(email) ||
    userinfo.email_verified !== true ||
    typeof authTime !== 'number' ||
    !Number.isInteger(authTime) ||
    authTime > now + MAX_CLOCK_SKEW_SECONDS ||
    authTime < now - 30 * 24 * 60 * 60
  ) {
    throw new Error('OIDC identity rejected');
  }
  return { subject, jtyid, email, name, authenticatedAt: new Date(authTime * 1_000) };
}

export function validateRefreshedIdentity(
  expected: Pick<OidcIdentity, 'subject' | 'jtyid' | 'email'>,
  userinfo: Record<string, unknown>,
): void {
  if (
    userinfo.sub !== expected.subject ||
    userinfo.jtyid !== expected.jtyid ||
    userinfo.email !== expected.email ||
    userinfo.email_verified !== true
  ) {
    throw new Error('OIDC identity rejected');
  }
}
