/**
 * Session lookup, create, and delete helpers.
 *
 * A session in Zero is the *identity* - the mailbox itself. There is
 * no separate user table. A row in `session` represents one active
 * sign-in: it holds the encrypted IMAP password and the IMAP/SMTP
 * coordinates so we can open connections per request without asking
 * the user to re-authenticate.
 *
 * `getSession()` is what middleware calls; it returns the row plus a
 * decrypted password ready for `withImap` / `sendMail`.
 */

import { eq } from 'drizzle-orm';
import { nanoid } from 'nanoid';
import { db, schema } from '../db';
import { encryptSecret, decryptSecret } from './crypto';
import { env } from '../env';
import {
  RefreshCoordinator,
  fetchUserinfo,
  refreshOidcTokens,
  revokeRefreshToken,
  validateRefreshedIdentity,
  type OidcConfig,
  type OidcIdentity,
} from './jtyid-oidc';

export type SessionAuthMode = 'password' | 'jtyid';

export interface SessionContext {
  sessionId: string;
  email: string;
  name: string | null;
  authMode: SessionAuthMode;
  password: string | null;
  accessToken: string | null;
  jtyid: string | null;
  providerSubject: string | null;
  imapHost: string;
  imapPort: number;
  smtpHost: string;
  smtpPort: number;
  expiresAt: Date;
}

export async function createSession(opts: {
  email: string;
  name: string | null;
  password: string;
  imapHost: string;
  imapPort: number;
  smtpHost: string;
  smtpPort: number;
}): Promise<{ id: string; expiresAt: Date }> {
  const id = nanoid(40);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + env.SESSION_TTL_SECONDS * 1000);
  await db.insert(schema.session).values({
    id,
    email: opts.email.toLowerCase(),
    name: opts.name,
    encryptedPassword: encryptSecret(opts.password),
    authMode: 'password',
    imapHost: opts.imapHost,
    imapPort: opts.imapPort,
    smtpHost: opts.smtpHost,
    smtpPort: opts.smtpPort,
    createdAt: now,
    expiresAt,
  });
  return { id, expiresAt };
}

export interface JtyidSessionRowIdentity {
  id: string;
  authMode: string;
  providerSubject: string | null;
  jtyid: string | null;
  email: string;
}

export function resolveJtyidSessionMatch<T extends JtyidSessionRowIdentity>(
  rows: readonly T[],
  identity: OidcIdentity,
): T | null {
  const bySubject = rows.find(
    (row) => row.authMode === 'jtyid' && row.providerSubject === identity.subject,
  );
  const byJtyid = rows.find((row) => row.authMode === 'jtyid' && row.jtyid === identity.jtyid);
  if (
    (bySubject && bySubject.jtyid !== identity.jtyid) ||
    (byJtyid && byJtyid.providerSubject !== identity.subject)
  ) {
    throw new Error('OIDC session identity rejected');
  }
  if (bySubject && byJtyid && bySubject.id !== byJtyid.id) {
    throw new Error('OIDC session identity rejected');
  }
  return bySubject ?? byJtyid ?? null;
}

export function assertJtyidIdentityContinuity<T extends JtyidSessionRowIdentity>(
  rows: readonly T[],
  identity: OidcIdentity,
): void {
  resolveJtyidSessionMatch(rows, identity);
}

export function resolvePasswordSessionMatch<T extends JtyidSessionRowIdentity>(
  rows: readonly T[],
  email: string,
): T | null {
  return (
    rows.find((row) => row.authMode === 'password' && row.email === email.toLowerCase()) ?? null
  );
}

export async function createJtyidSession(opts: {
  identity: OidcIdentity;
  accessToken: string;
  refreshToken: string;
  accessTokenExpiresAt: Date;
  imapHost: string;
  imapPort: number;
  smtpHost: string;
  smtpPort: number;
}): Promise<{ id: string; expiresAt: Date }> {
  const id = nanoid(40);
  const now = new Date();
  const expiresAt = jtyidSessionExpiry(opts.identity.authenticatedAt, now, env.SESSION_TTL_SECONDS);
  await db.insert(schema.session).values({
    id,
    email: opts.identity.email,
    name: opts.identity.name,
    encryptedPassword: encryptSecret(''),
    authMode: 'jtyid',
    jtyid: opts.identity.jtyid,
    providerSubject: opts.identity.subject,
    authenticatedAt: opts.identity.authenticatedAt,
    encryptedAccessToken: encryptSecret(opts.accessToken),
    encryptedRefreshToken: encryptSecret(opts.refreshToken),
    accessTokenExpiresAt: opts.accessTokenExpiresAt,
    imapHost: opts.imapHost,
    imapPort: opts.imapPort,
    smtpHost: opts.smtpHost,
    smtpPort: opts.smtpPort,
    createdAt: now,
    expiresAt,
  });
  return { id, expiresAt };
}

export function jtyidSessionExpiry(
  authenticatedAt: Date,
  now: Date,
  configuredTtlSeconds: number,
): Date {
  const configuredExpiry = new Date(now.getTime() + configuredTtlSeconds * 1_000);
  const absoluteExpiry = new Date(authenticatedAt.getTime() + 30 * 24 * 60 * 60 * 1_000);
  return configuredExpiry.getTime() < absoluteExpiry.getTime() ? configuredExpiry : absoluteExpiry;
}

export async function updateJtyidSession(
  id: string,
  opts: {
    identity: OidcIdentity;
    accessToken: string;
    refreshToken: string;
    accessTokenExpiresAt: Date;
  },
): Promise<void> {
  await db
    .update(schema.session)
    .set({
      email: opts.identity.email,
      name: opts.identity.name,
      encryptedAccessToken: encryptSecret(opts.accessToken),
      encryptedRefreshToken: encryptSecret(opts.refreshToken),
      accessTokenExpiresAt: opts.accessTokenExpiresAt,
    })
    .where(eq(schema.session.id, id));
}

const refreshCoordinator = new RefreshCoordinator();

function oidcConfig(): OidcConfig {
  if (!env.JTYID_OIDC_CLIENT_SECRET) throw new Error('OAuth session unavailable');
  return {
    issuer: env.JTYID_OIDC_ISSUER,
    clientId: env.JTYID_OIDC_CLIENT_ID,
    clientSecret: env.JTYID_OIDC_CLIENT_SECRET,
    redirectUri: `${env.PUBLIC_URL}/auth/jtyid/callback`,
    authorizationEndpoint: env.JTYID_OIDC_AUTHORIZATION_ENDPOINT,
    tokenEndpoint: env.JTYID_OIDC_TOKEN_ENDPOINT,
    userinfoEndpoint: env.JTYID_OIDC_USERINFO_ENDPOINT,
    jwksUri: env.JTYID_OIDC_JWKS_URI,
    revocationEndpoint: env.JTYID_OIDC_REVOCATION_ENDPOINT,
  };
}

async function currentAccessToken(row: typeof schema.session.$inferSelect): Promise<string | null> {
  if (
    row.authMode !== 'jtyid' ||
    !row.providerSubject ||
    !row.jtyid ||
    !row.authenticatedAt ||
    !row.encryptedAccessToken ||
    !row.encryptedRefreshToken ||
    !row.accessTokenExpiresAt
  )
    return null;
  if (row.accessTokenExpiresAt.getTime() > Date.now() + 60_000) {
    return decryptSecret(row.encryptedAccessToken as Buffer);
  }
  return refreshCoordinator.run(row.id, async () => {
    const latest = await db.query.session.findFirst({ where: eq(schema.session.id, row.id) });
    if (
      !latest ||
      latest.authMode !== 'jtyid' ||
      !latest.providerSubject ||
      !latest.jtyid ||
      !latest.authenticatedAt ||
      !latest.encryptedAccessToken ||
      !latest.encryptedRefreshToken ||
      !latest.accessTokenExpiresAt
    )
      throw new Error('OAuth session unavailable');
    if (latest.accessTokenExpiresAt.getTime() > Date.now() + 60_000) {
      return decryptSecret(latest.encryptedAccessToken as Buffer);
    }
    const config = oidcConfig();
    const refreshed = await refreshOidcTokens(
      config,
      decryptSecret(latest.encryptedRefreshToken as Buffer),
    );
    const userinfo = await fetchUserinfo(config, refreshed.accessToken);
    validateRefreshedIdentity(
      { subject: latest.providerSubject, jtyid: latest.jtyid, email: latest.email },
      userinfo,
    );
    const accessTokenExpiresAt = new Date(Date.now() + refreshed.expiresIn * 1_000);
    await db
      .update(schema.session)
      .set({
        encryptedAccessToken: encryptSecret(refreshed.accessToken),
        encryptedRefreshToken: encryptSecret(refreshed.refreshToken),
        accessTokenExpiresAt,
      })
      .where(eq(schema.session.id, latest.id));
    return refreshed.accessToken;
  });
}

export async function getSession(sessionId: string): Promise<SessionContext | null> {
  const row = await db.query.session.findFirst({
    where: eq(schema.session.id, sessionId),
  });
  if (!row) return null;
  if (row.expiresAt.getTime() < Date.now()) {
    await revokeAndDeleteSession(sessionId);
    return null;
  }
  if (row.authMode !== 'password' && row.authMode !== 'jtyid') return null;
  const authMode: SessionAuthMode = row.authMode === 'jtyid' ? 'jtyid' : 'password';
  if (
    authMode === 'jtyid' &&
    (!row.authenticatedAt ||
      row.expiresAt.getTime() > row.authenticatedAt.getTime() + 30 * 24 * 60 * 60 * 1_000)
  ) {
    return null;
  }
  let accessToken: string | null = null;
  if (authMode === 'jtyid') {
    try {
      accessToken = await currentAccessToken(row);
    } catch {
      return null;
    }
    if (!accessToken) return null;
  }
  return {
    sessionId: row.id,
    email: row.email,
    name: row.name,
    authMode,
    password: authMode === 'password' ? decryptSecret(row.encryptedPassword as Buffer) : null,
    accessToken,
    jtyid: row.jtyid,
    providerSubject: row.providerSubject,
    imapHost: row.imapHost,
    imapPort: row.imapPort,
    smtpHost: row.smtpHost,
    smtpPort: row.smtpPort,
    expiresAt: row.expiresAt,
  };
}

export async function deleteSession(sessionId: string): Promise<void> {
  await db.delete(schema.session).where(eq(schema.session.id, sessionId));
}

export async function revokeJtyidSessionGrant(sessionId: string): Promise<void> {
  const row = await db.query.session.findFirst({ where: eq(schema.session.id, sessionId) });
  if (row?.authMode !== 'jtyid' || !row.encryptedRefreshToken) return;
  await revokeRefreshToken(oidcConfig(), decryptSecret(row.encryptedRefreshToken as Buffer));
}

export async function revokeAndDeleteSession(
  sessionId: string,
  revoke: (sessionId: string) => Promise<void> = revokeJtyidSessionGrant,
  remove: (sessionId: string) => Promise<void> = deleteSession,
): Promise<boolean> {
  let revoked = true;
  try {
    await revoke(sessionId);
  } catch {
    revoked = false;
  } finally {
    await remove(sessionId);
  }
  return revoked;
}

/**
 * Derives IMAP/SMTP coordinates for an email address. If the env var
 * overrides are set, use them - otherwise guess `mail.<domain>`.
 *
 * This is the convention iRedMail installs out of the box, and is the
 * shape openship's mail panel provisions; for other setups, the
 * sign-in endpoint accepts host/port overrides.
 */
export function defaultMailHosts(email: string): {
  imapHost: string;
  imapPort: number;
  smtpHost: string;
  smtpPort: number;
} {
  const domain = email.split('@')[1] ?? '';
  return {
    imapHost: env.DEFAULT_IMAP_HOST ?? `mail.${domain}`,
    imapPort: env.DEFAULT_IMAP_PORT,
    smtpHost: env.DEFAULT_SMTP_HOST ?? `mail.${domain}`,
    smtpPort: env.DEFAULT_SMTP_PORT,
  };
}
