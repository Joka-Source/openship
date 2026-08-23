import { describe, expect, it } from 'bun:test';
import { Database } from 'bun:sqlite';
import { bootstrapSchema } from '../src/db/bootstrap';

describe('session schema migration', () => {
  it('adds OAuth fields while preserving a legacy password session', () => {
    const sqlite = new Database(':memory:');
    sqlite.exec(`CREATE TABLE session (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL,
      name TEXT,
      encrypted_password BLOB NOT NULL,
      imap_host TEXT NOT NULL,
      imap_port INTEGER NOT NULL,
      smtp_host TEXT NOT NULL,
      smtp_port INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    )`);
    sqlite
      .query(`INSERT INTO session VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(
        'legacy-id',
        'person@jjty.in',
        null,
        Buffer.from('encrypted'),
        'mail.jjty.in',
        993,
        'mail.jjty.in',
        465,
        1,
        2,
      );

    bootstrapSchema(sqlite);
    const row = sqlite
      .query(
        `SELECT auth_mode, jtyid, provider_subject, authenticated_at, encrypted_access_token, encrypted_refresh_token, access_token_expires_at FROM session WHERE id = ?`,
      )
      .get('legacy-id') as Record<string, unknown>;

    expect(row).toEqual({
      auth_mode: 'password',
      jtyid: null,
      provider_subject: null,
      authenticated_at: null,
      encrypted_access_token: null,
      encrypted_refresh_token: null,
      access_token_expires_at: null,
    });
  });
});
