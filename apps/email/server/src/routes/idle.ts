/**
 * Server-Sent Events bridge for IMAP IDLE.
 *
 * Client opens `GET /mail/idle?folder=inbox` and we hold an IMAP
 * connection open in IDLE on that mailbox. Every EXISTS / EXPUNGE /
 * FETCH from Dovecot becomes one SSE `event: mailbox` line - the
 * client invalidates the threads query in response.
 *
 * We hold one IMAP connection per SSE client. Cheap on the same VPS;
 * if we ever need to scale, share one IMAP connection per mailbox
 * across SSE clients.
 */

import { Hono } from 'hono';
import { streamSSE } from 'hono/streaming';
import { getCookie } from 'hono/cookie';
import { ImapFlow } from 'imapflow';
import { env } from '../env';
import { getSession } from '../lib/session';
import { imapClientOptions } from '../lib/imap';

export const idleRoute = new Hono();

idleRoute.get('/idle', async (c) => {
  const sid = getCookie(c, env.SESSION_COOKIE_NAME);
  if (!sid) return c.text('Unauthorized', 401);
  const session = await getSession(sid);
  if (!session) return c.text('Unauthorized', 401);

  const folder = c.req.query('folder') || 'INBOX';

  return streamSSE(c, async (stream) => {
    const client = new ImapFlow(
      imapClientOptions({
        host: session.imapHost,
        port: session.imapPort,
        user: session.email,
        ...(session.authMode === 'jtyid'
          ? { accessToken: session.accessToken! }
          : { pass: session.password! }),
      }),
    );

    const send = async (event: string, data: unknown) => {
      await stream.writeSSE({ event, data: JSON.stringify(data) });
    };

    const onChange = () => {
      void send('mailbox', { folder, at: new Date().toISOString() });
    };

    try {
      await client.connect();
      await client.mailboxOpen(folder);
      client.on('exists', onChange);
      client.on('expunge', onChange);
      client.on('flags', onChange);
      await client.idle();

      stream.onAbort(async () => {
        try {
          await client.logout();
        } catch {
          /* ignore */
        }
      });

      // Keep the response open until aborted. `idle()` returns when
      // the IDLE is broken; loop so brief disconnects don't end the
      // stream.
      // eslint-disable-next-line no-constant-condition
      while (true) {
        await new Promise((r) => setTimeout(r, 1000 * 60 * 25));
        try {
          await client.noop();
        } catch {
          break;
        }
      }
    } catch (err) {
      await send('error', { message: (err as Error).message });
    } finally {
      try {
        await client.logout();
      } catch {
        /* ignore */
      }
    }
  });
});
