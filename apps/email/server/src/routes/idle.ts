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
import { folderToMailbox, normalizeFolderSlug } from '../lib/imap-driver';
import { bindImapAbort } from '../lib/imap-idle';

export const idleRoute = new Hono();

idleRoute.get('/idle', async (c) => {
  const sid = getCookie(c, env.SESSION_COOKIE_NAME);
  if (!sid) return c.text('Unauthorized', 401);
  const session = await getSession(sid);
  if (!session) return c.text('Unauthorized', 401);

  const folder = normalizeFolderSlug(c.req.query('folder'));
  const mailbox = folderToMailbox(folder);

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
    const abortState = bindImapAbort(stream, client);

    const send = async (event: string, data: unknown) => {
      await stream.writeSSE({ event, data: JSON.stringify(data) });
    };

    const onChange = () => {
      if (!abortState.aborted) {
        void send('mailbox', { folder, at: new Date().toISOString() });
      }
    };

    try {
      await client.connect();
      if (abortState.aborted) return;
      await client.mailboxOpen(mailbox);
      if (abortState.aborted) return;
      client.on('exists', onChange);
      client.on('expunge', onChange);
      client.on('flags', onChange);
      await client.idle();
    } catch (err) {
      if (!abortState.aborted) {
        await send('error', { message: (err as Error).message });
      }
    } finally {
      client.close();
    }
  });
});
