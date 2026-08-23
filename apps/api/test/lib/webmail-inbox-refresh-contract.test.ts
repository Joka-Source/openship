import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const repoRoot = resolve(import.meta.dirname, "../../../..");
const mailLayout = readFileSync(
  resolve(repoRoot, "apps/email/client/components/mail/mail.tsx"),
  "utf8",
);
const idleRoute = readFileSync(
  resolve(repoRoot, "apps/email/server/src/routes/idle.ts"),
  "utf8",
);

describe("webmail inbox freshness", () => {
  it("subscribes once to IMAP IDLE events and refetches the visible folder", () => {
    expect(mailLayout).toContain("new EventSource(`/mail/idle?folder=");
    expect(mailLayout).toContain("addEventListener('mailbox'");
    expect(mailLayout).toContain("void refetchThreads()");
    expect(mailLayout).toContain("eventSource.close()");
  });

  it("retains a bounded visible-tab fallback when IDLE is interrupted", () => {
    expect(mailLayout).toContain("30_000");
    expect(mailLayout).toContain("document.visibilityState === 'visible'");
    expect(mailLayout).toContain("visibilitychange");
    expect(mailLayout).toContain("window.clearInterval");
  });

  it("normalizes route folders and arms socket cleanup before IMAP can block", () => {
    expect(idleRoute).toContain("normalizeFolderSlug(c.req.query('folder'))");
    expect(idleRoute).toContain("folderToMailbox(folder)");
    expect(idleRoute).toContain("client.mailboxOpen(mailbox)");
    expect(idleRoute.indexOf("bindImapAbort(stream, client)")).toBeLessThan(
      idleRoute.indexOf("await client.connect()"),
    );
  });
});
