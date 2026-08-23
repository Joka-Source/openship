import { describe, expect, it } from "bun:test";

import { folderToMailbox, normalizeFolderSlug } from "../src/lib/imap-driver";
import { bindImapAbort } from "../src/lib/imap-idle";

describe("IMAP IDLE mailbox selection", () => {
  it("maps physical, aliased, and virtual route folders through the mail driver contract", () => {
    expect(folderToMailbox(normalizeFolderSlug("sent"))).toBe("Sent");
    expect(folderToMailbox(normalizeFolderSlug("draft"))).toBe("Drafts");
    expect(folderToMailbox(normalizeFolderSlug("bin"))).toBe("Trash");
    expect(folderToMailbox(normalizeFolderSlug("starred"))).toBe("INBOX");
    expect(folderToMailbox(normalizeFolderSlug("unexpected"))).toBe("INBOX");
  });
});

describe("IMAP IDLE abort lifecycle", () => {
  it("closes the IMAP socket synchronously when the SSE client disconnects", () => {
    let abort: (() => void) | undefined;
    let closeCount = 0;

    const state = bindImapAbort(
      { onAbort: (handler) => (abort = handler) },
      { close: () => closeCount++ },
    );

    expect(state.aborted).toBe(false);
    expect(abort).toBeDefined();
    abort!();
    expect(closeCount).toBe(1);
    expect(state.aborted).toBe(true);
  });
});
