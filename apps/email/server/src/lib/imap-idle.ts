interface AbortStream {
  onAbort(handler: () => void): void;
}

interface ClosableImapClient {
  close(): void;
}

/** Bind transport cleanup before any potentially blocking IMAP operation. */
export function bindImapAbort(stream: AbortStream, client: ClosableImapClient) {
  let aborted = false;

  stream.onAbort(() => {
    aborted = true;
    client.close();
  });

  return {
    get aborted() {
      return aborted;
    },
  };
}
