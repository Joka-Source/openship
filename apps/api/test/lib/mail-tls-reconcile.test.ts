import { execFileSync } from "node:child_process";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

const repoRoot = resolve(import.meta.dirname, "../../../..");
const reconcileScript = resolve(repoRoot, "apps/email/docker/configure-mail-tls.sh");
const entrypoint = readFileSync(resolve(repoRoot, "apps/email/docker/entrypoint.sh"), "utf8");
const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const path of temporaryDirectories.splice(0)) {
    rmSync(path, { recursive: true, force: true });
  }
});

function fixture(
  options: { certificate?: boolean; danglingLineage?: boolean; matchingKey?: boolean } = {},
) {
  const root = mkdtempSync(resolve(tmpdir(), "openship-mail-tls-"));
  temporaryDirectories.push(root);

  const live = resolve(root, "letsencrypt/live/mail.jjty.in");
  const cert = resolve(root, "ssl/certs/iRedMail.crt");
  const key = resolve(root, "ssl/private/iRedMail.key");
  const fakeOpenSsl = resolve(root, "bin/openssl");
  mkdirSync(live, { recursive: true });
  mkdirSync(resolve(root, "ssl/certs"), { recursive: true });
  mkdirSync(resolve(root, "ssl/private"), { recursive: true });
  mkdirSync(resolve(root, "bin"), { recursive: true });
  writeFileSync(cert, "prior-certificate\n");
  writeFileSync(key, "prior-private-key\n");

  if (options.danglingLineage) {
    symlinkSync(
      resolve(root, "letsencrypt/archive/missing-fullchain.pem"),
      resolve(live, "fullchain.pem"),
    );
    symlinkSync(
      resolve(root, "letsencrypt/archive/missing-privkey.pem"),
      resolve(live, "privkey.pem"),
    );
  } else if (options.certificate) {
    writeFileSync(resolve(live, "fullchain.pem"), "VALID CERT mail.jjty.in\n");
    writeFileSync(
      resolve(live, "privkey.pem"),
      options.matchingKey === false ? "WRONG KEY\n" : "VALID KEY mail.jjty.in\n",
    );
  }

  writeFileSync(
    fakeOpenSsl,
    `#!/usr/bin/env bash
set -eu
shift
input=""
previous=""
for argument in "$@"; do
  if [ "$previous" = "-in" ]; then input="$argument"; fi
  previous="$argument"
done
case " $* " in
  *" -checkend "*) grep -q "VALID CERT" "$input" ;;
  *" -checkhost "*) grep -q "mail.jjty.in" "$input" ;;
  *" -pubkey "*) printf "PUBLIC-KEY\\n" ;;
  *" -pubout "*)
    if grep -q "VALID KEY" "$input"; then printf "PUBLIC-KEY\\n"; else printf "OTHER-KEY\\n"; fi ;;
  *) exit 64 ;;
esac
`,
    { mode: 0o755 },
  );

  return { root, live, cert, key, fakeOpenSsl };
}

function reconcile(paths: ReturnType<typeof fixture>) {
  return execFileSync("bash", [reconcileScript], {
    encoding: "utf8",
    env: {
      ...process.env,
      FIRST_DOMAIN: "jjty.in",
      OPENSHIP_MAIL_TLS_ROOT: resolve(paths.root, "letsencrypt"),
      OPENSHIP_MAIL_SSL_CERT_FILE: paths.cert,
      OPENSHIP_MAIL_SSL_KEY_FILE: paths.key,
      OPENSHIP_MAIL_TLS_OPENSSL: paths.fakeOpenSsl,
    },
  });
}

describe("mail engine TLS reconciliation", () => {
  it("runs on every engine boot before database bootstrap", () => {
    const tlsIndex = entrypoint.indexOf("configure-mail-tls.sh");
    expect(tlsIndex).toBeGreaterThan(-1);
    expect(tlsIndex).toBeLessThan(entrypoint.indexOf("bash /opt/openship-mail/db-bootstrap.sh"));
  });

  it("atomically links a valid matching public certificate and key", () => {
    const paths = fixture({ certificate: true, matchingKey: true });

    expect(reconcile(paths)).toContain("mail.jjty.in");

    expect(lstatSync(paths.cert).isSymbolicLink()).toBe(true);
    expect(lstatSync(paths.key).isSymbolicLink()).toBe(true);
    expect(readlinkSync(paths.cert)).toBe(resolve(paths.live, "fullchain.pem"));
    expect(readlinkSync(paths.key)).toBe(resolve(paths.live, "privkey.pem"));
  });

  it("keeps the baked certificate on an initial boot before ACME issuance", () => {
    const paths = fixture();

    expect(reconcile(paths)).toContain("not issued yet");

    expect(readFileSync(paths.cert, "utf8")).toBe("prior-certificate\n");
    expect(readFileSync(paths.key, "utf8")).toBe("prior-private-key\n");
  });

  it("fails without replacing working files when the public cert and key mismatch", () => {
    const paths = fixture({ certificate: true, matchingKey: false });

    expect(() => reconcile(paths)).toThrow();

    expect(existsSync(paths.cert)).toBe(true);
    expect(readFileSync(paths.cert, "utf8")).toBe("prior-certificate\n");
    expect(readFileSync(paths.key, "utf8")).toBe("prior-private-key\n");
  });

  it("fails closed when a retained Certbot lineage has dangling live symlinks", () => {
    const paths = fixture({ danglingLineage: true });

    expect(() => reconcile(paths)).toThrow();

    expect(readFileSync(paths.cert, "utf8")).toBe("prior-certificate\n");
    expect(readFileSync(paths.key, "utf8")).toBe("prior-private-key\n");
  });
});
