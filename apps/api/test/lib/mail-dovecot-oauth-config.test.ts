import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

const repoRoot = resolve(import.meta.dirname, "../../../..");
const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const path of temporaryDirectories.splice(0)) {
    rmSync(path, { recursive: true, force: true });
  }
});

function fixture(version: "2.3" | "2.4") {
  const root = mkdtempSync(resolve(tmpdir(), `openship-dovecot-${version}-`));
  temporaryDirectories.push(root);
  const confDir = resolve(root, "etc/dovecot");
  const seedDir = resolve(root, "seed/dovecot");
  mkdirSync(resolve(confDir, "iredmail"), { recursive: true });
  mkdirSync(resolve(seedDir, "iredmail"), { recursive: true });

  const mechanisms =
    version === "2.3"
      ? "auth_mechanisms = PLAIN LOGIN\n"
      : "auth_mechanisms {\n    plain = yes\n    login = yes\n    oauthbearer = no\n    xoauth2 = no\n}\n";
  writeFileSync(
    resolve(confDir, "dovecot.conf"),
    `${mechanisms}!include_try ${confDir}/iredmail/*.conf\n`,
  );

  if (version === "2.3") {
    const managed = readFileSync(
      resolve(repoRoot, "apps/email/engine/samples/dovecot/dovecot-jtyid-oauth-2.3.conf"),
      "utf8",
    ).replace("PH_DOVECOT_OAUTH2_CONF", resolve(confDir, "dovecot-oauth2.conf.ext"));
    const oauth = readFileSync(
      resolve(repoRoot, "apps/email/engine/samples/dovecot/dovecot-oauth2.conf"),
      "utf8",
    )
      .replace("PH_JTYID_DOVECOT_INTROSPECTION_CLIENT_ID", "openship-mail-dovecot")
      .replace("PH_JTYID_DOVECOT_INTROSPECTION_SECRET", "jtyid-introspection-secret-placeholder")
      .replace(
        "PH_JTYID_DOVECOT_INTROSPECTION_URL",
        "https://id.jjty.in/application/o/introspect/",
      );
    writeFileSync(resolve(seedDir, "iredmail/90-openship-jtyid-oauth.conf"), managed);
    writeFileSync(resolve(seedDir, "dovecot-oauth2.conf.ext"), oauth);
  } else {
    const managed = readFileSync(
      resolve(repoRoot, "apps/email/engine/samples/dovecot/dovecot-jtyid-oauth-2.4.conf"),
      "utf8",
    )
      .replace("PH_JTYID_DOVECOT_INTROSPECTION_CLIENT_ID", "openship-mail-dovecot")
      .replace("PH_JTYID_DOVECOT_INTROSPECTION_SECRET", "jtyid-introspection-secret-placeholder")
      .replace(
        "PH_JTYID_DOVECOT_INTROSPECTION_URL",
        "https://id.jjty.in/application/o/introspect/",
      );
    writeFileSync(resolve(seedDir, "iredmail/90-openship-jtyid-oauth.conf"), managed);
  }
  return { confDir, seedDir };
}

function reconcile(version: "2.3" | "2.4", paths: ReturnType<typeof fixture>, secret?: string) {
  execFileSync("bash", [resolve(repoRoot, "apps/email/docker/configure-dovecot-jtyid-oauth.sh")], {
    encoding: "utf8",
    env: {
      ...process.env,
      DOVECOT_TEST_MODE: "1",
      DOVECOT_VERSION_OVERRIDE: version,
      DOVECOT_CONF_DIR: paths.confDir,
      DOVECOT_SEED_DIR: paths.seedDir,
      JTYID_DOVECOT_INTROSPECTION_CLIENT_ID: "openship-mail-dovecot",
      JTYID_DOVECOT_INTROSPECTION_SECRET: secret,
      JTYID_DOVECOT_INTROSPECTION_URL: "https://id.jjty.in/application/o/introspect/",
    },
  });
}

describe("Dovecot JTYID OAuth configuration", () => {
  it("passes the executable 2.3/current and 2.4 sample and generator contract", () => {
    const verifier = resolve(repoRoot, "apps/email/docker/verify-dovecot-oauth-config.sh");

    const output = execFileSync("bash", [verifier, repoRoot], { encoding: "utf8" });

    expect(output).toContain("Dovecot OAuth config contract: OK");
  });

  it.each(["2.3", "2.4"] as const)(
    "applies and rolls back the managed %s OAuth config while retaining password login",
    (version) => {
      const paths = fixture(version);
      const credential = `test-${version.replace(".", "")}-credential`;

      reconcile(version, paths, credential);
      const enabled = readFileSync(resolve(paths.confDir, "dovecot.conf"), "utf8");
      const managed = readFileSync(
        resolve(paths.confDir, "iredmail/90-openship-jtyid-oauth.conf"),
        "utf8",
      );
      const credentialConfig =
        version === "2.3"
          ? readFileSync(resolve(paths.confDir, "dovecot-oauth2.conf.ext"), "utf8")
          : managed;
      expect(enabled.toLowerCase()).toContain("plain");
      expect(enabled.toLowerCase()).toContain("login");
      expect(enabled.toLowerCase()).toContain("oauthbearer");
      expect(enabled.toLowerCase()).toContain("xoauth2");
      expect(credentialConfig).not.toContain("jtyid-introspection-secret-placeholder");
      expect(managed).toContain(version === "2.3" ? "driver = oauth2" : "active_value = true");

      reconcile(version, paths);
      const disabled = readFileSync(resolve(paths.confDir, "dovecot.conf"), "utf8");
      expect(disabled.toLowerCase()).toContain("plain");
      expect(disabled.toLowerCase()).toContain("login");
      if (version === "2.3") {
        expect(disabled.toLowerCase()).not.toContain("oauthbearer");
        expect(disabled.toLowerCase()).not.toContain("xoauth2");
      } else {
        expect(disabled.toLowerCase()).toContain("oauthbearer = no");
        expect(disabled.toLowerCase()).toContain("xoauth2 = no");
      }
      expect(existsSync(resolve(paths.confDir, "iredmail/90-openship-jtyid-oauth.conf"))).toBe(
        false,
      );
      expect(existsSync(resolve(paths.confDir, "dovecot-oauth2.conf.ext"))).toBe(false);
    },
  );
});
