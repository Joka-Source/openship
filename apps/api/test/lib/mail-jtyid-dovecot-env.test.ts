import { describe, expect, it } from "vitest";

import { jtyidDovecotEngineSecrets } from "../../src/modules/mail/jtyid-dovecot";

describe("JTYID Dovecot engine secrets", () => {
  it("passes the dedicated introspection contract only when its secret is configured", () => {
    expect(
      jtyidDovecotEngineSecrets({
        clientId: "openship-mail-dovecot",
        secret: undefined,
        introspectionUrl: "https://id.jjty.in/application/o/introspect/",
      }),
    ).toEqual({});

    expect(
      jtyidDovecotEngineSecrets({
        clientId: "openship-mail-dovecot",
        secret: "test-only-introspection-secret",
        introspectionUrl: "https://id.jjty.in/application/o/introspect/",
      }),
    ).toEqual({
      JTYID_DOVECOT_INTROSPECTION_CLIENT_ID: "openship-mail-dovecot",
      JTYID_DOVECOT_INTROSPECTION_SECRET: "test-only-introspection-secret",
      JTYID_DOVECOT_INTROSPECTION_URL: "https://id.jjty.in/application/o/introspect/",
    });
  });

  it("emits an explicit empty secret for reconcile so removing the API secret disables OAuth", () => {
    expect(
      jtyidDovecotEngineSecrets(
        {
          clientId: "openship-mail-dovecot",
          secret: undefined,
          introspectionUrl: "https://id.jjty.in/application/o/introspect/",
        },
        { includeDisabled: true },
      ),
    ).toEqual({
      JTYID_DOVECOT_INTROSPECTION_CLIENT_ID: "openship-mail-dovecot",
      JTYID_DOVECOT_INTROSPECTION_SECRET: "",
      JTYID_DOVECOT_INTROSPECTION_URL: "https://id.jjty.in/application/o/introspect/",
    });
  });
});
