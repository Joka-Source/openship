export interface JtyidDovecotIntrospectionConfig {
  clientId: string;
  secret: string | undefined;
  introspectionUrl: string;
}

/**
 * The introspection credential belongs to Dovecot, not the public webmail RP.
 * Omit the entire contract when it is unavailable so password-only first installs
 * keep working. Reconcile opts into an explicit empty secret: that removes a retained
 * credential and lets the engine entrypoint disable OAuth during rollback/deconfiguration.
 */
export function jtyidDovecotEngineSecrets(
  config: JtyidDovecotIntrospectionConfig,
  opts: { includeDisabled?: boolean } = {},
): Record<string, string> {
  if (!config.secret && !opts.includeDisabled) return {};
  return {
    JTYID_DOVECOT_INTROSPECTION_CLIENT_ID: config.clientId,
    JTYID_DOVECOT_INTROSPECTION_SECRET: config.secret ?? "",
    JTYID_DOVECOT_INTROSPECTION_URL: config.introspectionUrl,
  };
}
