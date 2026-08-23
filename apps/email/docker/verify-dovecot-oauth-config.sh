#!/usr/bin/env bash
set -euo pipefail

if [ -d "${1:-}/apps/email/engine" ]; then
  engine_root="$1/apps/email/engine"
  docker_root="$1/apps/email/docker"
else
  engine_root="${1:?engine root required}"
  docker_root="${2:?docker root required}"
fi

require() {
  local file="$1" pattern="$2" description="$3"
  grep -Eq "$pattern" "$file" || {
    echo "Dovecot OAuth config contract failed: ${description} (${file})" >&2
    exit 1
  }
}

current="$engine_root/samples/dovecot/dovecot.conf"
oauth23="$engine_root/samples/dovecot/dovecot-oauth2.conf"
managed23="$engine_root/samples/dovecot/dovecot-jtyid-oauth-2.3.conf"
managed24="$engine_root/samples/dovecot/dovecot-jtyid-oauth-2.4.conf"
generator="$engine_root/functions/dovecot.sh"
helper="$docker_root/configure-dovecot-jtyid-oauth.sh"
build_config="$docker_root/build-config"

require "$current" '^auth_mechanisms = PLAIN LOGIN OAUTHBEARER XOAUTH2$' \
  '2.3/current must retain passwords and advertise both bearer mechanisms'
require "$managed23" 'driver = oauth2' '2.3/current must use the OAuth2 passdb'
require "$managed23" 'mechanisms = OAUTHBEARER XOAUTH2' \
  '2.3/current OAuth passdb must be isolated to bearer mechanisms'
require "$oauth23" '^introspection_mode = post$' '2.3/current must POST introspection'
require "$oauth23" '^username_attribute = email$' '2.3/current must bind tokens to email'
require "$oauth23" '^active_attribute = active$' '2.3/current must fail closed on inactive tokens'
require "$oauth23" '^active_value = true$' '2.3/current must accept only active=true'

for sample in "$engine_root"/samples/dovecot/dovecot-2.4-*.conf; do
  require "$sample" '^auth_mechanisms \{' '2.4 must use the mechanism filter syntax'
  require "$sample" '^[[:space:]]+plain = yes$' '2.4 must retain PLAIN'
  require "$sample" '^[[:space:]]+login = yes$' '2.4 must retain LOGIN'
  require "$sample" '^[[:space:]]+oauthbearer = yes$' '2.4 must enable OAUTHBEARER'
  require "$sample" '^[[:space:]]+xoauth2 = yes$' '2.4 must enable XOAUTH2'
  require "$sample" '^!include_try PH_DOVECOT_CONF_INCLUDE_DIR/\*\.conf$' \
    '2.4 must load the managed OAuth filter'
done
require "$managed24" '^oauth2 \{' '2.4 must define the OAuth2 filter'
require "$managed24" '^[[:space:]]+introspection_mode = post$' \
  '2.4 must POST introspection'
require "$managed24" '^[[:space:]]+username_attribute = email$' \
  '2.4 must bind tokens to email'
require "$managed24" '^[[:space:]]+active_attribute = active$' \
  '2.4 must fail closed on inactive tokens'
require "$managed24" '^[[:space:]]+active_value = true$' \
  '2.4 must accept only active=true'

require "$generator" 'dovecot-jtyid-oauth-2\.3\.conf' \
  'generator must install the 2.3 managed fragment'
require "$generator" 'dovecot-jtyid-oauth-2\.4\.conf' \
  'generator must install the 2.4 managed fragment'
require "$generator" 'chmod 0640.*DOVECOT_JTYID_OAUTH_CONF' \
  'generator must protect the introspection configuration'
require "$build_config" "JTYID_DOVECOT_INTROSPECTION_CLIENT_ID='openship-mail-dovecot'" \
  'build config must lock the dedicated client id'
require "$build_config" "JTYID_DOVECOT_INTROSPECTION_SECRET='jtyid-introspection-secret-placeholder'" \
  'build config must contain only the dedicated runtime marker'
require "$build_config" "JTYID_DOVECOT_INTROSPECTION_URL='https://id.jjty.in/application/o/introspect/'" \
  'build config must lock the Authentik global introspection endpoint'

bash -n "$generator"
bash -n "$helper"
require "$helper" 'rm -f "\$managed_conf" "\$oauth2_conf"' \
  'runtime disable must remove managed OAuth credentials'
require "$helper" 'doveconf -c "\$main_conf" -n' \
  'runtime apply must reject invalid generated Dovecot configuration'

echo 'Dovecot OAuth config contract: OK'
