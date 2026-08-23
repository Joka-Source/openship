#!/usr/bin/env bash
set -euo pipefail

log() { echo "[openship-mail] $*"; }

install_config_dir() {
  if [ "${DOVECOT_TEST_MODE:-}" = 1 ]; then
    install -d -m 0750 "$1"
  else
    install -d -m 0750 -o root -g dovecot "$1"
  fi
}

install_config_file() {
  if [ "${DOVECOT_TEST_MODE:-}" = 1 ]; then
    install -m 0640 "$1" "$2"
  else
    install -m 0640 -o root -g dovecot "$1" "$2"
  fi
}

conf_dir="${DOVECOT_CONF_DIR:-/etc/dovecot}"
seed_dir="${DOVECOT_SEED_DIR:-/opt/openship-mail/seed/dovecot}"
main_conf="${conf_dir}/dovecot.conf"
managed_conf="${conf_dir}/iredmail/90-openship-jtyid-oauth.conf"
oauth2_conf="${conf_dir}/dovecot-oauth2.conf.ext"
version="${DOVECOT_VERSION_OVERRIDE:-$(dovecot --version 2>/dev/null || true)}"
version="${version%% *}"

[ -f "$main_conf" ] || { log "FATAL: Dovecot config is missing"; exit 1; }
case "$version" in
  2.3*) version=2.3 ;;
  2.4*) version=2.4 ;;
  *) log "FATAL: unsupported Dovecot version for JTYID OAuth"; exit 1 ;;
esac

secret="${JTYID_DOVECOT_INTROSPECTION_SECRET:-}"
client_id="${JTYID_DOVECOT_INTROSPECTION_CLIENT_ID:-openship-mail-dovecot}"
introspection_url="${JTYID_DOVECOT_INTROSPECTION_URL:-https://id.jjty.in/application/o/introspect/}"

disable_oauth_mechanisms() {
  perl -pi -e 'if (/^auth_mechanisms\s*=/) { s/\s+(?:OAUTHBEARER|XOAUTH2)\b//ig }' "$main_conf"
  perl -pi -e 's/^(\s*(?:oauthbearer|xoauth2)\s*=\s*)yes\b/${1}no/i' "$main_conf"
}

enable_oauth_mechanisms() {
  perl -pi -e 'if (/^auth_mechanisms\s*=/ && !/\b(?:OAUTHBEARER|XOAUTH2)\b/i) { s/\s*$/ OAUTHBEARER XOAUTH2\n/ }' "$main_conf"
  perl -pi -e 's/^(\s*(?:oauthbearer|xoauth2)\s*=\s*)no\b/${1}yes/i' "$main_conf"
}

if [ -z "$secret" ]; then
  disable_oauth_mechanisms
  rm -f "$managed_conf" "$oauth2_conf"
  log "JTYID Dovecot OAuth disabled; PLAIN LOGIN remains available"
  exit 0
fi

case "$client_id" in
  *[!A-Za-z0-9._-]*|"") log "FATAL: invalid JTYID Dovecot introspection client id"; exit 1 ;;
esac
case "$secret" in
  *[!A-Za-z0-9._~-]*|"") log "FATAL: invalid JTYID Dovecot introspection secret"; exit 1 ;;
esac
case "$introspection_url" in
  https://*) ;;
  *) log "FATAL: JTYID Dovecot introspection URL must use HTTPS"; exit 1 ;;
esac
case "$introspection_url" in
  *$'\n'*|*$'\r'*) log "FATAL: invalid JTYID Dovecot introspection URL"; exit 1 ;;
esac

source_managed="${seed_dir}/iredmail/90-openship-jtyid-oauth.conf"
[ -f "$source_managed" ] || { log "FATAL: baked Dovecot OAuth config is missing"; exit 1; }
install_config_dir "${conf_dir}/iredmail"
install_config_file "$source_managed" "$managed_conf"

if [ "$version" = 2.3 ]; then
  source_oauth2="${seed_dir}/dovecot-oauth2.conf.ext"
  [ -f "$source_oauth2" ] || { log "FATAL: baked Dovecot OAuth2 settings are missing"; exit 1; }
  install_config_file "$source_oauth2" "$oauth2_conf"
else
  rm -f "$oauth2_conf"
fi

export _JTYID_DOVECOT_CLIENT_ID="$client_id"
export _JTYID_DOVECOT_SECRET="$secret"
export _JTYID_DOVECOT_INTROSPECTION_URL="$introspection_url"
for config in "$managed_conf" "$oauth2_conf"; do
  [ -f "$config" ] || continue
  perl -pi -e 's/\Qopenship-mail-dovecot\E/$ENV{_JTYID_DOVECOT_CLIENT_ID}/g' "$config"
  perl -pi -e 's/\Qjtyid-introspection-secret-placeholder\E/$ENV{_JTYID_DOVECOT_SECRET}/g' "$config"
  perl -pi -e 's#\Qhttps://id.jjty.in/application/o/introspect/\E#$ENV{_JTYID_DOVECOT_INTROSPECTION_URL}#g' "$config"
done
unset _JTYID_DOVECOT_CLIENT_ID _JTYID_DOVECOT_SECRET _JTYID_DOVECOT_INTROSPECTION_URL

if ! grep -qF "!include_try ${conf_dir}/iredmail/*.conf" "$main_conf"; then
  printf '\n!include_try %s/iredmail/*.conf\n' "$conf_dir" >> "$main_conf"
fi
enable_oauth_mechanisms

if command -v doveconf >/dev/null 2>&1; then
  doveconf -c "$main_conf" -n >/dev/null
fi
log "JTYID Dovecot OAuth configured for ${version}"
