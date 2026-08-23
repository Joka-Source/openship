#!/usr/bin/env bash
set -euo pipefail

log() { echo "[openship-mail] $*"; }

domain="${FIRST_DOMAIN:-}"
tls_root="${OPENSHIP_MAIL_TLS_ROOT:-/etc/letsencrypt}"
cert_file="${OPENSHIP_MAIL_SSL_CERT_FILE:-/etc/ssl/certs/iRedMail.crt}"
key_file="${OPENSHIP_MAIL_SSL_KEY_FILE:-/etc/ssl/private/iRedMail.key}"
openssl_bin="${OPENSHIP_MAIL_TLS_OPENSSL:-openssl}"

if ! printf '%s' "$domain" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$'; then
  log "FATAL: FIRST_DOMAIN is not a valid DNS domain for mail TLS"
  exit 1
fi

mail_domain="mail.${domain}"
live_dir="${tls_root}/live/${mail_domain}"
public_cert="${live_dir}/fullchain.pem"
private_key="${live_dir}/privkey.pem"

if [ ! -e "$public_cert" ] && [ ! -L "$public_cert" ] \
  && [ ! -e "$private_key" ] && [ ! -L "$private_key" ]; then
  log "public certificate for ${mail_domain} not issued yet; retaining the baked bootstrap certificate"
  exit 0
fi
if [ ! -f "$public_cert" ] || [ ! -f "$private_key" ]; then
  log "FATAL: incomplete public certificate material for ${mail_domain}"
  exit 1
fi

# Validate all public material before touching either daemon path. A mismatched,
# expired, or wrong-host pair must leave the previously working files untouched.
"$openssl_bin" x509 -in "$public_cert" -noout -checkend 86400 >/dev/null
"$openssl_bin" x509 -in "$public_cert" -noout -checkhost "$mail_domain" >/dev/null
cert_public_key=$("$openssl_bin" x509 -in "$public_cert" -pubkey -noout)
private_public_key=$("$openssl_bin" pkey -in "$private_key" -pubout)
if [ "$cert_public_key" != "$private_public_key" ]; then
  log "FATAL: public certificate and private key do not match for ${mail_domain}"
  exit 1
fi
unset cert_public_key private_public_key

cert_tmp="${cert_file}.openship-tls.$$"
key_tmp="${key_file}.openship-tls.$$"
cleanup() { rm -f "$cert_tmp" "$key_tmp"; }
trap cleanup EXIT

mkdir -p "$(dirname "$cert_file")" "$(dirname "$key_file")"
ln -s "$public_cert" "$cert_tmp"
ln -s "$private_key" "$key_tmp"

# The daemons have not started yet. Publish each already-validated symlink with a
# same-directory rename so neither path is ever a partially-written PEM file.
mv -f "$key_tmp" "$key_file"
mv -f "$cert_tmp" "$cert_file"
trap - EXIT

log "reconciled Postfix/Dovecot TLS certificate for ${mail_domain}"
