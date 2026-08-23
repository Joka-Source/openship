#!/usr/bin/env bash
set -Eeuo pipefail

test_root=$(mktemp -d /tmp/openship-dovecot-auth.XXXXXX)
dovecot_pid=
cleanup() {
  if [ -n "$dovecot_pid" ]; then
    kill "$dovecot_pid" >/dev/null 2>&1 || true
    wait "$dovecot_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$test_root"
}
trap cleanup EXIT

install -d -m 0755 "$test_root/run" "$test_root/state" "$test_root/mail"
cat > "$test_root/dovecot-sql.conf.ext" <<'EOF'
driver = pgsql
connect = host=127.0.0.1 port=1 dbname=unreachable user=unreachable password=unreachable connect_timeout=1
default_pass_scheme = SSHA512
password_query = SELECT password FROM mailbox WHERE username = '%u'
EOF
cat > "$test_root/dovecot-oauth2.conf.ext" <<'EOF'
client_id = openship-mail-dovecot
client_secret = build-time-placeholder
introspection_mode = post
introspection_url = https://127.0.0.1:1/introspect/
username_attribute = email
active_attribute = active
active_value = true
tls_ca_cert_file = /etc/ssl/certs/ca-certificates.crt
EOF
cat > "$test_root/dovecot.conf" <<EOF
base_dir = $test_root/run
state_dir = $test_root/state
protocols = imap
listen = 127.0.0.1
ssl = no
disable_plaintext_auth = no
auth_mechanisms = PLAIN LOGIN OAUTHBEARER XOAUTH2
mail_location = maildir:$test_root/mail/%u
first_valid_uid = 1
log_path = $test_root/dovecot.log
info_log_path = $test_root/dovecot.log
debug_log_path = $test_root/dovecot.log

service imap-login {
  inet_listener imap {
    address = 127.0.0.1
    port = 11143
  }
}

service auth {
  unix_listener auth-userdb {
    mode = 0600
  }
}

userdb {
  driver = static
  args = uid=nobody gid=nogroup home=$test_root/mail/%u
}

passdb {
  driver = sql
  args = $test_root/dovecot-sql.conf.ext
  mechanisms = PLAIN LOGIN
}

passdb {
  driver = oauth2
  args = $test_root/dovecot-oauth2.conf.ext
  mechanisms = OAUTHBEARER XOAUTH2
}
EOF

/usr/sbin/dovecot -F -c "$test_root/dovecot.conf" &
dovecot_pid=$!
for _attempt in $(seq 1 20); do
  nc -z 127.0.0.1 11143 >/dev/null 2>&1 && break
  sleep 0.25
done
nc -z 127.0.0.1 11143 >/dev/null 2>&1

printf 'a CAPABILITY\r\nb LOGOUT\r\n' |
  timeout --signal=KILL 10 nc 127.0.0.1 11143 > "$test_root/capability.txt"

grep -q 'AUTH=XOAUTH2' "$test_root/capability.txt"
grep -q 'AUTH=OAUTHBEARER' "$test_root/capability.txt"
! grep -q 'Auth process broken' "$test_root/capability.txt"
! grep -q 'Panic: file http-client' "$test_root/dovecot.log"
printf '%s\n' 'Dovecot PostgreSQL + OAuth auth-process regression: OK'
