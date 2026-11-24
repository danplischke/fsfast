#!/usr/bin/env bash
# Start local test services for fsfast integration tests and benchmarks.
#   scripts/test-services.sh start|stop|env
# Services:
#   S3     RustFS container on 127.0.0.1:9000 (key=testkey secret=testsecret)
#   SMB    Samba smbd on 127.0.0.1:445, shares: data (signing), enc (encryption required)
#          user=fsfast password=fsfastpw
#   SFTP   OpenSSH sshd on 127.0.0.1:2222, user=fsfast password=fsfastpw
set -euo pipefail
STATE="${FSFAST_TEST_STATE:-/tmp/fsfast-test}"
cmd="${1:-start}"

start_s3() {
  if ! docker info >/dev/null 2>&1; then
    (nohup dockerd >"$STATE/dockerd.log" 2>&1 &); sleep 6
  fi
  docker rm -f fsfast-s3 >/dev/null 2>&1 || true
  docker run -d --name fsfast-s3 -p 9000:9000 \
    -e RUSTFS_ACCESS_KEY=testkey -e RUSTFS_SECRET_KEY=testsecret rustfs/rustfs:latest >/dev/null
}

start_smb() {
  mkdir -p "$STATE/smb/data" "$STATE/smb/enc" "$STATE/smb/run" "$STATE/smb/log" "$STATE/smb/private" "$STATE/smb/lock" "$STATE/smb/cache" "$STATE/smb/state" "$STATE/smb/ncalrpc"
  id fsfast >/dev/null 2>&1 || useradd -M -s /usr/sbin/nologin fsfast
  echo "fsfast:fsfastpw" | chpasswd
  chown -R fsfast "$STATE/smb/data" "$STATE/smb/enc"
  cat >"$STATE/smb/smb.conf" <<CONF
[global]
  workgroup = WORKGROUP
  server role = standalone server
  map to guest = never
  server min protocol = SMB2_02
  server max protocol = SMB3_11
  server signing = mandatory
  smb ports = 445
  interfaces = lo
  bind interfaces only = yes
  pid directory = $STATE/smb/run
  lock directory = $STATE/smb/lock
  state directory = $STATE/smb/state
  cache directory = $STATE/smb/cache
  private dir = $STATE/smb/private
  log file = $STATE/smb/log/%m.log
  log level = 1
  passdb backend = tdbsam:$STATE/smb/private/passdb.tdb
  disable spoolss = yes
  ncalrpc dir = $STATE/smb/ncalrpc
  load printers = no
  smb2 leases = yes
[data]
  path = $STATE/smb/data
  read only = no
  valid users = fsfast
[enc]
  path = $STATE/smb/enc
  read only = no
  valid users = fsfast
  smb encrypt = required
CONF
  pkill -f "smbd.*$STATE/smb/smb.conf" >/dev/null 2>&1 || true
  printf 'fsfastpw\nfsfastpw\n' | smbpasswd -c "$STATE/smb/smb.conf" -s -a fsfast >/dev/null
  smbd -D -s "$STATE/smb/smb.conf"
}

start_sftp() {
  mkdir -p "$STATE/sftp/home"
  id fsfast >/dev/null 2>&1 || useradd -M -s /usr/sbin/nologin fsfast
  echo "fsfast:fsfastpw" | chpasswd
  usermod -d "$STATE/sftp/home" -s /bin/bash fsfast
  chown fsfast "$STATE/sftp/home"
  [ -f "$STATE/sftp/hostkey" ] || ssh-keygen -q -t ed25519 -N '' -f "$STATE/sftp/hostkey"
  mkdir -p /run/sshd
  cat >"$STATE/sftp/sshd_config" <<CONF
Port 2222
ListenAddress 127.0.0.1
HostKey $STATE/sftp/hostkey
PasswordAuthentication yes
KbdInteractiveAuthentication no
UsePAM yes
PidFile $STATE/sftp/sshd.pid
Subsystem sftp internal-sftp
CONF
  [ -f "$STATE/sftp/sshd.pid" ] && kill "$(cat "$STATE/sftp/sshd.pid")" 2>/dev/null || true
  /usr/sbin/sshd -f "$STATE/sftp/sshd_config"
}

case "$cmd" in
  start)
    mkdir -p "$STATE"
    start_s3 || echo "WARN: S3 container failed to start" >&2
    start_smb || echo "WARN: smbd failed to start" >&2
    start_sftp || echo "WARN: sshd failed to start" >&2
    "$0" env
    ;;
  stop)
    docker rm -f fsfast-s3 >/dev/null 2>&1 || true
    pkill -f "smbd.*$STATE/smb/smb.conf" || true
    [ -f "$STATE/sftp/sshd.pid" ] && kill "$(cat "$STATE/sftp/sshd.pid")" || true
    ;;
  env)
    cat <<ENV
export NO_PROXY="127.0.0.1,localhost" no_proxy="127.0.0.1,localhost"
export FSFAST_TEST_S3_ENDPOINT=http://127.0.0.1:9000 FSFAST_TEST_S3_KEY=testkey FSFAST_TEST_S3_SECRET=testsecret
export FSFAST_TEST_SMB_HOST=127.0.0.1 FSFAST_TEST_SMB_PORT=445 FSFAST_TEST_SMB_USER=fsfast FSFAST_TEST_SMB_PASSWORD=fsfastpw FSFAST_TEST_SMB_SHARE=data FSFAST_TEST_SMB_ENC_SHARE=enc
export FSFAST_TEST_SFTP_HOST=127.0.0.1 FSFAST_TEST_SFTP_PORT=2222 FSFAST_TEST_SFTP_USER=fsfast FSFAST_TEST_SFTP_PASSWORD=fsfastpw
ENV
    ;;
esac
