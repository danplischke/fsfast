#!/usr/bin/env bash
# Start fsfast's test services on a GitHub Actions ubuntu runner by reusing
# scripts/test-services.sh (the same RustFS / fake-gcs-server / Azurite
# containers and the same Samba and OpenSSH configuration engineers use
# locally), then export the service settings to later steps.
#
#   .github/scripts/ci-services.sh            # start, wait, export
#
# What this adds on top of scripts/test-services.sh:
#   * installs samba and openssh-server (only under GitHub Actions);
#   * stops the distribution's smbd that the samba package starts on :445
#     (test-services.sh leaves any service already listening on a port
#     alone, so it would otherwise test against the wrong server);
#   * runs the script as root (useradd, chpasswd, smbd/sshd on privileged
#     ports need it), waits until every service answers, and appends the
#     `scripts/test-services.sh env` settings to $GITHUB_ENV.
#
# Outside GitHub Actions it only runs `test-services.sh start` (which never
# touches services that are already up), waits, and prints the settings, so
# it is safe to run on a shared development machine.
set -euo pipefail
cd "$(dirname "$0")/../.."

STATE="${FSFAST_TEST_STATE:-/tmp/fsfast-test}"
SUDO=""
if [ "$(id -u)" != 0 ]; then SUDO="sudo"; fi

port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

wait_for() { # name port timeout_seconds
  local name=$1 port=$2 limit=$3
  for _ in $(seq "$limit"); do
    if port_open "$port"; then return 0; fi
    sleep 1
  done
  echo "::error::$name did not start listening on port $port within ${limit}s" >&2
  return 1
}

wait_http() { # name url timeout_seconds: any HTTP status means the server is up
  local name=$1 url=$2 limit=$3 code
  for _ in $(seq "$limit"); do
    code=$(curl -s -o /dev/null -w '%{http_code}' --noproxy '*' "$url" || true)
    if [ "$code" != "000" ]; then return 0; fi
    sleep 1
  done
  echo "::error::$name at $url did not answer within ${limit}s" >&2
  return 1
}

if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
  export DEBIAN_FRONTEND=noninteractive
  $SUDO apt-get update -qq
  $SUDO apt-get install -y -qq --no-install-recommends samba openssh-server curl
  # Only the distribution's systemd units: a CI runner has no other smbd.
  $SUDO systemctl stop smbd nmbd samba-ad-dc 2>/dev/null || true
  $SUDO systemctl disable smbd nmbd samba-ad-dc 2>/dev/null || true
  for _ in $(seq 30); do port_open 445 || break; sleep 1; done
  if port_open 445; then
    echo "::error::port 445 is still in use after stopping the distribution's smbd" >&2
    exit 1
  fi
  # Pull the images up front so the start below is quick and a registry
  # hiccup is reported as such.
  for img in rustfs/rustfs:latest fsouza/fake-gcs-server:latest \
             mcr.microsoft.com/azure-storage/azurite:latest; do
    $SUDO docker pull -q "$img" >/dev/null
  done
fi

$SUDO env FSFAST_TEST_STATE="$STATE" scripts/test-services.sh start >/dev/null

wait_for "RustFS (S3)" 9000 120
wait_for "Samba" 445 60
wait_for "OpenSSH" 2222 60
wait_for "fake-gcs-server" 4443 120
wait_for "Azurite" 10000 120
wait_http "RustFS (S3)" http://127.0.0.1:9000/ 120
wait_http "fake-gcs-server" http://127.0.0.1:4443/storage/v1/b 120
wait_http "Azurite" http://127.0.0.1:10000/devstoreaccount1 120

scripts/test-services.sh status

settings=$(bash -c 'eval "$(scripts/test-services.sh env)"; env' |
  grep -E '^(FSFAST_TEST_[A-Z0-9_]+|NO_PROXY|no_proxy)=' | sort)
if [ -n "${GITHUB_ENV:-}" ]; then
  printf '%s\n' "$settings" >>"$GITHUB_ENV"
  echo "exported $(printf '%s\n' "$settings" | wc -l) settings to GITHUB_ENV"
else
  printf '%s\n' "$settings" | sed -E 's/^([A-Za-z0-9_]+_(KEY|SECRET|PASSWORD|CONNECTION_STRING))=.*/\1=***/'
fi
