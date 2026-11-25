#!/usr/bin/env bash
# Reproducible compliance runs (docs/dev/compliance.md).
#
#   tests/compliance/run.sh [--ref] [SUITE...]
#
# SUITEs (default: all):
#   abstract   fsspec.tests.abstract against every fsfast class
#              (tests/compliance/abstract; local/memory always, network
#              backends when the test services are configured)
#   s3fs       s3fs's own tests (moto server, started by the tests)
#   fsspec     fsspec's implementation tests for local, memory, http
#   fsspec-net fsspec's smb and sftp tests, on the shared Samba/OpenSSH
#              services (paths rewritten to a fresh directory)
#   gcsfs      gcsfs's tests on fake-gcs-server
#   adlfs      adlfs's tests on Azurite
#
# --ref also runs each suite against the reference implementation (the
# baseline the triage compares with). Reports go to
# tests/compliance/reports/<suite>[-ref].xml plus a markdown summary
# (summary.md). Upstream sources are fetched by upstream/fetch.sh.
#
# Needs the extension built (maturin develop --release) and, for the
# network suites, eval "$(scripts/test-services.sh env)" (done here when
# the services script is present). Exit status: 0 when every selected
# fsfast run had no failures/errors.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
UP="${FSFAST_UPSTREAM_DIR:-$HERE/.upstream}"
REPORTS="${FSFAST_COMPLIANCE_REPORTS:-$HERE/reports}"
TIMEOUT="${FSFAST_COMPLIANCE_TIMEOUT:-300}"
export FSFAST_UPSTREAM_DIR="$UP"
mkdir -p "$REPORTS"

WITH_REF=0
SUITES=()
for a in "$@"; do
  case "$a" in
    --ref) WITH_REF=1 ;;
    -h|--help) sed -n '2,27p' "$0"; exit 0 ;;
    *) SUITES+=("$a") ;;
  esac
done
[[ ${#SUITES[@]} -eq 0 ]] && SUITES=(abstract s3fs fsspec fsspec-net gcsfs adlfs)

if [[ -z "${FSFAST_TEST_S3_ENDPOINT:-}" && -x "$ROOT/scripts/test-services.sh" ]]; then
  eval "$("$ROOT/scripts/test-services.sh" env)"
fi
export NO_PROXY="${NO_PROXY:-127.0.0.1,localhost}" no_proxy="${no_proxy:-127.0.0.1,localhost}"

"$HERE/upstream/fetch.sh" >/dev/null || { echo "fetch failed" >&2; exit 2; }
V_FSSPEC=$("$PY" -c "import fsspec; print(fsspec.__version__)")
V_S3FS=$("$PY" -c "import importlib.metadata as m; print(m.version('s3fs'))")
V_GCSFS=$("$PY" -c "import importlib.metadata as m; print(m.version('gcsfs'))")
V_ADLFS=$("$PY" -c "import importlib.metadata as m; print(m.version('adlfs'))")

STATUS=0
RAN=()

# upstream SHIM IMPL NAME DIR PYTEST-ARGS...: run an upstream suite from DIR.
upstream() {
  local shim=$1 impl=$2 name=$3 dir=$4; shift 4
  local xml="$REPORTS/$name.xml"
  echo "== $name ($impl) in $dir"
  (cd "$dir" && env FSFAST_SHIM="$shim" FSFAST_SHIM_IMPL="$impl" \
      PYTHONPATH="$HERE/upstream${PYTHONPATH:+:$PYTHONPATH}" \
      "$PY" -m pytest -c "$HERE/upstream/ini/$shim.ini" --rootdir "$dir" \
      -p fsfast_shim -p no:cacheprovider -q -W ignore --timeout "$TIMEOUT" \
      -rfEX --junitxml="$xml" "$@") 2>&1 | tail -n 25
  RAN+=("$xml")
  if [[ $impl == fsfast ]] && ! "$PY" "$HERE/summarize.py" --clean "$xml" >/dev/null; then STATUS=1; fi
}

abstract() {
  local impl=$1 name=$2 xml="$REPORTS/$2.xml"
  echo "== $name ($impl)"
  (cd "$ROOT" && FSFAST_COMPLIANCE_IMPL="$impl" "$PY" -m pytest tests/compliance/abstract \
      -p no:cacheprovider -q -W ignore --timeout "$TIMEOUT" -rfEX --junitxml="$xml") 2>&1 | tail -n 25
  RAN+=("$xml")
  if [[ $impl == fsfast ]] && ! "$PY" "$HERE/summarize.py" --clean "$xml" >/dev/null; then STATUS=1; fi
}

gen_fsspec_net() {
  # Copies of fsspec's smb/sftp test modules with /home/... rewritten to a
  # fresh directory on the shared services (the shim swaps the docker
  # fixtures for the services' settings and removes the directory).
  GEN="$UP/generated-fsspec-net"
  local gen="$GEN" src="$UP/fsspec-git-$V_FSSPEC/fsspec/implementations/tests"
  local tag; tag="fsfast-cmp-$(date +%s)-$$"
  rm -rf "$gen"; mkdir -p "$gen"
  export FSFAST_GEN_SMB_ROOT="/${FSFAST_TEST_SMB_SHARE:-data}/$tag"
  local home
  home=$("$PY" -c "
import os, fsfast
fs = fsfast.SFTPFileSystem(host=os.environ['FSFAST_TEST_SFTP_HOST'], port=int(os.environ.get('FSFAST_TEST_SFTP_PORT', '22')),
    username=os.environ['FSFAST_TEST_SFTP_USER'], password=os.environ['FSFAST_TEST_SFTP_PASSWORD'], skip_instance_cache=True)
print(fs.realpath('.').rstrip('/'))") || return 1
  export FSFAST_GEN_SFTP_ROOT="$home/$tag"
  sed "s#/home/#$FSFAST_GEN_SMB_ROOT/#g" "$src/test_smb.py" > "$gen/test_smb.py"
  # The relative "a/b/c" case stays relative, below the run's directory.
  sed -e "s#/home/someuserout#$FSFAST_GEN_SFTP_ROOT/someuserout#g" \
      -e "s#\"a/b/c\"#\"$tag/a/b/c\"#g" "$src/test_sftp.py" > "$gen/test_sftp.py"
}

for suite in "${SUITES[@]}"; do
  impls=(fsfast); [[ $WITH_REF == 1 ]] && impls+=(ref)
  for impl in "${impls[@]}"; do
    sfx=""; [[ $impl == ref ]] && sfx="-ref"
    case "$suite" in
      abstract) abstract "$impl" "abstract$sfx" ;;
      s3fs) upstream s3fs "$impl" "s3fs$sfx" "$UP/s3fs-$V_S3FS" s3fs/tests ;;
      fsspec)
        I=fsspec/implementations/tests
        upstream fsspec "$impl" "fsspec$sfx" "$UP/fsspec-git-$V_FSSPEC" \
          $I/test_local.py $I/local $I/test_memory.py $I/memory $I/test_http.py $I/test_http_sync.py \
          fsspec/tests/abstract/mv.py ;;
      fsspec-net)
        if [[ -z "${FSFAST_TEST_SMB_HOST:-}" || -z "${FSFAST_TEST_SFTP_HOST:-}" ]]; then
          echo "== fsspec-net skipped: SMB/SFTP services not configured"; continue
        fi
        gen_fsspec_net || { echo "fsspec-net: cannot reach sftp" >&2; STATUS=1; continue; }
        upstream fsspec "$impl" "fsspec-net$sfx" "$GEN" test_smb.py test_sftp.py ;;
      gcsfs)
        if [[ -z "${FSFAST_TEST_GCS_ENDPOINT:-}" ]]; then echo "== gcsfs skipped: no GCS emulator"; continue; fi
        tag="fsfast-cmp-$(date +%s)-$$"
        STORAGE_EMULATOR_HOST="$FSFAST_TEST_GCS_ENDPOINT" GCSFS_TEST_BUCKET="${tag}-b" \
        GCSFS_TEST_VERSIONED_BUCKET="${tag}-v" GCSFS_TEST_REQ_PAYS_BUCKET="${tag}-rp" \
        GCSFS_TEST_PROJECT=test GCSFS_EXPERIMENTAL_ZB_HNS_SUPPORT=false \
          upstream gcsfs "$impl" "gcsfs$sfx" "$UP/gcsfs-git-$V_GCSFS" gcsfs/tests/test_core.py gcsfs/tests/derived \
          gcsfs/tests/test_mapping.py gcsfs/tests/test_dircache.py gcsfs/tests/test_caching.py \
          gcsfs/tests/test_core_versioned.py gcsfs/tests/test_manyopens.py gcsfs/tests/test_checkers.py ;;
      adlfs)
        if [[ -z "${FSFAST_TEST_AZURE_CONNECTION_STRING:-}" ]]; then echo "== adlfs skipped: no Azurite"; continue; fi
        # test_large_upload_overflow writes a 3 GiB blob (several GiB of
        # Azurite storage on the shared disk): not run, for either impl.
        upstream adlfs "$impl" "adlfs$sfx" "$UP/adlfs-$V_ADLFS" adlfs/tests \
          --deselect adlfs/tests/test_spec.py::test_large_upload_overflow ;;
      *) echo "unknown suite $suite" >&2; exit 2 ;;
    esac
  done
done

if [[ ${#RAN[@]} -gt 0 ]]; then
  "$PY" "$HERE/summarize.py" --by-report "${RAN[@]}" | tee "$REPORTS/summary.md"
fi
exit $STATUS
