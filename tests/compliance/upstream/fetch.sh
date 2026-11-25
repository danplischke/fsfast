#!/usr/bin/env bash
# Fetch the upstream test suites matching the installed reference packages
# (fsspec, s3fs, gcsfs, adlfs) into $FSFAST_UPSTREAM_DIR
# (default: tests/compliance/.upstream, git-ignored).
#
# * s3fs: the PyPI sdist ships s3fs/tests.
# * fsspec, gcsfs: their sdists omit the tests, so the git tag is cloned
#   (shallow) from GitHub.
# * adlfs: the wheel installs adlfs/tests; the sdist is fetched anyway so
#   every suite runs from one place.
#
# Idempotent: an existing checkout of the right version is kept.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
DEST="${FSFAST_UPSTREAM_DIR:-$ROOT/tests/compliance/.upstream}"
mkdir -p "$DEST"

version() { "$PY" -c "import importlib.metadata as m; print(m.version('$1'))"; }

sdist() { # name version -> $DEST/name-version
  local name=$1 ver=$2 out="$DEST/$1-$2"
  [[ -d "$out" ]] && { echo "have $out"; return; }
  local url
  url=$(curl -fsSL "https://pypi.org/pypi/$name/$ver/json" |
    "$PY" -c "import json,sys; print(next(u['url'] for u in json.load(sys.stdin)['urls'] if u['packagetype']=='sdist'))")
  echo "fetch $url"
  curl -fsSL "$url" | tar xz -C "$DEST"
}

gittag() { # name repo tag -> $DEST/name-git-tag
  local name=$1 repo=$2 tag=$3 out="$DEST/$1-git-$3"
  [[ -d "$out" ]] && { echo "have $out"; return; }
  echo "clone $repo@$tag"
  git -c advice.detachedHead=false clone -q --depth 1 --branch "$tag" "$repo" "$out"
}

sdist s3fs "$(version s3fs)"
sdist adlfs "$(version adlfs)"
gittag fsspec https://github.com/fsspec/filesystem_spec.git "$(version fsspec)"
gittag gcsfs https://github.com/fsspec/gcsfs.git "$(version gcsfs)"
echo "upstream suites in $DEST"
