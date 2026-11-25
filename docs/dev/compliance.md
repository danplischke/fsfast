# Compliance with fsspec's and the references' test suites

fsfast's Python classes are run against fsspec's abstract test suite and the
reference implementations' own test suites, on the shared local services. Each
suite is also run against the reference implementation on the same service
(`--ref`). That baseline separates fsfast defects from properties of a suite
or of an emulator.

Measured on 2026-11-25 with:

| Package | Version | Test source |
|---|---|---|
| fsspec | 2026.9.0 | git tag `2026.9.0` (the sdist has no tests) |
| s3fs | 2026.9.0 | PyPI sdist |
| gcsfs | 2026.8.2 | git tag `2026.8.2` |
| adlfs | 2026.8.0 | PyPI sdist |

The extension was a release build (`maturin develop --release`). The services
were RustFS for S3, Samba 4.19 (`data` and `enc` shares), OpenSSH,
fake-gcs-server and Azurite. The s3fs suite uses its own moto server.

## Reproducing

```sh
. .venv/bin/activate
maturin develop --release -m crates/fsfast-py/Cargo.toml
eval "$(scripts/test-services.sh env)"     # run.sh also does this when it is unset
tests/compliance/run.sh                     # every suite, fsfast only
tests/compliance/run.sh --ref               # every suite, fsfast and the reference
tests/compliance/run.sh --ref gcsfs adlfs   # selected suites
PYTEST_ADDOPTS="-k prefix" tests/compliance/run.sh gcsfs   # a subset
```

- `tests/compliance/upstream/fetch.sh` (called by `run.sh`) fetches the
  upstream sources matching the installed versions into
  `tests/compliance/.upstream/`, which is git-ignored. It needs network
  access through the proxy.
- Reports go to `tests/compliance/reports/<suite>[-ref].xml`, with a summary in
  `reports/summary.md`.
- `run.sh` exits non-zero if any fsfast run has a failure or an error.
- Extra test dependencies: `pytest-timeout`, `pytest-mock`, `dask[dataframe]`
  (adlfs's tests import dask and pandas). Install them with
  `uv pip install --python .venv/bin/python -c <(echo fsspec==2026.9.0) pytest-mock "dask[dataframe]"`.
- Without the services, the network suites skip (`gcsfs`, `adlfs`,
  `fsspec-net`) and the abstract suite runs only for local and memory.
- Counts per backend or module:
  `python tests/compliance/summarize.py --pattern 'Test(\w+?)(?:Copy|Get|Put|Open|Pipe)$' tests/compliance/reports/abstract.xml`.
- Failure messages: `python tests/compliance/summarize.py --failures REPORT.xml`.

### How the suites are wired

**abstract** (`tests/compliance/abstract/test_abstract.py`). fsspec's
`AbstractCopyTests`, `AbstractGetTests`, `AbstractPutTests`, `AbstractOpenTests`
and `AbstractPipeTests` run for each of 8 backends. The fixtures are the ones
the references use:
- local: fsspec's `local_fixtures` (`auto_mkdir=True`, `make_path_posix`);
- memory: fsspec's `memory_fixtures`;
- s3, gcs, azure: s3fs's `s3fs_fixtures` (bucket as `fs_path`,
  `supports_empty_directories=False`), with a fresh bucket or container per test
  class;
- smb (each share) and sftp: a fresh directory per test class.

HTTP is not run: the suite needs `makedirs`, `rm` and `touch`, which fsspec's
HTTP filesystem does not offer either. `FSFAST_COMPLIANCE_IMPL=ref` builds the
reference classes instead.

**Upstream suites** (`tests/compliance/upstream/fsfast_shim.py`, loaded with
`-p fsfast_shim`):
- The fetched `tests` packages are appended to the installed packages'
  `__path__`.
- The reference class is replaced by the fsfast class in its module, in its
  package and in fsspec's registry.
- Fixtures that start docker containers are pointed at the shared services:
  - adlfs: refuses to run if a container its tests name already exists, and
    afterwards deletes the containers it created;
  - fsspec smb/sftp: generated copies of the test modules, with `/home/...`
    rewritten to a fresh directory, which is deleted afterwards;
  - gcsfs: fresh bucket names through `GCSFS_TEST_*`.
- Two fixture internals are replaced:
  - fsspec's memory fixtures clear the store through the public API instead of
    `store.clear()`;
  - gcsfs's teardown skips `close_session(gcs._session)`.
- For the `--ref` run of fsspec's suites, fsspec's own `SFTPFileSystem` is
  registered for `sftp`/`ssh`; the installed sshfs package would otherwise
  take over those protocols.

**Triage** (`tests/compliance/upstream/triage.py`). Every upstream test that
does not apply to fsfast has an entry with its reason. Entries are one of:
- `skip`: the test depends on reference internals, or the emulator cannot run
  it;
- `xfail`: an intentional, documented deviation (non-strict);
- `skip-root`: skipped only when running as root.

Every other test must pass. The shim prints entries that matched no collected
test. The `fsspec` table serves both the `fsspec` and `fsspec-net` runs, so
each run lists the other's entries as unmatched.

**Not run:**
- adlfs `test_large_upload_overflow`: a 3 GiB blob that fills the shared disk
  through Azurite's storage.
- gcsfs's zonal/HNS, inventory-report, credential, retry, fuse and
  `extended_gcsfs` modules: they test gcsfs's own client machinery.
- fsspec's generic tests (`fsspec/tests/test_spec.py` and similar): they test
  fsspec's base classes, which fsfast reuses.

## Results

Counts are from the JUnit reports. An XPASS of an upstream non-strict xfail
counts as passed.

| Suite | Backend(s) | Impl | Passed | Failed | Errors | Skipped | Xfailed |
|---|---|---|---:|---:|---:|---:|---:|
| abstract | 8 backends (table below) | fsfast | 1096 | 0 | 0 | 0 | 0 |
| abstract | | reference | 825 | 271 | 0 | 0 | 0 |
| s3fs `s3fs/tests` | S3 on moto | fsfast | 307 | 0 | 0 | 48 | 27 |
| | | s3fs | 377 | 0 | 0 | 1 | 4 |
| fsspec `implementations/tests` (local, memory, http, http_sync) + `tests/abstract/mv.py` | local, memory, http | fsfast | 533 | 0 | 0 | 41 | 20 |
| | | fsspec | 575 | 2 | 0 | 17 | 0 |
| fsspec `test_smb.py` + `test_sftp.py` | Samba `data`, OpenSSH | fsfast | 23 | 0 | 0 | 9 | 0 |
| | | fsspec | 30 | 2 | 0 | 0 | 0 |
| gcsfs `test_core.py`, `derived`, `test_mapping`, `test_dircache`, `test_caching`, `test_core_versioned`, `test_manyopens`, `test_checkers` | fake-gcs-server | fsfast | 272 | 0 | 0 | 118 | 3 |
| | | gcsfs | 350 | 11 | 7 | 25 | 0 |
| adlfs `adlfs/tests` | Azurite | fsfast | 131 | 0 | 0 | 55 | 6 |
| | | adlfs | 190 | 0 | 0 | 2 | 0 |

### Abstract suite per backend

| Backend | fsfast passed | fsfast failed | Reference | Reference passed | Reference failed |
|---|---:|---:|---|---:|---:|
| local | 137 | 0 | fsspec `LocalFileSystem` | 137 | 0 |
| memory | 137 | 0 | fsspec `MemoryFileSystem` | 137 | 0 |
| s3 (RustFS) | 137 | 0 | s3fs | 135 | 2 |
| gcs (fake-gcs-server) | 137 | 0 | gcsfs | 136 | 1 |
| azure (Azurite) | 137 | 0 | adlfs | 82 | 55 |
| smb `data` (signing) | 137 | 0 | fsspec smb | 74 | 63 |
| smb `enc` (encryption) | 137 | 0 | fsspec smb | 74 | 63 |
| sftp (OpenSSH) | 137 | 0 | fsspec sftp (paramiko) | 50 | 87 |

Why the references fail here:
- **adlfs** ignores `maxdepth` in `find`. Its `cp`/`get` with `maxdepth`, and
  the glob edge cases that build on them, act on the whole tree.
- **fsspec smb** has no recursive `copy` (`get_smb_tree() got an unexpected
  keyword argument 'recursive'`). Its glob never matches directories, because
  of the trailing `/` in its find keys. It raises `SMBOSError` instead of
  `FileExistsError` for `xb`.
- **fsspec sftp** has no `cp_file`. Its `put` of a directory fails with
  `IsADirectoryError`, and its `get` of directories fails.
- **s3fs, gcsfs and adlfs** do not raise `FileExistsError` for `open(..., "xb")`
  of an existing object on these emulators.
- **s3fs**: RustFS rejects its conditional `pipe(mode="create")` with a
  different error.

fsfast passes all of these: they are fsspec's documented semantics.

### Where the skips come from

| Suite | Upstream skip / xfail | Triage: reference internals | Triage: emulator | Triage: deviation (xfail) |
|---|---:|---:|---:|---:|
| s3fs | 1 / 3 | 47 | 0 | 24 |
| fsspec (local, memory, http, mv) | 17 / 0 | 24 (2 of them `skip-root`) | 0 | 20 |
| fsspec-net (smb, sftp) | 0 / 0 | 9 | 0 | 0 |
| gcsfs | 25 / 0 | 75 | 18 | 3 |
| adlfs | 2 / 0 | 53 | 0 | 6 |

Upstream skips are the suites' own conditions (real-GCS-only, Windows-only,
optional dependencies). The two `skip-root` entries are permission tests that
cannot work as root; fsspec fails them too here.

## Triage

### fsfast defects found and fixed

| Found by | Defect | Fix | Regression test |
|---|---|---|---|
| gcsfs `test_ls_prefix_cache`, `test_find_with_prefix_partial_cache`, `test_find_withdirs_prefix` | `GCSFileSystem.ls/find(prefix=...)` raised `NotImplementedError` | Implemented with gcsfs's semantics, including prefixes containing `/`, gcsfs's find-directory dicts, and no caching of prefixed listings (`python/fsfast/_gcs.py`) | `tests/python/test_compliance_upstream_fixes.py::test_gcs_prefix_listings` |
| gcsfs `test_mv_file_raises_error_for_specific_generation` | No public `mv_file`; a destination generation was not rejected | `mv_file`/`_mv_file`, which raise gcsfs's `ValueError` | `test_gcs_mv_file` |
| gcsfs conftest and `test_custom_gcp_universe` | `on_google`, `base` and `batch_url_base` were missing | Added; they report the endpoint resolved at construction | `test_gcs_location_properties` |
| adlfs `test_content_settings_*`, `test_put_methods_with_content_settings` | `content_settings=` on `open`/`pipe_file`/`put_file`/`put` was silently ignored | Forwarded to the Rust writer as a per-call option; a `ContentSettings` object or a dict are both accepted | `test_azure_content_settings_and_metadata` |
| adlfs `test_metadata_write`, `test_lazy_metadata_write_mode` | `open(..., metadata=...)` raised `NotImplementedError` | Forwarded. **fsfast-azure** now accepts a per-call `metadata` option (`crates/fsfast-azure/src/write.rs`, unit test `metadata_from_extra`) | same |
| adlfs `test_dask_parquet` | `rm(dir)` without `recursive` raised `OSError(ENOTEMPTY)`; adlfs leaves the directory alone | `_rm_skips_nonempty_dirs` for Azure (`python/fsfast/_objstore.py`) | `test_azure_rm_ls_find` |
| adlfs `test_ls`, `test_mkdir` | `ls(".")`, `ls("*")` and `ls("./")` raised `ValueError`; adlfs lists the containers | `_ls_target` | `test_azure_rm_ls_find` |
| adlfs `test_makedir`, `test_makedir_rmdir`, `test_mkdir` | `mkdir`/`makedir` did not follow adlfs: `makedir` of a path in an existing container did not raise `FileExistsError`; no warning for a failed container probe with `assume_container_exists=None`; root listing stale after creating a container | adlfs's `_mkdir` logic (container probe, `PermissionError`/`FileExistsError`, warning) | `test_azure_mkdir_makedir`, `test_azure_mkdir_probe_failure_warns` |
| adlfs `test_block_size`, `test_find_with_prefix` | `blocksize` defaulted to 4 MiB (adlfs: 50 MiB); `find(prefix=)` raised `NotImplementedError` | 50 MiB attribute default; the Rust handles keep their tuned defaults unless a size is given. `find(prefix=)` implemented | `test_azure_blocksize_and_anon`, `test_azure_rm_ls_find` |
| adlfs `test_anon_*` (its `fs.anon` check) | `fs.anon` stayed `None`; adlfs resolves it from `$AZURE_STORAGE_ANON` | Resolved the same way | `test_azure_blocksize_and_anon` |

Two more defects were found while re-running the earlier sweep's
regression tests (`tests/python/test_compliance_fixes.py`):

| Defect | Fix | Regression test |
|---|---|---|
| SMB `glob("dir/*/")` (trailing `/`: directories only) returned `[]`. SMB paths keep the trailing `/`, and fsspec's glob then built the pattern `dir/*//` | The glob view strips it, as fsspec's glob expects (`python/fsfast/_smb.py`) | `test_compliance_fixes.py::test_smb_glob_matches_directories` |
| S3/Azure `put(dir, "missing-bucket", recursive=True)` uploaded to `bucket/dir/...` instead of `bucket/...`. The bucket was created before the expansion decided whether the target exists | Expand first, then create the bucket (`python/fsfast/_objstore.py`) | `test_compliance_fixes.py::test_s3_recursive_put_creates_missing_bucket` |

The abstract suite had already driven fixes before these runs: SMB glob
matching directories, and Azure `find` honouring `maxdepth`. The parity tests
in `tests/python` had not been updated for them; they now list both as known
deviations from the references (`test_net_smb.py`, `test_net_azure.py`).

### Intentional deviations (xfail)

Each item is documented in [python-parity.md](python-parity.md).

| Suite | Tests | Reason |
|---|---|---|
| s3fs | `test_not_delegate`, `test_merge`, `test_list_del_multipart`, `test_*_exclusive_big*`, `test_put_exclusive_small` | `get_delegated_s3pars`, `merge` and `list/clear_multipart_uploads` are not implemented (the exclusive-write tests check for leftover uploads with them) |
| s3fs | `test_versions*`, `test_fsspec_versions_multiple`, `test_versioned_file_fullpath`, `test_touch_versions`, `test_version_sizes` | write handles do not expose `version_id`; `pipe_file` returns `None` |
| s3fs | `test_multi_checksum`, `test_xattr_setxattr_in_write_mode`, `test_async_stream` | no `ChecksumAlgorithm=`; files have no `setxattr`; no `open_async` |
| s3fs | `test_with_size`, `test_url`, `test_raise_exception_when_file_has_changed_during_reading*` | `open(size=)` is ignored; presigning uses SigV4; a changed object raises `fsfast.PreconditionFailed` (`OSError`), not `s3fs.utils.FileExpired` |
| fsspec memory | `test_no_rewind_append_mode`, `test_append_creates_missing_file[a/ab]` | write handles stream and are not seekable |
| fsspec http | `test_list_invalid_args` | unknown options raise `ValueError` at construction |
| fsspec http | `test_list_cache_*` | HTTP listings are not cached |
| fsspec http | `test_random_access[...]`, `test_no_range_support*`, `test_cat_file_range*` | the test server answers a Range request with a partial 200; fsfast treats a 200 as the full body (RFC 9110) |
| fsspec http | `test_content_length_zero`, `test_mcat_expand`, `test_encoded`, `test_async_file` | trusts `Content-Length: 0`; the test server crashes on HEAD of a directory; per-call request headers are not forwarded; no `open_async` |
| gcsfs | `test_isfile` | assigns `version_aware` after construction; fsfast fixes it at construction |
| gcsfs | `test_default_gcp_universe` | reuses a cached instance after the universe domain changed; fsfast resolves the endpoint at construction |
| gcsfs | `test_write_file_cache_invalidates_only_immediate_parent_standard` | writes invalidate all ancestors' listings |
| adlfs | `test_loop.py` | async (`azure.identity.aio`) credentials are not supported |
| adlfs | `test_fs_pickling` | unknown options raise `ValueError` |
| adlfs | `test_ls_versioned`, `test_write_*_version_id_*` | `ls(versions=True)` and `f.version_id` after a write are not implemented |

### Tests skipped because they depend on reference internals

Every entry is in `triage.py` with its reason. By kind:

**s3fs** (47):
- tests that inspect or patch the aiobotocore client `fs.s3`, call
  `connect()`/`_connect()`, or use `set_session` and aiobotocore sessions;
- private helpers: `_copy_managed`, `_call_s3`, `_get_s3_method_kwargs`;
- `S3File` internals: `buffer`, `parts`, `mpu`, `cache`, `fill_cache`;
- `info()` identity with the dircache object;
- `MANAGED_COPY_THRESHOLD`/`preserve_etag`.

**fsspec** (24, plus 9 in fsspec-net):
- local: `LocalFileOpener.commit` and the umask cache;
- memory: the `store` dict and the `pseudo_dirs` list, and `cp_file`
  monkeypatching;
- http: the aiohttp session, `_fetch_range`, `HTTPStreamFile` and aiohttp
  exception types;
- sftp: fake `paramiko.SSHClient` host-key tests, and paths at the server root
  that need the docker image's root login.

**gcsfs** (75):
- `_call`/`call`, `_get_object` and `_mv_file` mocks;
- the aiohttp session;
- `GCSFile` buffers, cache and prefetcher;
- `_cat_file_*`/`_get_file_*` concurrency helpers and thresholds;
- google-auth patching;
- the dircache-updater helpers;
- a test that reloads the gcsfs module;
- `_call` fakes that, with fsfast, would really create buckets on the shared
  emulator.

**adlfs** (53):
- patches of azure-storage-blob clients (`BlobServiceClient.__init__`,
  `download_blob`, `upload_blob`, `stage_block`, `generate_blob_sas`, versioned
  `BlobClient` fakes);
- `service_client`/`container_client`;
- `_fetch_range`, `_details` and `_rm_files`;
- `AzureBlobFile.metadata`.

### Emulator limitations (fail for the reference too)

gcsfs on fake-gcs-server (18 tests):
- the emulator cannot store an object `a` next to objects `a/...` (`test_simple_upload`, `test_large_upload`, `test_multi_upload`, `test_rm_recursive`);
- it keeps no `dir/` placeholder objects (`test_dir_marker*`, `test_tree`, `test_glob`, `test_expand_path_regional`, `test_walk`);
- it answers HTTP 500 for an `ifGenerationMatch=0` overwrite (`TestGcsfsPipe::test_pipe_exclusive`);
- it cannot create versioned buckets (`test_core_versioned.py`, 7 tests; errors for gcsfs).

## Not covered

- Real AWS, GCS and Azure. Everything above ran against local emulators and
  servers.
- HTTP in the abstract suite (see above), and fsspec's HTTP tests that only
  exercise aiohttp.
- The suites' tests of reference internals (listed above). Where behaviour
  behind them matters (caching, multipart uploads, retries), it is covered by
  the fsfast backends' own Rust tests and by `tests/python`.
