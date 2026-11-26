# Python parity of the network backends

fsfast's Python package offers drop-in replacements for six fsspec
implementations. Each class subclasses `fsfast.FsfastFileSystem` (an fsspec
`AsyncFileSystem`) and runs its operations in Rust.

| protocols | fsfast class | reference | Rust crate |
|---|---|---|---|
| `http`, `https` | `fsfast.HTTPFileSystem` | `fsspec.implementations.http.HTTPFileSystem` | fsfast-http |
| `s3`, `s3a` | `fsfast.S3FileSystem` | `s3fs.S3FileSystem` | fsfast-s3 |
| `smb` | `fsfast.SMBFileSystem` | `fsspec.implementations.smb.SMBFileSystem` | fsfast-smb |
| `sftp`, `ssh` | `fsfast.SFTPFileSystem` | `fsspec.implementations.sftp.SFTPFileSystem` | fsfast-sftp |
| `gs`, `gcs` | `fsfast.GCSFileSystem` | `gcsfs.GCSFileSystem` | fsfast-gcs |
| `abfs`, `az`, `abfss` | `fsfast.AzureBlobFileSystem` | `adlfs.AzureBlobFileSystem` | fsfast-azure |

All the protocols are in `fsfast.CLASSES`, so `fsfast.install()` and `FSFAST_OVERRIDE` can swap them into fsspec's registry. A protocol whose cargo feature is compiled out does not appear in `CLASSES`.

## How parity is tested

`tests/python/test_net_<backend>.py` and the shared harness in `tests/python/netparity.py` run each reference implementation and fsfast against the same local service: RustFS, fake-gcs-server, Azurite, Samba (both the `data` and the `enc` share), OpenSSH, and an HTTP server that the test starts itself.

- **Reads.** The reference builds one tree, and about 70 read operations run through both implementations on that tree:
  - ls, info and find (detail, withdirs, maxdepth), walk, glob, du;
  - cat, cat_file ranges (including negative and past-EOF ranges), cat_ranges, head, tail, read_block;
  - open in rb and r modes with seek, readline and iteration;
  - exists, isdir, isfile, size, sizes, modified;
  - a name with spaces, unicode, `+`, `%`, `&` and `=`, empty files;
  - missing paths and directories, to compare errors;
  - the listings cache, with "cached" steps that reuse it.

  The results must be equal. Dicts must have the same keys in the same order, except for GCS objects (see below). An error must be the reference's type, or a subclass of it, or for SMB an `OSError` with the same errno.
- **Writes.** The same 30–40 mutating steps run in two scratch roots, one per implementation:
  - mkdir/makedirs/rmdir, pipe, pipe_file, write_bytes, touch;
  - open in wb, w, ab and xb modes, and transactions;
  - put_file, recursive put, recursive get, get_file;
  - cp_file, recursive copy, mv of a file and of a directory, rm, rm_file, recursive rm, and the same operations on missing paths.

  After every step the outcomes are compared, and so are both trees. The reference takes both snapshots, with names mapped between the roots. The return values of mutating calls are not compared: s3fs, for example, returns boto responses.
- **Integration.**
  - `fsspec.filesystem(proto, ...)`, `fsspec.open("proto://...")` and `url_to_fs` after `install()`, for every protocol alias.
  - The async methods (`_pipe_file`, `_cat_file`, `_info`, `_find`, `_ls`, `_cat_ranges`, `_rm_file`) on an `asynchronous=True` instance inside an event loop.
  - Pickling round trips of filesystems and open files.
  - Offline comparisons of `_strip_protocol`, `_get_kwargs_from_urls`, `_parent`, `split_path` and `unstrip_protocol` on awkward URLs.
  - The listings-cache semantics, by writing behind the cache with a third client.
  - Fork safety: an SMB filesystem is used in a forked child.
  - The reference extras each class provides.
- Without the service environment variables, the service tests skip and the offline tests still run. Plain `pytest` passes without services.

Result with a release build of the extension (`maturin develop --release`): 674 passed and 2 skipped in `tests/python` when this page was written; 745 passed and 2 skipped on 2026-11-26, after the review and performance fixes added their regression tests (`test_review_fixes.py`, `test_perf_fixes.py`). The 2 skips are permission tests that need a non-root user. Per backend:
- s3: 17 passed
- gcs: 16 passed
- azure: 16 passed
- smb: 20 passed (both shares)
- sftp: 15 passed
- http: 11 passed

## Shared mechanics

- **Info key order.** `fsfast-core`'s `FileInfo.extra` is a sorted map, so fsfast-py restores the reference key order with per-backend layouts (`Backend::layouts` in `crates/fsfast-py/src/registry.rs`).
  - s3fs builds differently ordered dicts for HEAD results, listing entries, `ls("")` buckets and probed directories. fsfast-py picks a layout per entry.
  - fsspec http puts `type` last.
- **Listings cache** (s3, gs, abfs; `python/fsfast/_objstore.py`):
  - Listings are kept in fsspec's `dircache`, which `use_listings_cache`, `listings_expiry_time` and `max_paths` configure.
  - `info`, `exists` and `isdir` answer from a cached parent listing, as the references do. `info` after `ls` returns the listing entry, and a stale listing hides objects written by others until `refresh=True` or `invalidate_cache()` is used.
  - `find` fills the cache with the listings it implies.
  - Every mutating method invalidates the paths it touched and their ancestors.
  - http caches only when `use_listings_cache=True`, as fsspec's does.
- **Transactions** (`autocommit=False`) on object stores and http go to a local temporary file, which is uploaded at commit. Nothing is visible before the commit. SMB and SFTP write to the reference's temporary path (`temppath`) and rename it at commit.
- **Backend-specific methods.** They go through `RustFileSystem.call(method, args)` and `call_async`, which `crates/fsfast-py/src/ext.rs` dispatches per backend:
  - SMB `connect`/`connection_info`;
  - SFTP `connect`/`chmod`/`symlink`/`readlink`/`realpath`;
  - s3fs extras;
  - gcsfs `url`/`merge`;
  - adlfs `setxattrs`.
- **Eager connection.** SMB and SFTP connect and authenticate in the constructor, without the GIL, as fsspec's classes do. Bad credentials raise `PermissionError` at construction.
- **Per-call options.** `open()` and `pipe_file()` keywords reach the backend as `WriteOptions.extra`/`ReadOptions.extra`, so s3fs-style `ContentType=`, `Metadata=` and `ServerSideEncryption=` work.

## Intentional deviations

Each item below is either a reference bug or a limitation that fsfast does not copy, or a point where fsfast cannot match the reference exactly. Every one is listed in the test's `known` table with the reason.

### All backends
- **Exception types are more precise.** fsfast raises the precise `OSError` subclass (`FileNotFoundError`, `IsADirectoryError`, ...) where references raise a plain `OSError`/`IOError` (paramiko) or their own `OSError` subclass. Code catching the reference's type still works.
- **Negative and out-of-range byte ranges** follow fsspec's semantics on every backend. Several references fail on them:
  - fsspec smb and sftp raise `AttributeError` for a negative start;
  - adlfs raises `ValueError`;
  - s3fs raises `OSError(EINVAL)` past EOF;
  - fsspec http raises `aiohttp.ClientResponseError` (416).
- **File objects return what Python's `io` objects return.** `write()` returns the byte count and `seek()` the new position; paramiko's files return `None` for both. fsfast files also always have `.size`, which smbclient and paramiko files lack: fsspec's `read_block` fails on those references.
- **Not subclasses of the references.** The classes are not subclasses of the reference classes, unlike `fsfast.LocalFileSystem`. s3fs, gcsfs and adlfs are optional dependencies; importing fsspec's smb/sftp/http modules would pull in smbprotocol, paramiko and aiohttp.

### s3
- **Recursive mv of a directory.** s3fs `mv(dir, dir2, recursive=True)` copies the tree, then raises `FileNotFoundError` copying the directory entry, and leaves the source in place. fsfast moves the tree.
- **open of a prefix.** s3fs opens it as an empty file; fsfast raises `FileNotFoundError`.
- **cat_file past EOF** returns `b""`.
- **rm.** `rm` returns the list of keys it deleted. Deletes never report missing keys (`strict_delete=False` by default, matching DeleteObjects).
- **find directory dicts.** The directory dicts that `find` derives use s3fs's find key order, `Key, Size, name, StorageClass, type, size`. They go into the listings cache, as in s3fs.
- **Not provided:**
  - `session=` (an aiobotocore session) raises `NotImplementedError`.
  - `mkdir(acl=...)` is not supported.
  - `url()` only supports `client_method="get_object"`.
  - `merge`, `get_delegated_s3pars`, `clear_multipart_uploads` and `list_multipart_uploads` raise `NotImplementedError`.
  - `invalidate_region_cache()` is a no-op: regions are cached and re-resolved in Rust.
- **Provided:**
  - `get_tags`/`put_tags` (modes `o`/`m`), `metadata`, `getxattr`, `setxattr` (in place, keeps the content type), `chmod`;
  - `url`/`sign` (SigV4 presigned GET), `checksum`, `modified` (`IsADirectoryError` for prefixes);
  - `object_version_info` and `ls(versions=True)` (version_aware), `is_bucket_versioned`/`make_bucket_versioned`;
  - `find(prefix=...)`, `split_path`, `cat_file(path, version_id, start, end)`.
- **botocore values are translated.** `botocore.UNSIGNED` and `botocore.config.Config` objects in `config_kwargs`/`client_kwargs` become plain values.

### gs
- **Key order of object dicts.** Object dicts hold the server's JSON fields in the server's order, which fsfast cannot observe (the Rust map is sorted). fsfast uses the field order of Google's JSON API, so key order is not compared for GCS; keys and values are. fake-gcs-server sends a different order.
- **open of a prefix.** gcsfs opens it as an empty object; fsfast raises `FileNotFoundError`.
- **Not provided:**
  - `setxattrs` (object PATCH) raises `NotImplementedError`;
  - `ls`/`find` with `versions=`;
  - `mkdir` with `location`, `enable_versioning` or other bucket settings.
- **ls/find with prefix=** give gcsfs's results (same entries, the same find-directory dicts, prefixed listings are not cached). fsfast filters a listing of the directory instead of sending gcsfs's narrower prefix request, so it transfers more for a narrow prefix of a large directory.
- **version_aware is fixed at construction.** It is part of the instance key; assigning `fs.version_aware = True` later does not make the backend parse `path#generation` (gcsfs reads the attribute on every call). Pass `version_aware=True` to the constructor.
- **The endpoint is resolved at construction** from `endpoint_url`, `$STORAGE_EMULATOR_HOST` and `$GOOGLE_CLOUD_UNIVERSE_DOMAIN`; gcsfs re-reads the environment on every request. `base`, `batch_url_base`, `on_google` and `url()` report the endpoint in use.
- **Write invalidation.** A write drops the cached listings of every ancestor; gcsfs drops only the parent when it is cached (never stale either way).
- **token.** google-auth user `Credentials` objects become their `authorized_user` dict, or else their access token. Other credential objects raise `NotImplementedError`.
- **Provided:** `url`, `merge` (compose), `getxattr`, `buckets`, `split_path`, `modified`/`created`, `mv_file` (rejects a destination generation like gcsfs), `on_google`, `base`, `batch_url_base`, and `open(..., metadata=..., fixed_key_metadata=..., content_type=...)`.

### abfs
- **open "ab".** adlfs appends only to append blobs (`ResourceExistsError` for a block blob). fsfast also appends to block blobs, by re-staging the existing blocks.
- **Transactions.** adlfs uploads on close even inside a transaction. fsfast defers the upload to the commit.
- **Recursive mv of a directory** fails in adlfs as in s3fs; fsfast moves the tree.
- **Opening a directory** fails in adlfs with `TypeError`; fsfast raises `IsADirectoryError`.
- **find mirrors adlfs** except for `maxdepth`: it never lists the root and returns `[path]` for a file, but it honours `maxdepth`, which adlfs ignores (fsspec's contract and its abstract test suite require it; with adlfs `cp`/`rm`/`get` with `maxdepth` act on the whole tree).
- **find(prefix=)** gives adlfs's result (names starting with `path/prefix`); fsfast filters the listing of `path` instead of listing with `name_starts_with`.
- **rm(dir) without recursive** leaves a non-empty directory in place, as adlfs does (it deletes only a blob named like the directory).
- **mkdir/makedir follow adlfs:** only containers are created; an existing container raises `FileExistsError` with `exist_ok=False` (the default of `makedir`); `create_parents=False` for a missing container raises `PermissionError`; with `assume_container_exists=None` a failed container probe warns and assumes the container exists.
- **ls of `"."`, `"*"`, `"/"`** lists the containers, as in adlfs.
- **blocksize** defaults to adlfs's 50 MiB (`fs.blocksize`, `f.blocksize`); the Rust handles keep their tuned defaults (8 MiB upload blocks and ranged reads) unless a block size is given. `anon` resolves `$AZURE_STORAGE_ANON` like adlfs.
- **Unknown constructor options** raise `ValueError`; adlfs keeps them in `fs.kwargs`.
- **content_settings** is azure's `ContentSettings` (with `content_md5` as a `bytearray`) when the Azure SDK is installed. Otherwise it is a dict with the same keys in the same order.
- **invalidate_cache(path)** also drops the ancestors' listings (adlfs drops only the path's).
- **rmdir copies adlfs.** A container path deletes the container, even a non-empty one, in one request (`delete_container`). Any path below a container, or a missing container, is a silent no-op. Covered by `test_rmdir_semantics`.
- **Stale listings after cp.** adlfs leaves the destination's cached listing stale after `copy`/`cp_file`. fsfast invalidates it, so `ls` shows the copy.
- **credential.** azure-core credential objects are converted:
  - `AzureNamedKeyCredential` becomes a shared key;
  - `AzureSasCredential` becomes a SAS;
  - a sync `TokenCredential` becomes a bearer token fetched at construction, which is not refreshed.
  - Async credentials raise `NotImplementedError`.
- **Not provided:**
  - `ls(versions=...)`/`version_id`;
  - `url(content_*=...)` overrides;
  - the adlfs file attribute `f.metadata` (lazy blob metadata) and `f.version_id` after a write.
- **Provided:** `url`/`sign` (SAS), `getxattr`, `setxattrs`, `makedir`, `split_path`, `modified`/`created`, `content_settings=` (dict or `ContentSettings`) on `open`/`pipe_file`/`put_file`/`put`, `metadata=` on `open`, `overwrite=False` on `pipe_file`/`put_file`. Inside a transaction the per-call settings of a spooled write are not applied (the upload at commit goes through `put_file`).

### smb
- **Errors.** smbclient raises `SMBOSError`, an `OSError` that is not a `FileNotFoundError`. fsfast raises the precise subclass with the same errno: the tests compare errnos.
- **cp_file and copy.** fsspec smb has no `cp_file` (`NotImplementedError`), and `copy(recursive=True)` fails with `TypeError`. fsfast copies server-side with `FSCTL_SRV_COPYCHUNK`.
- **created()** can differ by 1 µs. fsspec rounds a float timestamp; fsfast truncates the exact FILETIME.
- **glob matches directories.** fsspec's smb `glob("dir/*")` never matches a subdirectory (its find keys directories as `"dir/sub/"`, which the pattern does not match), so `get`/`cp`/`rm` of a glob with `recursive=True` silently skip them. fsfast matches directories, named without the trailing `/`, as fsspec's glob does on every other backend and as fsspec's abstract test suite requires.
- **share_access** is per filesystem. Overriding it in `open()` raises `NotImplementedError`.
- **put/copy create directories.** `put`/`put_file` create parent directories, as fsspec's generic `put_file` does, and `copy` creates the target directories.
- **Extra:** `connection_info(share)`.

### sftp
- **Not supported by fsspec's sftp, supported by fsfast:**
  - `cp_file`/`copy` (`NotImplementedError` in fsspec); fsfast uses `copy-data@openssh.com` or a pipelined stream;
  - `put(recursive=True)` of a tree with subdirectories (`IsADirectoryError` in fsspec);
  - `mv(..., recursive=...)`, where fsspec raises `TypeError` for the keyword.
- **Open modes.** fsfast files support `rb`, `wb`, `ab` and `xb`. paramiko's `r+b` and other update modes are not supported.
- **host_key_policy and pkey.** `host_key_policy` accepts the names or the paramiko policy classes and instances. `pkey` accepts key text or a paramiko `PKey`. `sock` and `transport_factory` objects cannot be used.
- **Extras:** `chmod`, `symlink`, `readlink`, `realpath`.

### http
- **Listing order.** fsspec http builds listings from a set, so their order is arbitrary. fsfast sorts them, and the tests compare them sorted.
- **Writing.** fsspec http cannot open files for writing. fsfast PUTs them (`method="post"` to POST), and transactions upload at commit.
- **modified()** reads `Last-Modified`; fsspec http raises `NotImplementedError`.
- **Recursive get of a directory page** fails in both, with different `OSError` subclasses.
- **get_client** (an aiohttp session factory) raises `NotImplementedError`.
- **du()** asks `info()` for every file in one concurrent batch, as fsspec's async `du` does one by one.

## Fixes made in backend crates

- **fsfast-http** (`crates/fsfast-http/src/info.rs`, `requote`): `info()["url"]` left a `%` that does not start an escape unescaped. yarl, and so fsspec, writes it as `%25`. This showed for names containing `%`. A unit test (`requote_escapes_a_lone_percent_like_yarl`) checks yarl's outputs.
- **fsfast-azure** (`crates/fsfast-azure/src/write.rs`, `BlobHeaders::from_options`): a per-call `metadata` option (adlfs `open(..., metadata=...)`) was rejected as unknown; it is now merged into the blob's metadata. Unit test `write::tests::metadata_from_extra`.

The upstream compliance runs that found these are in [compliance.md](compliance.md).

## Recursive copy of a tree onto or into itself

`copy(src, dst, recursive=True)` with `dst == src` or `dst` inside `src` is
undefined. fsspec expands the source while writing into it, so its result
depends on iteration order (for the memory filesystem it can turn a copied
subdirectory into an empty file). fsfast does not reproduce that; the
stateful parity tests skip this case, as they already did for `mv` into
itself.
