"""Triage of upstream tests run against fsfast (see docs/dev/compliance.md).

``TABLE[suite][key] = (kind, reason)``. ``key`` matches a test whose node
id ends with ``key`` (``file.py::test_name`` or ``::test_name``; a trailing
``*`` matches every parametrization). ``kind``:

``skip``
    the test exercises reference internals (the aiobotocore client
    ``fs.s3``, gcsfs's session, private helpers) or a feature fsfast does not
    offer; running it says nothing about fsfast.
``xfail``
    an intentional, documented deviation (docs/dev/python-parity.md).

Every entry must say why. Tests not listed must pass.
"""

from __future__ import annotations

import fnmatch

TABLE: dict[str, dict[str, tuple[str, str]]] = {
    "s3fs": {
        # --- reference internals: the aiobotocore client and s3fs helpers
        "::test_ssl_off": ("skip", "inspects the aiobotocore client (fs.s3)"),
        "::test_client_kwargs": ("skip", "inspects the aiobotocore client (fs.s3)"),
        "::test_config_kwargs": ("skip", "calls fs.connect() and inspects the botocore config"),
        "::test_config_kwargs_class_attributes_default": ("skip", "calls fs.connect() and inspects the botocore config"),
        "::test_config_kwargs_class_attributes_override": ("skip", "calls fs.connect() and inspects the botocore config"),
        "::test_idempotent_connect": ("skip", "inspects the aiobotocore client (fs.s3)"),
        "::test_multiple_objects": ("skip", "calls fs.connect() and compares aiobotocore clients"),
        "::test_checksum": ("skip", "patches the aiobotocore client (fs.s3)"),
        "::test_xattr": ("skip", "calls the aiobotocore client (fs.s3) to set object ACLs"),
        "::test_copy_managed": ("skip", "calls s3fs's private _copy_managed"),
        "::test_errors_cause_preservings": ("skip", "expects botocore exception classes as __cause__ and patches fs.s3"),
        "::test_listing_retries_transient_errors": ("skip", "patches the aiobotocore client (fs.s3)"),
        "::test_write_small_with_acl": ("skip", "reads the object ACL through the aiobotocore client (fs.s3)"),
        "::test_write_small_secure": ("skip", "reads the object through the aiobotocore client (fs.s3)"),
        "::test_write_blocks": ("skip", "inspects S3File.buffer"),
        "::test_no_connection_sharing_among_processes*": ("skip", "compares aiobotocore clients (fs.s3) across processes"),
        "::test_multipart_upload_blocksize": ("skip", "inspects S3File.parts"),
        "::test_default_pars": ("skip", "inspects S3File.fill_cache/cache internals"),
        "::test_append": ("skip", "inspects S3File.parts/_initiate_upload after its first checks (append tell() and content, which pass; covered in tests/python/test_net_s3.py)"),
        "::test_autocommit_mpu": ("skip", "inspects S3File.mpu"),
        "::test_requester_pays": ("skip", "calls s3fs's private _get_s3_method_kwargs"),
        "::test_requester_pays_per_file_override*": ("skip", "calls s3fs's private _get_s3_method_kwargs"),
        "::test_requester_pays_makedirs_uses_object_listing": ("skip", "overrides s3fs's private _call_s3"),
        "::test_credentials": ("skip", "inspects the aiobotocore client's credentials (fs.s3)"),
        "::test_async_s3": ("skip", "uses set_session()/the aiobotocore client"),
        "::test_async_s3_old": ("skip", "uses s3fs's private _connect()"),
        "::test_async_close": ("skip", "uses s3fs's private _connect()"),
        "::test_upload_parts": ("skip", "inspects S3File.buffer/parts"),
        "::test_upload_part_with_prime_pads": ("skip", "inspects S3File.buffer/parts"),
        "::test_invalidate_cache": ("skip", "overrides s3fs's private _call_s3"),
        "::test_session_close": ("skip", "uses set_session()/aiobotocore sessions"),
        "::test_set_session_sessions_none": ("skip", "uses set_session()/aiobotocore sessions"),
        "::test_set_session_concurrent_no_leak": ("skip", "uses set_session()/aiobotocore sessions"),
        "::test_set_session_preserves_injected_session": ("skip", "passes an aiobotocore session object"),
        "::test_set_session_closed_sessions_rebuilds_once": ("skip", "uses s3fs's private _s3/set_session"),
        "::test_user_session_is_preserved": ("skip", "passes an aiobotocore session object"),
        "::test_default_cache_type*": ("skip", "checks f.cache is an fsspec cache class; fsfast caches in Rust (cache_type is honoured)"),
        "::test_read_small": ("skip", "checks len(f.cache) (fsspec cache object); fsfast caches in Rust"),
        "::test_info": ("skip", "asserts info() returns the very dict object held in dircache (id()); fsfast returns equal values"),
        "::test_s3fs_etag_preserving_multipart_copy": ("skip", "patches s3fs.core.MANAGED_COPY_THRESHOLD and uses copy(preserve_etag=True), an s3fs-only option"),
        # --- features fsfast does not offer (docs/dev/python-parity.md)
        "::test_not_delegate": ("xfail", "get_delegated_s3pars is not implemented (NotImplementedError)"),
        "::test_merge": ("xfail", "merge (multipart copy) is not implemented"),
        "::test_list_del_multipart": ("xfail", "list/clear_multipart_uploads are not implemented"),
        "::test_pipe_exclusive_big": ("xfail", "checks for leftover uploads with list_multipart_uploads (not implemented)"),
        "::test_pipe_exclusive_big_after_small": ("xfail", "checks for leftover uploads with list_multipart_uploads (not implemented)"),
        "::test_put_exclusive_big": ("xfail", "checks for leftover uploads with list_multipart_uploads (not implemented)"),
        "::test_put_exclusive_big_after_small": ("xfail", "checks for leftover uploads with list_multipart_uploads (not implemented)"),
        "::test_put_exclusive_small": ("xfail", "checks for leftover uploads with list_multipart_uploads (not implemented)"),
        "::test_multi_checksum": ("xfail", "ChecksumAlgorithm= (flexible checksums) is not a supported S3 parameter"),
        "::test_xattr_setxattr_in_write_mode": ("xfail", "files have no setxattr() (metadata goes in open(..., Metadata=...))"),
        "::test_versions*": ("xfail", "write handles do not expose version_id"),
        "::test_fsspec_versions_multiple": ("xfail", "write handles do not expose version_id"),
        "::test_versioned_file_fullpath": ("xfail", "write handles do not expose version_id"),
        "::test_versions_unaware": ("xfail", "write handles do not expose version_id"),
        "::test_versions_dircached": ("xfail", "write handles do not expose version_id"),
        "::test_touch_versions": ("xfail", "write handles do not expose version_id"),
        "::test_version_sizes": ("xfail", "pipe_file returns None, not the PutObject response (VersionId)"),
        "::test_async_stream": ("xfail", "open_async (async file objects) is not implemented"),
        # --- intentional deviations (docs/dev/python-parity.md)
        "::test_with_size": ("xfail", "open(size=) is ignored: fsfast always reads the object's real size"),
        "::test_url": ("xfail", "url() presigns with SigV4 (X-Amz-Expires), botocore's default for moto is SigV2 (Expires)"),
        "::test_raise_exception_when_file_has_changed_during_reading*": ("xfail", "raises fsfast.PreconditionFailed (OSError), not s3fs.utils.FileExpired"),
    },
    "fsspec": {
        # --- local: reference internals
        "test_local.py::test_transaction_ends_when_a_commit_fails": ("skip", "patches LocalFileOpener.commit, which fsfast's files do not use"),
        "test_local.py::test_multiple_file_transaction_use_umask_cache": ("skip", "counts hits of fsspec's private get_umask cache"),
        "test_local.py::test_multiple_transactions_use_umask_cache": ("skip", "counts hits of fsspec's private get_umask cache"),
        "test_local.py::test_multiple_filesystems_use_umask_cache": ("skip", "counts hits of fsspec's private get_umask cache"),
        # --- memory: reference internals (the store dict / pseudo_dirs list)
        "test_memory.py::test_independent_store_from_config": ("skip", "inspects MemoryFileSystem.store (a Python dict; fsfast's store is in Rust)"),
        "test_memory.py::test_independent_store_pickle*": ("skip", "inspects MemoryFileSystem.store"),
        "test_memory.py::test_default_store_pickle": ("skip", "inspects MemoryFileSystem.store"),
        "test_memory.py::test_directories": ("skip", "inspects MemoryFileSystem.store"),
        "test_memory.py::test_find_snapshots_store_before_iterating": ("skip", "mutates MemoryFileSystem.store during iteration"),
        "test_memory.py::test_dir_errors": ("skip", "inspects MemoryFileSystem.pseudo_dirs (the error checks before it pass)"),
        "test_memory.py::test_mv_recursive_propagates_cp_file_errors": ("skip", "monkeypatches fs.cp_file; fsfast's mv copies in one Rust batch, not through cp_file"),
        # --- memory: write-mode files are not seekable (docs/dev/python-parity.md)
        "test_memory.py::test_no_rewind_append_mode": ("xfail", "text append mode needs a seekable binary file for tell(); fsfast write handles stream and are not seekable"),
        "test_memory.py::test_append_creates_missing_file[a]": ("xfail", "text append mode needs a seekable binary file; fsfast write handles are not seekable"),
        "test_memory.py::test_append_creates_missing_file[ab]": ("xfail", "seek(0, 2) on a write handle raises (write handles stream; a no-op seek would make zipfile assume it can seek back)"),
        # --- http: aiohttp internals
        "test_http.py::test_async_other_thread": ("skip", "uses set_session() (the aiohttp session)"),
        "test_http.py::test_async_this_thread": ("skip", "uses set_session() (the aiohttp session)"),
        "test_http.py::test_close*": ("skip", "uses close_session() and aiohttp/get_client internals"),
        "test_http.py::test_async_expand_path": ("skip", "uses fs._session"),
        "test_http.py::test_async_walk": ("skip", "uses fs._session"),
        "test_http.py::test_with_cache": ("skip", "wraps the file's private _fetch_range"),
        "test_http.py::test_exists_strict": ("skip", "expects aiohttp.ClientResponseError; fsfast raises PermissionError for 401"),
        "test_http.py::test_content_encoding_gzip": ("skip", "checks the file is fsspec's HTTPStreamFile class"),
        # --- http: intentional deviations / gaps (docs/dev/python-parity.md)
        "test_http.py::test_list_invalid_args": ("xfail", "an unknown option raises ValueError at construction (fsspec: TypeError from aiohttp at first request)"),
        "test_http.py::test_list_cache_with_expiry_time_cached": ("xfail", "HTTP listings are not cached in dircache (use_listings_cache is accepted and ignored)"),
        "test_http.py::test_list_cache_with_expiry_time_purged": ("xfail", "HTTP listings are not cached in dircache"),
        "test_http.py::test_list_cache_reuse": ("xfail", "HTTP listings are not cached in dircache"),
        "test_http.py::test_random_access[headers0]": ("xfail", "the test server answers a Range request with 200 and a partial body; fsfast treats a 200 as the full representation (RFC 9110) and slices it, fsspec trusts the body"),
        "test_http.py::test_random_access[headers1]": ("xfail", "the test server answers a Range request with 200 and a partial body; fsfast treats a 200 as the full representation (RFC 9110) and slices it, fsspec trusts the body"),
        "test_http.py::test_random_access[headers4]": ("xfail", "the test server answers a Range request with 200 and a partial body; fsfast treats a 200 as the full representation (RFC 9110) and slices it, fsspec trusts the body"),
        "test_http.py::test_no_range_support*": ("xfail", "fsfast reads a file from a server that ignores Range by slicing the full 200 body instead of raising ValueError; with this test server's partial 200 bodies the result differs"),
        "test_http.py::test_cat_file_range": ("xfail", "the test server answers a Range request with 200 and a partial body (see test_random_access)"),
        "test_http.py::test_cat_file_range_numpy": ("xfail", "the test server answers a Range request with 200 and a partial body (see test_random_access)"),
        "test_http.py::test_content_length_zero": ("xfail", "HEAD says Content-Length: 0 and fsfast trusts it (fsspec treats size 0 as unknown and streams)"),
        "test_http.py::test_mcat_expand": ("xfail", "fsfast's glob HEADs the directory URL; fsspec's test server crashes on HEAD /index/ and resets the connection"),
        "test_http.py::test_encoded": ("xfail", "per-call request keywords on cat (headers=...) are not forwarded"),
        "test_http.py::test_async_file": ("xfail", "open_async (async file objects) is not implemented"),
        # --- sftp (generated copy on the shared OpenSSH service)
        "test_sftp.py::test_mkdir_create_parent[/a/b/c]": ("skip", "creates /a at the server's root, which needs the docker container's root login"),
        "test_sftp.py::test_makedirs_exist_ok[/a/b/c]": ("skip", "creates /a at the server's root, which needs the docker container's root login"),
        "test_sftp.py::test_host_key_policy_default": ("skip", "replaces paramiko.SSHClient with a fake and inspects fs.client (fsfast's SSH client is Rust)"),
        "test_sftp.py::test_host_key_policy_by_name*": ("skip", "replaces paramiko.SSHClient with a fake and inspects fs.client"),
        "test_sftp.py::test_host_key_policy_passed_through*": ("skip", "replaces paramiko.SSHClient with a fake and inspects fs.client"),
        "test_sftp.py::test_host_key_policy_not_passed_to_connect": ("skip", "replaces paramiko.SSHClient with a fake and inspects its connect() arguments"),
    },
    "gcsfs": {},
    "adlfs": {},
}


def matches(key: str, nodeid: str) -> bool:
    """``nodeid`` ends with ``key``; ``*`` in ``key`` is a wildcard
    (brackets are literal)."""
    pattern = "*" + key.replace("[", "[[]")
    return fnmatch.fnmatchcase(nodeid, pattern)
