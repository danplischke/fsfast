#!/usr/bin/env python3
"""Generate reference test vectors for fsfast-smb-proto from the Python SMB
stack (smbprotocol 1.17 + pyspnego 0.12) installed in the repository's .venv.

Run from the repository root:

    . .venv/bin/activate
    python -I crates/fsfast-smb-proto/tests/reference/gen_vectors.py \
        > crates/fsfast-smb-proto/src/reference_vectors.rs

Every input that is normally random (NTLM client challenge and session key,
SMB salts, AEAD nonces, GUIDs) is pinned so the output is deterministic. The
Rust tests in src/reference_tests.rs feed the same inputs to the Rust codec and
compare the bytes.
"""

import hashlib
import os
import struct
import sys
import uuid

import spnego
import spnego._ntlm as sp_ntlm
from spnego._ntlm_raw import messages as ntlm_msgs
from spnego._ntlm_raw.crypto import rc4k, sealkey, signkey, RC4Handle
from spnego._ntlm_raw.security import sign as ntlm_sign
from spnego._spnego import NegTokenResp, NegState, pack_mech_type_list, unpack_token

from smbprotocol import connection as smbconn
from smbprotocol import create_contexts as cc
from smbprotocol import ioctl as smbioctl
from smbprotocol import open as smbopen
from smbprotocol import session as smbsession
from smbprotocol import tree as smbtree
from smbprotocol import file_info as fi
from smbprotocol import query_info as qi
from smbprotocol.header import Commands, SMB2HeaderRequest, Smb2Flags

OUT = []


def emit(name, value, comment=None):
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).hex()
    if comment:
        OUT.append(f"/// {comment}")
    OUT.append(f'pub(crate) const {name}: &str = "{value}";')


class FixedRandom:
    """os.urandom replacement returning pinned values by requested length."""

    def __init__(self, table):
        self.table = table

    def __call__(self, n):
        return self.table[n]


# ---------------------------------------------------------------------------
# NTLM + SPNEGO (pyspnego)
# ---------------------------------------------------------------------------

NTLM_USER = "DOMAIN\\User"
NTLM_PASSWORD = "Password"
NTLM_WORKSTATION = "FSFAST-WS"
NTLM_SPN_HOST = "server.domain.test"
CLIENT_CHALLENGE = bytes([0xAA] * 8)
EXPORTED_KEY = bytes([0x55] * 16)
SERVER_CHALLENGE = bytes.fromhex("0123456789abcdef")
SERVER_TIME = 133_500_000_000_000_000  # a FILETIME in 2024


def ntlm_vectors():
    ntlm_msgs.Version.get_current = staticmethod(lambda: ntlm_msgs.Version(10, 0, 19041, 15))
    sp_ntlm._get_workstation = lambda: NTLM_WORKSTATION
    sp_ntlm.os.urandom = FixedRandom({8: CLIENT_CHALLENGE, 16: EXPORTED_KEY})

    info = ntlm_msgs.TargetInfo()
    info[ntlm_msgs.AvId.nb_domain_name] = "DOMAIN"
    info[ntlm_msgs.AvId.nb_computer_name] = "SERVER"
    info[ntlm_msgs.AvId.dns_domain_name] = "domain.test"
    info[ntlm_msgs.AvId.dns_computer_name] = "server.domain.test"
    info[ntlm_msgs.AvId.timestamp] = ntlm_msgs.FileTime.unpack(struct.pack("<Q", SERVER_TIME))
    flags = 0xE28A8235  # client defaults | TARGET_INFO | TARGET_TYPE_DOMAIN, minus OEM
    challenge = ntlm_msgs.Challenge(
        flags,
        SERVER_CHALLENGE,
        target_name="DOMAIN",
        target_info=info,
        version=ntlm_msgs.Version(10, 0, 20348, 15),
    ).pack()

    # Raw NTLM.
    c = spnego.client(NTLM_USER, NTLM_PASSWORD, service="cifs", hostname=NTLM_SPN_HOST, protocol="ntlm",
                      options=spnego.NegotiateOptions.session_key)
    negotiate = c.step()
    authenticate = c.step(challenge)
    emit("NTLM_NEGOTIATE", negotiate, "pyspnego NEGOTIATE_MESSAGE (version 10.0.19041 rev 15)")
    emit("NTLM_CHALLENGE", challenge, "CHALLENGE_MESSAGE with MsvAvTimestamp")
    emit("NTLM_AUTHENTICATE", authenticate, "pyspnego AUTHENTICATE_MESSAGE (client challenge AA.., key 55..)")
    emit("NTLM_SESSION_KEY", c.session_key)

    # SPNEGO.
    s = spnego.client(NTLM_USER, NTLM_PASSWORD, service="cifs", hostname=NTLM_SPN_HOST, protocol="negotiate",
                      options=spnego.NegotiateOptions.session_key)
    init = s.step()
    resp1 = NegTokenResp(
        neg_state=NegState.accept_incomplete,
        supported_mech="1.3.6.1.4.1.311.2.2.10",
        response_token=challenge,
    ).pack()
    out2 = s.step(resp1)
    emit("SPNEGO_INIT", init, "pyspnego NegTokenInit (GSS framed)")
    emit("SPNEGO_CHALLENGE", resp1, "server NegTokenResp carrying the CHALLENGE")
    emit("SPNEGO_AUTH", out2, "pyspnego NegTokenResp carrying AUTHENTICATE + mechListMIC")
    # Server's final mechListMIC over the MechTypeList with the
    # server-to-client keys.
    mech_list = pack_mech_type_list(["1.3.6.1.4.1.311.2.2.10"])
    auth = ntlm_msgs.Authenticate.unpack(unpack_token(out2).response_token)
    key = s.session_key
    handle = RC4Handle(sealkey(auth.flags, key, "accept"))
    server_mic = ntlm_sign(auth.flags, handle, signkey(auth.flags, key, "accept"), 0, mech_list)
    final = NegTokenResp(neg_state=NegState.accept_complete, mech_list_mic=server_mic).pack()
    assert s.step(final) is None and s.complete
    emit("SPNEGO_FINAL", final, "server accept-completed NegTokenResp with mechListMIC")
    emit("SPNEGO_SESSION_KEY", s.session_key)


# ---------------------------------------------------------------------------
# SMB crypto (smbprotocol)
# ---------------------------------------------------------------------------

SESSION_KEY_16 = bytes(range(0x10, 0x20))
SESSION_KEY_32 = bytes(range(0x40, 0x60))  # e.g. a Kerberos AES-256 session key
PREAUTH = hashlib.sha512(b"fsfast preauth").digest()


class FakeConn:
    """Just enough of smbprotocol.connection.Connection for its crypto."""

    _generate_signature = smbconn.Connection._generate_signature
    _encrypt = smbconn.Connection._encrypt

    def __init__(self, dialect, signing_algorithm_id=None, cipher_id=None):
        self.dialect = dialect
        self.signing_algorithm_id = signing_algorithm_id
        self.cipher_id = cipher_id


class FakeSession:
    def __init__(self, session_id, key):
        self.session_id = session_id
        self.encryption_key = key


def kdf(ki, label, ctx, length=16):
    return smbsession.Session._smb3kdf(None, ki, label, ctx, length)


def header_message(command, body, message_id, flags=0, session_id=0x0000100000000005, tree_id=7):
    h = SMB2HeaderRequest()
    h["credit_charge"] = 1
    h["command"] = command
    h["credit_request"] = 64
    h["message_id"] = message_id
    h["session_id"] = session_id
    h["tree_id"] = tree_id
    h["flags"] = flags
    h["data"] = body
    return h.pack()


def crypto_vectors():
    D = smbconn.Dialects
    S = smbconn.SigningAlgorithms
    C = smbconn.Ciphers
    emit("KDF_SESSION_KEY_16", SESSION_KEY_16)
    emit("KDF_SESSION_KEY_32", SESSION_KEY_32)
    emit("KDF_PREAUTH", PREAUTH)
    # SMB 3.0/3.0.2 key derivation.
    emit("KEYS_302_SIGNING", kdf(SESSION_KEY_16, b"SMB2AESCMAC\x00", b"SmbSign\x00"))
    emit("KEYS_302_APP", kdf(SESSION_KEY_16, b"SMB2APP\x00", b"SmbRpc\x00"))
    emit("KEYS_302_ENC", kdf(SESSION_KEY_16, b"SMB2AESCCM\x00", b"ServerIn \x00"))
    emit("KEYS_302_DEC", kdf(SESSION_KEY_16, b"SMB2AESCCM\x00", b"ServerOut\x00"))
    # SMB 3.1.1 key derivation (128-bit cipher; signing/app keys use the
    # 16-byte SessionKey, the 256-bit cipher keys the full session key).
    emit("KEYS_311_SIGNING", kdf(SESSION_KEY_32[:16], b"SMBSigningKey\x00", PREAUTH))
    emit("KEYS_311_APP", kdf(SESSION_KEY_32[:16], b"SMBAppKey\x00", PREAUTH))
    emit("KEYS_311_ENC128", kdf(SESSION_KEY_32[:16], b"SMBC2SCipherKey\x00", PREAUTH))
    emit("KEYS_311_DEC128", kdf(SESSION_KEY_32[:16], b"SMBS2CCipherKey\x00", PREAUTH))
    emit("KEYS_311_ENC256", kdf(SESSION_KEY_32, b"SMBC2SCipherKey\x00", PREAUTH, 32))
    emit("KEYS_311_DEC256", kdf(SESSION_KEY_32, b"SMBS2CCipherKey\x00", PREAUTH, 32))

    # Preauth integrity chain over three messages.
    h = b"\x00" * 64
    for m in [b"negotiate request", b"negotiate response", b"session setup request"]:
        h = hashlib.sha512(h + m).digest()
    emit("PREAUTH_CHAIN", h)

    # Signing a TREE_CONNECT request (and a response / CANCEL for GMAC).
    tc = smbtree.SMB2TreeConnectRequest()
    tc["buffer"] = "\\\\server\\share".encode("utf-16-le")
    body = tc.pack()
    signed = Smb2Flags.SMB2_FLAGS_SIGNED
    msg = header_message(Commands.SMB2_TREE_CONNECT, body, 9, signed)
    emit("SIGN_MESSAGE", msg, "TREE_CONNECT request, signature field zero")
    key = bytes(range(0xA0, 0xB0))
    emit("SIGN_KEY", key)
    emit("SIGN_HMAC", FakeConn(D.SMB_2_1_0)._generate_signature(msg, key, 9, False, Commands.SMB2_TREE_CONNECT))
    emit("SIGN_CMAC", FakeConn(D.SMB_3_0_2)._generate_signature(msg, key, 9, False, Commands.SMB2_TREE_CONNECT))
    emit("SIGN_GMAC", FakeConn(D.SMB_3_1_1, S.AES_GMAC)._generate_signature(msg, key, 9, False, Commands.SMB2_TREE_CONNECT))
    resp = header_message(Commands.SMB2_TREE_CONNECT, body, 9, signed | Smb2Flags.SMB2_FLAGS_SERVER_TO_REDIR)
    emit("SIGN_GMAC_RESPONSE_MESSAGE", resp)
    emit("SIGN_GMAC_RESPONSE", FakeConn(D.SMB_3_1_1, S.AES_GMAC)._generate_signature(resp, key, 9, True, Commands.SMB2_TREE_CONNECT))
    cancel = header_message(Commands.SMB2_CANCEL, smbconn.SMB2CancelRequest().pack(), 10, signed)
    emit("SIGN_GMAC_CANCEL_MESSAGE", cancel)
    emit("SIGN_GMAC_CANCEL", FakeConn(D.SMB_3_1_1, S.AES_GMAC)._generate_signature(cancel, key, 10, False, Commands.SMB2_CANCEL))

    # Encryption of the same (unsigned) message.
    plain = header_message(Commands.SMB2_TREE_CONNECT, body, 9)
    emit("ENC_PLAINTEXT", plain)
    sid = 0x0000100000000005
    nonce16 = bytes(range(0xC0, 0xD0))
    cases = [
        ("ENC_AES128CCM_30", D.SMB_3_0_2, None, KEYS(16)),
        ("ENC_AES128CCM", D.SMB_3_1_1, C.AES_128_CCM, KEYS(16)),
        ("ENC_AES128GCM", D.SMB_3_1_1, C.AES_128_GCM, KEYS(16)),
        ("ENC_AES256CCM", D.SMB_3_1_1, C.AES_256_CCM, KEYS(32)),
        ("ENC_AES256GCM", D.SMB_3_1_1, C.AES_256_GCM, KEYS(32)),
    ]
    for name, dialect, cipher, k in cases:
        smbconn.os.urandom = lambda n: nonce16[:n]
        hdr = FakeConn(dialect, cipher_id=cipher)._encrypt(plain, FakeSession(sid, k))
        emit(name, hdr.pack())
    emit("ENC_KEY16", KEYS(16))
    emit("ENC_KEY32", KEYS(32))
    emit("ENC_NONCE", nonce16)


def KEYS(n):
    return bytes(range(0x30, 0x30 + n))


# ---------------------------------------------------------------------------
# Message bodies (smbprotocol Structure.pack)
# ---------------------------------------------------------------------------

FILE_ID = struct.pack("<QQ", 0x0102030405060708, 0x1112131415161718)
CLIENT_GUID = uuid.UUID(bytes=bytes(range(16)))
SERVER_GUID = uuid.UUID(bytes=bytes(range(0x20, 0x30)))
GSS_HINT = bytes.fromhex("6006 0604 2a030405".replace(" ", ""))


def neg_context(ctype, data, last=False):
    ctx = smbconn.SMB2NegotiateContextRequest()
    ctx["context_type"] = ctype
    ctx["data"] = data
    if last:
        ctx["padding"].size = 0
        ctx["padding"] = b""
    return ctx


def create_ctx(name, data):
    c = cc.SMB2CreateContextRequest()
    c["buffer_name"] = name
    c["buffer_data"] = data
    return c


def message_vectors():
    T = smbconn.NegotiateContextType
    # NEGOTIATE request with every context a client sends.
    neg = smbconn.SMB3NegotiateRequest()
    neg["dialects"] = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]
    neg["security_mode"] = 1
    neg["capabilities"] = 0x47
    neg["client_guid"] = CLIENT_GUID
    pre = smbconn.SMB2PreauthIntegrityCapabilities()
    pre["hash_algorithms"] = [1]
    pre["salt"] = bytes(range(32))
    enc = smbconn.SMB2EncryptionCapabilities()
    enc["ciphers"] = [2, 1, 4, 3]
    net = smbconn.SMB2NetnameNegotiateContextId()
    net["net_name"] = "server"
    sig = smbconn.SMB2SigningCapabilities()
    sig["signing_algorithms"] = [2, 1, 0]
    neg["negotiate_context_list"] = [
        neg_context(T.SMB2_PREAUTH_INTEGRITY_CAPABILITIES, pre),
        neg_context(T.SMB2_ENCRYPTION_CAPABILITIES, enc),
        neg_context(T.SMB2_NETNAME_NEGOTIATE_CONTEXT_ID, net),
        neg_context(T.SMB2_SIGNING_CAPABILITIES, sig, last=True),
    ]
    emit("MSG_NEGOTIATE_REQ", neg.pack())

    ss = smbsession.SMB2SessionSetupRequest()
    ss["security_mode"] = 1
    ss["capabilities"] = 1
    ss["buffer"] = b"\x60\x10" + bytes(range(16))
    emit("MSG_SESSION_SETUP_REQ", ss.pack())

    tc = smbtree.SMB2TreeConnectRequest()
    tc["buffer"] = "\\\\server\\share".encode("utf-16-le")
    emit("MSG_TREE_CONNECT_REQ", tc.pack())

    mxac = cc.SMB2CreateQueryMaximalAccessRequest()
    mxac["timestamp"] = ntlm_msgs.FileTime.unpack(struct.pack("<Q", SERVER_TIME))
    lease = cc.SMB2CreateRequestLeaseV2()
    lease["lease_key"] = bytes(range(0x80, 0x90))
    lease["lease_state"] = 7
    lease["lease_flags"] = 4
    lease["parent_lease_key"] = bytes(range(0x90, 0xA0))
    lease["epoch"] = 3
    dh2q = cc.SMB2CreateDurableHandleRequestV2()
    dh2q["timeout"] = 60000
    dh2q["flags"] = 0
    dh2q["create_guid"] = uuid.UUID(bytes=bytes(range(0x50, 0x60)))
    alsi = cc.SMB2CreateAllocationSize()
    alsi["allocation_size"] = 1 << 20
    ctxs = [
        create_ctx(b"MxAc", mxac.pack()),
        create_ctx(b"RqLs", lease.pack()),
        create_ctx(b"DH2Q", dh2q.pack()),
        create_ctx(b"AlSi", alsi.pack()),
    ]
    cr = smbopen.SMB2CreateRequest()
    cr["requested_oplock_level"] = 0xFF
    cr["impersonation_level"] = 2
    cr["desired_access"] = 0x0012019F
    cr["file_attributes"] = 0x80
    cr["share_access"] = 7
    cr["create_disposition"] = 3
    cr["create_options"] = 0x40
    cr["buffer_path"] = "dir\\file.txt".encode("utf-16-le")
    cr["buffer_contexts"] = cc.SMB2CreateContextRequest.pack_multiple(ctxs)
    emit("MSG_CREATE_REQ", cr.pack())

    cl = smbopen.SMB2CloseRequest()
    cl["flags"] = 1
    cl["file_id"] = FILE_ID
    emit("MSG_CLOSE_REQ", cl.pack())

    rd = smbopen.SMB2ReadRequest()
    rd["padding"] = 0x50
    rd["length"] = 65536
    rd["offset"] = 4096
    rd["file_id"] = FILE_ID
    rd["minimum_count"] = 1
    emit("MSG_READ_REQ", rd.pack())

    wr = smbopen.SMB2WriteRequest()
    wr["offset"] = 8192
    wr["file_id"] = FILE_ID
    wr["buffer"] = b"hello world"
    emit("MSG_WRITE_REQ", wr.pack())

    qd = smbopen.SMB2QueryDirectoryRequest()
    qd["file_information_class"] = 37
    qd["flags"] = 1
    qd["file_id"] = FILE_ID
    qd["buffer"] = "*".encode("utf-16-le")
    qd["output_buffer_length"] = 65536
    emit("MSG_QUERY_DIRECTORY_REQ", qd.pack())

    q = smbopen.SMB2QueryInfoRequest()
    q["info_type"] = 1
    q["file_info_class"] = 18
    q["output_buffer_length"] = 4096
    q["file_id"] = FILE_ID
    emit("MSG_QUERY_INFO_REQ", q.pack())

    rn = fi.FileRenameInformation()
    rn["replace_if_exists"] = True
    rn["file_name"] = "new\\name.txt".encode("utf-16-le")
    si = smbopen.SMB2SetInfoRequest()
    si["info_type"] = 1
    si["file_info_class"] = 10
    si["file_id"] = FILE_ID
    si["buffer"] = rn.pack()
    emit("MSG_SET_INFO_RENAME_REQ", si.pack())

    vni = smbioctl.SMB2ValidateNegotiateInfoRequest()
    vni["capabilities"] = 0x47
    vni["guid"] = CLIENT_GUID
    vni["security_mode"] = 1
    vni["dialects"] = [0x0300, 0x0302]
    io = smbioctl.SMB2IOCTLRequest()
    io["ctl_code"] = 0x00140204
    io["file_id"] = b"\xff" * 16
    io["max_input_response"] = 0
    io["max_output_response"] = 24
    io["flags"] = 1
    io["buffer"] = vni.pack()
    emit("MSG_IOCTL_VNI_REQ", io.pack())

    cpy = smbioctl.SMB2SrvCopyChunkCopy()
    cpy["source_key"] = bytes(range(24))
    chunk = smbioctl.SMB2SrvCopyChunk()
    chunk["source_offset"] = 0
    chunk["target_offset"] = 1 << 20
    chunk["length"] = 1 << 20
    cpy["chunks"] = [chunk]
    emit("FSCTL_COPYCHUNK", cpy.pack())

    fl = smbopen.SMB2FlushRequest()
    fl["file_id"] = FILE_ID
    emit("MSG_FLUSH_REQ", fl.pack())
    emit("MSG_ECHO_REQ", smbconn.SMB2Echo().pack())
    emit("MSG_LOGOFF_REQ", smbsession.SMB2Logoff().pack())
    emit("MSG_TREE_DISCONNECT_REQ", smbtree.SMB2TreeDisconnect().pack())
    emit("MSG_CANCEL_REQ", smbconn.SMB2CancelRequest().pack())

    from smbprotocol.change_notify import SMB2ChangeNotifyRequest
    chg = SMB2ChangeNotifyRequest()
    chg["flags"] = 1
    chg["output_buffer_length"] = 4096
    chg["file_id"] = FILE_ID
    chg["completion_filter"] = 0x17
    emit("MSG_CHANGE_NOTIFY_REQ", chg.pack())

    lk = smbopen.SMB2LockRequest()
    lk["file_id"] = FILE_ID
    el = smbopen.SMB2LockElement()
    el["offset"] = 0
    el["length"] = 100
    el["flags"] = 0x12
    lk["locks"] = [el]
    emit("MSG_LOCK_REQ", lk.pack())

    # ---- responses (decoded by the Rust codec) ----
    nr = smbconn.SMB2NegotiateResponse()
    nr["security_mode"] = 3
    nr["dialect_revision"] = 0x0311
    nr["server_guid"] = SERVER_GUID
    nr["capabilities"] = 0x2F
    nr["max_transact_size"] = 8388608
    nr["max_read_size"] = 8388608
    nr["max_write_size"] = 8388608
    nr["system_time"] = ntlm_msgs.FileTime.unpack(struct.pack("<Q", SERVER_TIME))
    nr["server_start_time"] = ntlm_msgs.FileTime.unpack(struct.pack("<Q", 0))
    nr["buffer"] = GSS_HINT
    pre_r = smbconn.SMB2PreauthIntegrityCapabilities()
    pre_r["hash_algorithms"] = [1]
    pre_r["salt"] = bytes(range(0x40, 0x60))
    enc_r = smbconn.SMB2EncryptionCapabilities()
    enc_r["ciphers"] = [2]
    sig_r = smbconn.SMB2SigningCapabilities()
    sig_r["signing_algorithms"] = [2]
    nr["negotiate_context_list"] = [
        neg_context(T.SMB2_PREAUTH_INTEGRITY_CAPABILITIES, pre_r),
        neg_context(T.SMB2_ENCRYPTION_CAPABILITIES, enc_r),
        neg_context(T.SMB2_SIGNING_CAPABILITIES, sig_r, last=True),
    ]
    emit("MSG_NEGOTIATE_RESP", nr.pack())

    tr = smbtree.SMB2TreeConnectResponse()
    tr["share_type"] = 1
    tr["share_flags"] = 0x8030
    tr["capabilities"] = 0x10
    tr["maximal_access"] = 0x001F01FF
    emit("MSG_TREE_CONNECT_RESP", tr.pack())

    mx_r = cc.SMB2CreateQueryMaximalAccessResponse()
    mx_r["query_status"] = 0
    mx_r["maximal_access"] = 0x001F01FF
    qf_r = cc.SMB2CreateQueryOnDiskIDResponse()
    qf_r["disk_file_id"] = 0xABCD
    qf_r["volume_id"] = 0x1234
    ls_r = cc.SMB2CreateResponseLeaseV2()
    ls_r["lease_key"] = bytes(range(0x80, 0x90))
    ls_r["lease_state"] = 3
    ls_r["flags"] = 0
    ls_r["parent_lease_key"] = b"\x00" * 16
    ls_r["epoch"] = 4
    dh_r = cc.SMB2CreateDurableHandleResponseV2()
    dh_r["timeout"] = 60000
    dh_r["flags"] = 0
    crr = smbopen.SMB2CreateResponse()
    crr["oplock_level"] = 0xFF
    crr["create_action"] = 2
    for i, f in enumerate(["creation_time", "last_access_time", "last_write_time", "change_time"]):
        crr[f] = ntlm_msgs.FileTime.unpack(struct.pack("<Q", SERVER_TIME + i * 10_000_000))
    crr["allocation_size"] = 4096
    crr["end_of_file"] = 11
    crr["file_attributes"] = 0x20
    crr["file_id"] = FILE_ID
    crr["buffer"] = cc.SMB2CreateContextRequest.pack_multiple([
        create_ctx(b"MxAc", mx_r.pack()),
        create_ctx(b"QFid", qf_r.pack()),
        create_ctx(b"RqLs", ls_r.pack()),
        create_ctx(b"DH2Q", dh_r.pack()),
    ])
    emit("MSG_CREATE_RESP", crr.pack())

    rr = smbopen.SMB2ReadResponse()
    rr["data_offset"] = 0x50
    rr["buffer"] = b"hello world"
    emit("MSG_READ_RESP", rr.pack())

    entries = []
    for i, name in enumerate(["a.txt", "longer-directory-name"]):
        e = fi.FileIdBothDirectoryInformation()
        e["file_index"] = 0
        for j, f in enumerate(["creation_time", "last_access_time", "last_write_time", "change_time"]):
            e[f] = ntlm_msgs.FileTime.unpack(struct.pack("<Q", SERVER_TIME + j * 10_000_000))
        e["end_of_file"] = 100 * (i + 1)
        e["allocation_size"] = 4096
        e["file_attributes"] = 0x10 if i else 0x20
        e["ea_size"] = 0
        e["short_name"] = "SHORT~1".encode("utf-16-le") if i else b""
        e["file_id"] = 1000 + i
        e["file_name"] = name.encode("utf-16-le")
        entries.append(e)
    blob = b""
    for i, e in enumerate(entries):
        b = e.pack()
        if i + 1 < len(entries):
            b += b"\x00" * ((8 - len(b) % 8) % 8)
            b = struct.pack("<I", len(b)) + b[4:]
        blob += b
    qdr = smbopen.SMB2QueryDirectoryResponse()
    qdr["buffer"] = blob
    emit("MSG_QUERY_DIRECTORY_RESP", qdr.pack())

    fa = fi.FileAllInformation()
    fa["basic_information"]["creation_time"] = SERVER_TIME
    fa["basic_information"]["file_attributes"] = 0x20
    fa["standard_information"]["allocation_size"] = 4096
    fa["standard_information"]["end_of_file"] = 11
    fa["standard_information"]["number_of_links"] = 1
    fa["internal_information"]["index_number"] = 77
    fa["access_information"]["access_flags"] = 0x001F01FF
    fa["mode_information"]["mode"] = 0x20
    fa["name_information"]["file_name"] = "\\dir\\file.txt".encode("utf-16-le")
    qir = smbopen.SMB2QueryInfoResponse()
    qir["buffer"] = fa.pack()
    emit("MSG_QUERY_INFO_ALL_RESP", qir.pack())

    vr = smbioctl.SMB2ValidateNegotiateInfoResponse()
    vr["capabilities"] = 0x2F
    vr["guid"] = SERVER_GUID
    vr["security_mode"] = 3
    vr["dialect"] = 0x0302
    ior = smbioctl.SMB2IOCTLResponse()
    ior["ctl_code"] = 0x00140204
    ior["file_id"] = b"\xff" * 16
    ior["buffer"] = vr.pack()
    ior["output_offset"] = 0x70
    ior["output_count"] = len(vr.pack())
    emit("MSG_IOCTL_VNI_RESP", ior.pack())

    ifs = []
    for idx, (fam, addr) in enumerate([(0x2, "192.168.1.10"), (0x17, "fe80:0000:0000:0000:0000:0000:0000:0001")]):
        n = smbioctl.SMB2NetworkInterfaceInfo()
        n["if_index"] = idx + 1
        n["capability"] = 1
        n["link_speed"] = 10_000_000_000
        st = smbioctl.SockAddrStorage()
        st["family"] = fam
        if fam == 0x2:
            a = smbioctl.SockAddrIn()
            a["port"] = 0
            a.set_ipaddress(addr)
        else:
            a = smbioctl.SockAddrIn6()
            a["port"] = 0
            a.set_ipaddress(addr)
        st["buffer"] = a
        n["sock_addr_storage"] = st
        ifs.append(n)
    ifs[0]["next"] = 152
    emit("FSCTL_NETWORK_INTERFACES", b"".join(i.pack() for i in ifs))

    from smbprotocol.exceptions import SMB2ErrorResponse, SMB2ErrorContextResponse, SMB2SymbolicLinkErrorResponse
    sym = SMB2SymbolicLinkErrorResponse()
    sym.set_name("\\??\\C:\\target\\dir", "target\\dir")
    sym["flags"] = 1
    sym["unparsed_path_length"] = 8
    ectx = SMB2ErrorContextResponse()
    ectx["error_context_data"] = sym.pack()
    er = SMB2ErrorResponse()
    er["error_context_count"] = 1
    er["error_data"] = [ectx]
    emit("MSG_ERROR_SYMLINK_RESP", er.pack())


def main():
    OUT.append("//! Reference vectors generated by `tests/reference/gen_vectors.py` from")
    OUT.append("//! smbprotocol 1.17 and pyspnego 0.12 with pinned randomness. Do not edit;")
    OUT.append("//! regenerate instead.")
    OUT.append("")
    ntlm_vectors()
    crypto_vectors()
    message_vectors()
    print("\n".join(OUT))


if __name__ == "__main__":
    main()
