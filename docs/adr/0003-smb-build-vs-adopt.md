# ADR-0003: Build our own SMB 2/3 stack

- Status: accepted (revisit after the first benchmark round)
- Date: 2026-11-24

## Context

SMB is fsfast's flagship backend. The available options were:

1. **Wrap `libsmbclient` (Samba).** It is GPLv3, so it is incompatible with a
   permissively licensed wheel. Rejected.
2. **Adopt `smb-rs` (the `smb` crate, 0.12).** A pure-Rust SMB2/3 client with
   TCP/NetBIOS/QUIC transports and NTLM/Kerberos through `sspi`. It is young,
   its messages are parsed with `binrw` (which allocates per message), and its
   API is not built around the things our throughput targets depend on.
3. **Build our own** I/O-free codec (`fsfast-smb-proto`) and client
   (`fsfast-smb`).

Our targets (≥ 90% of line rate on 10 GbE with AES-GCM; ≥ 10× fsspec's `smb`
backend for metadata-heavy work) depend on things that are hard to retrofit
into someone else's client:

- credit-window management and many large READ/WRITE requests in flight;
- compounding for every metadata operation;
- buffer ownership end to end, including decrypting straight into the
  caller's buffer and vectored writes without copies;
- a connection/session/tree pool shared by concurrent Python threads.

## Decision

Build `fsfast-smb-proto` (no I/O: messages, MS-FSCC info classes, NTSTATUS
mapping, signing/encryption/KDF, NTLMv2 + SPNEGO) and `fsfast-smb` (transport,
credits, sessions, trees, handles, the `FileSystem` implementation).

- **NTLMv2 + SPNEGO are implemented natively.** They are small, well
  specified and testable against the published MS-NLMP vectors and against
  Samba.
- **Kerberos goes behind an `Authenticator` trait**, to be implemented with
  `sspi` or system GSSAPI in the "enterprise" milestone.
- **`smb-rs` is kept as a differential-interop oracle** and benchmark
  baseline, alongside the Linux kernel client and `smbclient`.

## Consequences

- More code to own, offset by spec traceability and testing against several
  servers (Samba first; Windows, Azure Files and ksmbd in the interop matrix).
- If `smb-rs` matures past our targets, the clean split between codec and
  client lets us swap or share components.
