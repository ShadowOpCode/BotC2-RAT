# BotC2 RAT: From Binary to C2 Emulation

**Reverse engineering of a native Windows x64 RAT, from its delivery chain and embedded configuration to Schannel TLS, command dispatching and laboratory C2 validation.**

Research by **ShadowOpCode**.

## Overview

BotC2 RAT is a native C++ implant with remote execution, desktop control, persistence, wallet discovery and clipboard address replacement capabilities. This research reconstructs its application logic and custom C2 protocol from the x64 binary, then validates core communication flows against a running sample in a controlled laboratory.

**“BotC2 RAT” is a descriptive label used in the report, not a confirmed public malware-family attribution.** The embedded `DGM` tag does not establish an actor identity.

## Delivery chain

The report documents an invoice-themed download page presenting `Nostra_fattura.pdf`, followed by a ZIP containing obfuscated JavaScript for Windows Script Host and an UpCrypter-associated PowerShell staging chain.

The PowerShell stage uses repeating XOR keys and Base64 encoding to conceal subsequent code. It also attempts AMSI and ETW tampering. These operations belong to the stager; their effectiveness was not established, and they should not be attributed to the native RAT itself.

## Implemented capabilities

| Capability | Findings |
| --- | --- |
| Remote execution | One-shot shell commands and a persistent interactive terminal with redirected input/output. |
| File execution and update | Staging and execution of supplied payloads; executable replacement is a branch of `FILE_RUN`, not a separate `UPDATE` command. |
| Persistence | HKCU Run-key or scheduled-task installation; this build selects the registry method. |
| Process injection | An `INJECT` handler associated with process hollowing; comprehensive runtime validation is not established. |
| Desktop control | Primary-display capture encoded as JPEG, plus mouse and keyboard input through `SendInput`. |
| Wallet discovery | Detection of installed desktop wallets and browser extensions, reported through `CRYPTO_FOUND`. |
| Clipboard manipulation | Configurable replacement of address-like clipboard text; the worker starts disabled with empty replacement targets. |

Wallet discovery does **not** demonstrate extraction of seeds, private keys or wallet contents. Likewise, remote keyboard input is not evidence of passive keylogging.

## C2 and networking

The implant uses **Winsock and Schannel TLS 1.2** over TCP port **8080**, with primary and fallback DDNS hosts. The application protocol is custom, not HTTP.

The report covers address resolution, socket configuration, the SSPI handshake, certificate-validation settings, encrypted transmission, receive buffering, application framing, heartbeat logic and reconnection. Control messages use JSON, while screen captures carry raw JPEG data. Application frames and TLS records do not necessarily share boundaries.

The examined Schannel configuration disables automatic certificate-chain and server-name checks; no subsequent manual validation or certificate pinning was identified. TLS encryption therefore does not establish robust authentication of the C2 server in this implementation.

## Runtime validation

The laboratory tests documented in the report demonstrate:

- TLS 1.2 session establishment and receipt of the implant's `HELLO` registration.
- Successful `SHELL_EXEC` execution, output retrieval and matching task identifiers for that exchange.
- Bidirectional interactive-terminal use and follow-on PowerShell execution.
- Receipt and local storage of screenshots through the screencast capability.

**The C2 emulation script will not be published**, as stated in the report.

## Key indicators

| Indicator | Value |
| --- | --- |
| RAT SHA-256 | `a5926522d7ce3a0073da79c5082da6644c742d6a34440bba3f5d878f03712938` |
| Primary C2 | `axwtexa[.]ddns[.]net` |
| Fallback C2 | `back001xtc[.]ddns[.]net` |
| Transport | TLS over TCP/8080 |
| Configuration marker | `BOTCFG` |
| Configuration tag | `DGM` |
| Installation path | `%LOCALAPPDATA%\Runtimebroker\Runtimebroker.exe` |
| Run key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| Run value | `Runtimebroker` |
| Mutex | `Local\BotC2Stub.SingleInstance` |

The PDF appendix contains additional delivery-stage indicators and two YARA rules covering the native code cluster and the analyzed embedded configuration. Broader benign-corpus validation remains pending. These indicators describe the analyzed build; they are not evidence that the listed infrastructure remains active.
