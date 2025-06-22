# Kernel-Level Anti-Cheat with Server-Side Offset Verification

This project implements an anti-cheat system for Unreal Engine games, using a kernel-mode driver for local integrity checks and server-side verification of encrypted offsets to prevent hacking.

## Overview
The system ensures offsets (critical game memory addresses) are protected by encrypting them with AES-256-GCM and verifying them on a secure server over HTTPS with TLS 1.3. The kernel driver detects tampering attempts like debuggers.

- **AntiCheatDriver.cpp**: Kernel-mode driver that performs periodic integrity checks (e.g., debugger detection).
- **AntiCheatUser.cpp**: User-mode component that encrypts offsets and sends them to the server for verification, while triggering driver integrity checks.
- **AntiCheatCommon.h**: Shared header defining IOCTL codes.
- **AntiCheatServer.py**: Python Flask server that verifies encrypted offsets.

## Changes
- Offset verification moved to the server, using AES-256-GCM encryption with nonces and timestamps.
- Kernel driver now focuses on anti-tampering (e.g., debugger detection).
- Client communicates with the server over HTTPS with TLS 1.3.
- Removed deprecated files (`AntiCheatUser.c`, `AntiCheatDriver.c`).

## Security Notes
- **Session Key**: Currently hardcoded for simplicity. In production, derive keys dynamically using ECDH during the client-server handshake.
- **TLS**: The server uses a self-signed certificate (`cert.pem`, `key.pem`) for testing. Use a trusted CA certificate in production.
- **Nonces/Timestamps**: Prevent replay attacks by tracking nonces and validating timestamps.
- **Server Security**: Harden the server against DDoS and ensure secure key storage.

## Build Instructions
- **Driver**:
  - Install Windows Driver Kit (WDK).
  - Build `AntiCheatDriver.cpp` as a `.sys` file using Visual Studio with WDK.
- **User-Mode**:
  - Compile `AntiCheatUser.cpp` with MSVC, linking against `winhttp.lib` and `bcrypt.lib`.
- **Server**:
  - Install Python 3, Flask (`pip install flask`), and cryptography (`pip install cryptography`).
  - Generate a self-signed certificate:
    ```bash
    openssl req -x509 -newkey rsa:2048 -nodes -out cert.pem -keyout key.pem -days 365
    ```
  - Run `AntiCheatServer.py` with Python.

## Usage
1. Load the driver using a driver loader or test signing.
2. Start the server (`python AntiCheatServer.py`).
3. Run `AntiCheatUser.exe` to begin offset verification and integrity checks.
4. Monitor driver logs with DebugView and server responses in the console.

## Integration with Unreal Engine
- Replace `g_offsets` in `AntiCheatUser.cpp` with game-specific memory addresses (e.g., player health).
- Call `SendOffsetToServer` from the game loop or a dedicated thread.
- Update `EXPECTED_OFFSETS` in `AntiCheatServer.py` to match game offsets.
- Implement ECDH key exchange in the client and server for dynamic session keys.

## Next Steps
- Implement ECDH for session key derivation.
- Add client binary obfuscation to prevent reverse-engineering.
- Enhance server with rate-limiting and ban logic for repeated tampering.
- Integrate with Unreal Engine’s networking layer for seamless operation.