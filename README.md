# Kernel-Level Anti-Cheat for Unreal Engine with real-time cryptographic offset server verification.

## Overview
This project contains a basic template for a Windows kernel-mode "cryptographic" anti-cheat driver and a user-mode loader/communicator, both written in C++. Intended for integration with Unreal Engine games.

## Files
- `AntiCheatDriver.cpp`: Kernel-mode driver source (C++)
- `AntiCheatUser.cpp`: User-mode loader/communicator (C++)

## Build Instructions
1. Install the Windows Driver Kit (WDK) for kernel driver development.
2. Build `AntiCheatDriver.cpp` as a kernel-mode driver (`.sys` file) using Visual Studio with WDK.
3. Build `AntiCheatUser.cpp` as a standard Windows console application.

## Next Steps
- Implement driver communication (IOCTLs) between user-mode and kernel-mode.
- Add anti-cheat logic (memory scanning, integrity checks, etc).
- Integrate with Unreal Engine as needed.

**Note:** Kernel development requires administrator privileges and can cause system instability if not handled carefully. Only test on non-production systems.
