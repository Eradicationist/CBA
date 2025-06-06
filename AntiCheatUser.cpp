// AntiCheatUser.cpp
// User-mode loader/communicator for kernel anti-cheat driver (C++)
#include <windows.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <setupapi.h>
#pragma comment(lib, "setupapi.lib")

// Function to create a mutex to ensure anti-cheat is running
HANDLE g_antiCheatMutex = NULL;
const wchar_t* ANTI_CHEAT_MUTEX_NAME = L"Global\\AntiCheatRunningMutex";

bool CreateAntiCheatMutex() {
    g_antiCheatMutex = CreateMutexW(NULL, TRUE, ANTI_CHEAT_MUTEX_NAME);
    if (g_antiCheatMutex == NULL) {
        std::cout << "[AntiCheat][User] Failed to create anti-cheat mutex!" << std::endl;
        return false;
    }
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        std::cout << "[AntiCheat][User] Another instance of the anti-cheat is already running." << std::endl;
        return false;
    }
    return true;
}

// Simulated critical offsets (should match driver)
#define NUM_OFFSETS 3
unsigned long g_criticalOffsets[NUM_OFFSETS] = {0x12345678, 0x87654321, 0xABCDEF01};
unsigned long g_expectedChecksums[NUM_OFFSETS] = {0};

unsigned long CalculateChecksum(unsigned long value) {
    return value ^ 0x5A5A5A5A;
}

void InitializeChecksums() {
    for (int i = 0; i < NUM_OFFSETS; ++i) {
        g_expectedChecksums[i] = CalculateChecksum(g_criticalOffsets[i]);
    }
}

bool VerifyOffsets() {
    for (int i = 0; i < NUM_OFFSETS; ++i) {
        unsigned long current = g_criticalOffsets[i];
        unsigned long expected = g_expectedChecksums[i];
        unsigned long actual = CalculateChecksum(current);
        if (actual != expected) {
            std::cout << "[AntiCheat][User] Offset tampering detected at index " << i << "!" << std::endl;
            return false;
        }
    }
    std::cout << "[AntiCheat][User] All offsets verified." << std::endl;
    return true;
}

void PrintPCIDevices() {
    std::cout << "[AntiCheat][User] Enumerating PCI devices..." << std::endl;
    HDEVINFO hDevInfo = SetupDiGetClassDevs(NULL, L"PCI", NULL, DIGCF_PRESENT | DIGCF_ALLCLASSES);
    if (hDevInfo == INVALID_HANDLE_VALUE) {
        std::cout << "[AntiCheat][User] Failed to get PCI device info." << std::endl;
        return;
    }
    SP_DEVINFO_DATA DeviceInfoData;
    DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &DeviceInfoData); ++i) {
        TCHAR desc[1024];
        if (SetupDiGetDeviceRegistryProperty(hDevInfo, &DeviceInfoData, SPDRP_DEVICEDESC, NULL, (PBYTE)desc, sizeof(desc), NULL)) {
            std::wcout << L"[AntiCheat][User] PCI Device: " << desc << std::endl;
        }
    }
    SetupDiDestroyDeviceInfoList(hDevInfo);
}

void ShowDMASecurityNotice() {
    std::cout << "==============================\n";
    std::cout << "  DMA Security Notice\n";
    std::cout << "==============================\n";
    std::cout << "To protect against DMA-based cheats, please ensure the following BIOS/UEFI settings are enabled before running the game:\n";
    std::cout << " - IOMMU/VT-d (Intel) or AMD-Vi (AMD) is ENABLED\n";
    std::cout << " - Thunderbolt Security is ENABLED or Thunderbolt is DISABLED\n";
    std::cout << " - Unused PCIe/Thunderbolt ports are DISABLED\n";
    std::cout << " - DMA Protection is ENABLED (if available)\n";
    std::cout << "If you are unsure, please consult your motherboard/computer manual.\n";
    std::cout << "Press ENTER to continue..." << std::endl;
    std::cin.get();
}

int main() {
    if (!CreateAntiCheatMutex()) {
        std::cout << "[AntiCheat][User] Anti-cheat must be running before the game can start. Exiting..." << std::endl;
        return 1;
    }
    ShowDMASecurityNotice();
    std::cout << "AntiCheat user-mode component started (C++)." << std::endl;
    PrintPCIDevices();
    InitializeChecksums();
    // Periodically check offsets (simulate as long as the game is running)
    while (true) {
        VerifyOffsets();
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    return 0;
}
