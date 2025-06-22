#include <ntddk.h>
#include "AntiCheatCommon.h"

// Global variables
KSPIN_LOCK g_lock;
KTIMER g_timer;
KDPC g_dpc;
PDEVICE_OBJECT g_deviceObject = NULL;
UNICODE_STRING g_deviceName, g_symLinkName;
char g_logBuffer[4096] = {0};
size_t g_logLen = 0;

// Log event
void LogEvent(const char* message) {
    KIRQL irql;
    KeAcquireSpinLock(&g_lock, &irql);
    size_t msgLen = strlen(message);
    if (g_logLen + msgLen < sizeof(g_logBuffer)) {
        strcat_s(g_logBuffer + g_logLen, sizeof(g_logBuffer) - g_logLen, message);
        g_logLen += msgLen;
    }
    KeReleaseSpinLock(&g_lock, irql);
}

// Check for debugger presence
BOOLEAN CheckForDebugger() {
    return PsGetCurrentThread()->DebugPort != NULL;
}

// Periodic integrity check
VOID IntegrityCheck() {
    KeAcquireSpinLockAtDpcLevel(&g_lock);
    if (CheckForDebugger()) {
        LogEvent("[AntiCheat][C++] Debugger detected! Potential tampering.\n");
    }
    KeReleaseSpinLockFromDpcLevel(&g_lock);
}

VOID AntiCheatDpcRoutine(PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2) {
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    IntegrityCheck();

    LARGE_INTEGER dueTime;
    dueTime.QuadPart = -10000LL * 1000; // 1 second
    if (!KeSetTimer(&g_timer, dueTime, &g_dpc)) {
        LogEvent("[AntiCheat][C++] Failed to re-arm timer in DPC\n");
    }
}

NTSTATUS CreateCloseHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DeviceControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;

    switch (irpStack->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_CHECK_INTEGRITY:
            IntegrityCheck();
            break;
        case IOCTL_GET_LOGS:
            if (irpStack->Parameters.DeviceIoControl.OutputBufferLength < g_logLen) {
                status = STATUS_BUFFER_TOO_SMALL;
            } else {
                RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, g_logBuffer, g_logLen);
                Irp->IoStatus.Information = g_logLen;
            }
            break;
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    KeCancelTimer(&g_timer);
    IoDeleteSymbolicLink(&g_symLinkName);
    if (g_deviceObject) IoDeleteDevice(g_deviceObject);
    LogEvent("[AntiCheat][C++] Driver unloaded.\n");
    DbgPrint("%s", g_logBuffer);
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    KeInitializeSpinLock(&g_lock);
    KeInitializeTimer(&g_timer);
    KeInitializeDpc(&g_dpc, AntiCheatDpcRoutine, NULL);

    RtlInitUnicodeString(&g_deviceName, L"\\Device\\AntiCheatDriver");
    RtlInitUnicodeString(&g_symLinkName, L"\\DosDevices\\AntiCheatDriver");
    status = IoCreateDevice(DriverObject, 0, &g_deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_deviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AntiCheat][C++] Failed to create device: 0x%08X\n", status);
        return status;
    }

    status = IoCreateSymbolicLink(&g_symLinkName, &g_deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_deviceObject);
        g_deviceObject = NULL;
        DbgPrint("[AntiCheat][C++] Failed to create symbolic link: 0x%08X\n", status);
        return status;
    }

    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControlHandler;

    LARGE_INTEGER dueTime;
    dueTime.QuadPart = -10000LL * 1000;
    if (!KeSetTimer(&g_timer, dueTime, &g_dpc)) {
        IoDeleteSymbolicLink(&g_symLinkName);
        IoDeleteDevice(g_deviceObject);
        g_deviceObject = NULL;
        DbgPrint("[AntiCheat][C++] Failed to set timer\n");
        return STATUS_UNSUCCESSFUL;
    }

    LogEvent("[AntiCheat][C++] Driver loaded successfully.\n");
    DbgPrint("%s", g_logBuffer);
    return STATUS_SUCCESS;
}