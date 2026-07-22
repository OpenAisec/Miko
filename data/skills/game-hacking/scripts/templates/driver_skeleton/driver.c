/**
 * driver.c — WDF 驱动骨架（内存读写通信）
 *
 * 编译: Visual Studio + WDK
 *
 * 功能:
 * - IOCTL 通信接口
 * - 跨进程内存读写
 * - 隐藏进程/模块
 *
 * 警告: 仅用于授权的安全研究和测试环境
 */

#include <ntddk.h>
#include <wdf.h>

/* ========== IOCTL 定义 ========== */

#define IOCTL_READ_MEMORY   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_MEMORY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HIDE_PROCESS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _MEMORY_REQUEST {
    ULONG pid;
    ULONG_PTR address;
    ULONG_PTR buffer;
    SIZE_T size;
} MEMORY_REQUEST, *PMEMORY_REQUEST;

/* ========== 内核内存读写 ========== */

NTSTATUS kernel_read_memory(PEPROCESS process, PVOID address, PVOID buffer, SIZE_T size) {
    SIZE_T bytes = 0;
    return MmCopyVirtualMemory(process, address, PsGetCurrentProcess(), buffer, size, KernelMode, &bytes);
}

NTSTATUS kernel_write_memory(PEPROCESS process, PVOID address, PVOID buffer, SIZE_T size) {
    SIZE_T bytes = 0;
    return MmCopyVirtualMemory(PsGetCurrentProcess(), buffer, process, address, size, KernelMode, &bytes);
}

/* ========== 进程隐藏 ========== */

VOID hide_process_by_eprocess(PEPROCESS process) {
    /*
     * 从活动进程链表中摘除 EPROCESS
     *
     * 注意:
     * 1. ActiveProcessLinks 偏移随 Windows 版本变化
     * 2. 需要通过特征码或 PDB 确定偏移
     * 3. 摘除后进程管理器中不可见，但进程仍在运行
     */

    /* 示例偏移 (Windows 10 21H2 x64) */
    /* 实际使用时需要动态获取 */
    /*
    ULONG offset = 0x448;  // ActiveProcessLinks offset
    PLIST_ENTRY link = (PLIST_ENTRY)((PUCHAR)process + offset);

    // 从双向链表中移除
    link->Blink->Flink = link->Flink;
    link->Flink->Blink = link->Blink;

    // 自引用，防止遍历崩溃
    link->Flink = link;
    link->Blink = link;
    */
}

/* ========== IOCTL 处理 ========== */

NTSTATUS device_control(WDFDEVICE Device, WDFREQUEST Request,
                         size_t OutLen, size_t InLen, ULONG Code) {
    UNREFERENCED_PARAMETER(Device);
    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T returned = 0;

    switch (Code) {
    case IOCTL_READ_MEMORY: {
        PMEMORY_REQUEST req;
        status = WdfRequestRetrieveInputBuffer(Request, sizeof(MEMORY_REQUEST), &req, NULL);
        if (!NT_SUCCESS(status)) break;

        PVOID out_buf;
        status = WdfRequestRetrieveOutputBuffer(Request, req->size, &out_buf, NULL);
        if (!NT_SUCCESS(status)) break;

        PEPROCESS proc;
        status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->pid, &proc);
        if (!NT_SUCCESS(status)) break;

        status = kernel_read_memory(proc, (PVOID)req->address, out_buf, req->size);
        returned = NT_SUCCESS(status) ? req->size : 0;
        ObDereferenceObject(proc);
        break;
    }

    case IOCTL_WRITE_MEMORY: {
        PMEMORY_REQUEST req;
        status = WdfRequestRetrieveInputBuffer(Request, sizeof(MEMORY_REQUEST), &req, NULL);
        if (!NT_SUCCESS(status)) break;

        PEPROCESS proc;
        status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->pid, &proc);
        if (!NT_SUCCESS(status)) break;

        status = kernel_write_memory(proc, (PVOID)req->address, (PVOID)req->buffer, req->size);
        ObDereferenceObject(proc);
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    WdfRequestCompleteWithInformation(Request, status, returned);
    return status;
}

/* ========== 驱动入口/卸载 ========== */

VOID driver_unload(WDFDRIVER Driver) {
    UNREFERENCED_PARAMETER(Driver);
    KdPrint(("[GameHelper] Unloaded\n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;

    KdPrint(("[GameHelper] Loaded\n"));

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.EvtDriverUnload = driver_unload;

    status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) return status;

    /* 创建设备和符号链接 */
    WDFDEVICE device;
    UNICODE_STRING dev_name, sym_link;
    RtlInitUnicodeString(&dev_name, L"\\Device\\GameHelper");
    RtlInitUnicodeString(&sym_link, L"\\DosDevices\\GameHelper");

    PWDFDEVICE_INIT init = WdfControlDeviceInitAllocate(WdfGetDriver(), &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
    if (!init) return STATUS_INSUFFICIENT_RESOURCES;

    WdfDeviceInitAssignName(init, &dev_name);
    WdfDeviceInitSetIoType(init, WdfDeviceIoBuffered);

    status = WdfDeviceCreate(&init, WDF_NO_OBJECT_ATTRIBUTES, &device);
    if (!NT_SUCCESS(status)) return status;

    WdfDeviceCreateSymbolicLink(device, &sym_link);

    /* 注册 IOCTL */
    WDF_IO_QUEUE_CONFIG queue_config;
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue_config, WdfIoQueueDispatchParallel);
    queue_config.EvtIoDeviceControl = device_control;

    WDFQUEUE queue;
    status = WdfIoQueueCreate(device, &queue_config, WDF_NO_OBJECT_ATTRIBUTES, &queue);
    if (!NT_SUCCESS(status)) return status;

    WdfControlFinishInitializing(device);
    return STATUS_SUCCESS;
}
