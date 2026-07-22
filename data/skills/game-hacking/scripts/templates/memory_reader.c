/**
 * memory_reader.c — Windows 游戏内存读写模板
 *
 * 编译: cl memory_reader.c /link advapi32.lib
 * 或: gcc memory_reader.c -o memory_reader.exe -ladvapi32
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdint.h>

/* ========== 进程操作 ========== */

DWORD find_process(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = { .dwSize = sizeof(pe) };
    DWORD pid = 0;

    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

uintptr_t find_module(DWORD pid, const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32 me = { .dwSize = sizeof(me) };
    uintptr_t base = 0;

    if (Module32First(snap, &me)) {
        do {
            if (_stricmp(me.szModule, name) == 0) {
                base = (uintptr_t)me.modBaseAddr;
                break;
            }
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return base;
}

/* ========== 内存读写 ========== */

BOOL read_memory(HANDLE h, uintptr_t addr, void* buf, size_t sz) {
    return ReadProcessMemory(h, (LPCVOID)addr, buf, sz, NULL);
}

BOOL write_memory(HANDLE h, uintptr_t addr, void* buf, size_t sz) {
    DWORD old;
    VirtualProtectEx(h, (LPVOID)addr, sz, PAGE_EXECUTE_READWRITE, &old);
    BOOL ok = WriteProcessMemory(h, (LPVOID)addr, buf, sz, NULL);
    VirtualProtectEx(h, (LPVOID)addr, sz, old, &old);
    return ok;
}

/* ========== 指针链读写 ========== */

uintptr_t resolve_pointer_chain(HANDLE h, uintptr_t base,
                                  const uintptr_t* offsets, int count) {
    uintptr_t addr = base;
    for (int i = 0; i < count; i++) {
        if (!read_memory(h, addr, &addr, sizeof(addr))) return 0;
        addr += offsets[i];
    }
    return addr;
}

/* ========== AOB 特征码扫描 ========== */

uintptr_t aob_scan(HANDLE h, uintptr_t start, size_t range,
                    const BYTE* pattern, const BYTE* mask, size_t pat_len) {
    BYTE* buf = (BYTE*)malloc(range);
    if (!buf) return 0;

    if (!read_memory(h, start, buf, range)) {
        free(buf);
        return 0;
    }

    uintptr_t result = 0;
    for (size_t i = 0; i <= range - pat_len; i++) {
        BOOL match = TRUE;
        for (size_t j = 0; j < pat_len; j++) {
            if (mask[j] && buf[i + j] != pattern[j]) {
                match = FALSE;
                break;
            }
        }
        if (match) {
            result = start + i;
            break;
        }
    }

    free(buf);
    return result;
}

/* ========== 示例: 读取游戏数据 ========== */

typedef struct {
    int health;
    int max_health;
    float x, y, z;
    int level;
} PlayerInfo;

int main(int argc, char* argv[]) {
    const char* proc_name = argc > 1 ? argv[1] : "game.exe";
    DWORD pid = find_process(proc_name);
    if (!pid) {
        printf("Process not found: %s\n", proc_name);
        return 1;
    }
    printf("[+] PID: %lu\n", pid);

    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!h) {
        printf("OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }

    uintptr_t base = find_module(pid, proc_name);
    printf("[+] Base: 0x%p\n", (void*)base);

    /* 示例: 通过指针链读取玩家信息 */
    uintptr_t player_offsets[] = { 0x1A3F50, 0x10, 0x28 };
    uintptr_t player_addr = resolve_pointer_chain(h, base, player_offsets, 3);

    if (player_addr) {
        PlayerInfo info;
        if (read_memory(h, player_addr, &info, sizeof(info))) {
            printf("[+] Health: %d/%d\n", info.health, info.max_health);
            printf("[+] Position: %.1f, %.1f, %.1f\n", info.x, info.y, info.z);
            printf("[+] Level: %d\n", info.level);
        }
    }

    /* 示例: AOB 扫描 */
    BYTE pattern[] = { 0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF8 };
    BYTE mask[]    = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    uintptr_t found = aob_scan(h, base, 0x1000000, pattern, mask, sizeof(pattern));
    if (found) {
        printf("[+] AOB found at: 0x%p\n", (void*)found);
    }

    CloseHandle(h);
    return 0;
}
