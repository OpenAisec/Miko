/**
 * hook_inject.c — DLL 注入 + MinHook 示例
 *
 * 编译 DLL:
 *   cl /LD hook_inject.c /link minhook.lib user32.lib
 *
 * 注入器编译:
 *   cl injector.c /link advapi32.lib
 */

#include <windows.h>
#include <stdio.h>
#include "MinHook.h"  /* https://github.com/TsudaKageworker/minhook */

/* ========== Hook 示例: 拦截 MessageBoxW ========== */

typedef int (WINAPI *MessageBoxW_t)(HWND, LPCWSTR, LPCWSTR, UINT);
static MessageBoxW_t fpMessageBoxW = NULL;

int WINAPI MessageBoxW_Hook(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType) {
    /* 修改显示内容 */
    lpText = L"Hooked by game-hacking!";
    lpCaption = L"Hooked";

    /* 调用原始函数 */
    return fpMessageBoxW(hWnd, lpText, lpCaption, uType);
}

/* ========== Hook 示例: 拦截游戏函数 ========== */

/*
 * 假设游戏有一个函数: int GetPlayerHealth(void* player)
 * 编译后地址为: game.exe + 0x123456
 *
 * 步骤:
 * 1. IDA 分析找到函数地址
 * 2. 计算相对于模块基址的偏移
 * 3. 用 MinHook 创建 Hook
 */

typedef int (*GetPlayerHealth_t)(void*);
static GetPlayerHealth_t fpGetPlayerHealth = NULL;

int GetPlayerHealth_Hook(void* player) {
    int health = fpGetPlayerHealth(player);
    printf("[Hook] Player health: %d\n", health);

    /* 修改返回值 */
    return 9999;
}

/* ========== DLL 入口 ========== */

static HMODULE g_module = NULL;

DWORD WINAPI MainThread(LPVOID param) {
    /* 等待游戏模块加载 */
    HMODULE game_module = NULL;
    while (!game_module) {
        game_module = GetModuleHandleA("game.exe");
        Sleep(100);
    }

    /* 初始化 MinHook */
    if (MH_Initialize() != MH_OK) {
        MessageBoxA(NULL, "MH_Initialize failed", "Error", MB_OK);
        return 1;
    }

    /* Hook MessageBoxW (示例) */
    HMODULE user32 = GetModuleHandleA("user32.dll");
    if (user32) {
        LPVOID target = GetProcAddress(user32, "MessageBoxW");
        if (MH_CreateHook(target, &MessageBoxW_Hook, (LPVOID*)&fpMessageBoxW) == MH_OK) {
            MH_EnableHook(target);
        }
    }

    /* Hook 游戏函数 (取消注释并修改地址) */
    /*
    uintptr_t base = (uintptr_t)game_module;
    LPVOID game_func = (LPVOID)(base + 0x123456);  // 替换为实际偏移
    if (MH_CreateHook(game_func, &GetPlayerHealth_Hook, (LPVOID*)&fpGetPlayerHealth) == MH_OK) {
        MH_EnableHook(game_func);
    }
    */

    /* 创建控制台用于调试 */
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    printf("[+] Hooks installed!\n");
    printf("[+] Press END to unload\n");

    /* 等待卸载信号 */
    while (!(GetAsyncKeyState(VK_END) & 1)) {
        Sleep(100);
    }

    /* 清理 */
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    FreeConsole();
    FreeLibraryAndExitThread(g_module, 0);

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        g_module = hModule;
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, MainThread, NULL, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
