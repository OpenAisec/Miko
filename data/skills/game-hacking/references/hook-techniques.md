# Hook 技术详解 (Hook Techniques)

## 目录

1. [Hook 概述](#hook-概述)
2. [Inline Hook](#inline-hook)
3. [IAT Hook](#iat-hook)
4. [EAT Hook](#eat-hook)
5. [VMT Hook](#vmt-hook)
6. [DLL 注入](#dll-注入)
7. [渲染 Hook](#渲染-hook)
8. [异常 Hook](#异常-hook)
9. [实战案例](#实战案例)

---

## Hook 概述

Hook（钩子）是拦截和修改函数调用的技术。核心思想：**在目标函数执行前/后插入自定义代码**。

### Hook 类型对比

| 类型 | 原理 | 难度 | 稳定性 | 适用场景 |
|------|------|------|--------|----------|
| Inline Hook | 修改函数入口指令 | 中 | 高 | 任意函数 |
| IAT Hook | 修改导入表指针 | 低 | 高 | 导入的 API |
| EAT Hook | 修改导出表指针 | 低 | 中 | 导出的函数 |
| VMT Hook | 修改虚函数表 | 低 | 高 | C++ 虚函数 |
| 异常 Hook | 利用异常处理 | 高 | 中 | 无修改检测 |

---

## Inline Hook

### 原理

在目标函数入口处用 `JMP` 指令跳转到自定义函数：

```
原始代码:                 Hook 后:
┌──────────────────┐     ┌──────────────────┐
│ push ebp          │     │ jmp MyHook        │  ← 5字节被覆盖
│ mov ebp, esp      │     │ nop               │
│ sub esp, 0x10     │     │ sub esp, 0x10     │
│ ...               │     │ ...               │
└──────────────────┘     └──────────────────┘

MyHook:
┌──────────────────┐
│ 保存寄存器         │
│ 执行自定义逻辑     │
│ 恢复被覆盖的指令   │
│ 调用原始函数       │
│ 恢复寄存器         │
│ 返回              │
└──────────────────┘
```

### x86 实现

```c
#include <windows.h>

// Hook 结构
typedef struct {
    BYTE original_bytes[5];    // 保存原始字节
    BYTE jmp_bytes[5];         // JMP 指令
    LPVOID target_addr;        // 目标函数地址
    LPVOID detour_addr;        // Hook 函数地址
    LPVOID trampoline;         // 跳板函数
} InlineHook;

// 创建跳板函数
LPVOID create_trampoline(LPVOID target, LPVOID detour) {
    // 分配可执行内存
    LPVOID trampoline = VirtualAlloc(NULL, 32, 
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    // 复制原始函数的前几条指令（至少5字节）
    // 需要处理指令边界，不能截断指令
    memcpy(trampoline, target, 5);
    
    // 添加跳回原始函数的 JMP
    BYTE* code = (BYTE*)trampoline + 5;
    code[0] = 0xE9;  // JMP
    *(DWORD*)(code + 1) = (DWORD)target + 5 - (DWORD)(code + 5);
    
    return trampoline;
}

// 安装 Hook
BOOL install_inline_hook(InlineHook* hook) {
    DWORD old_protect;
    
    // 保存原始字节
    memcpy(hook->original_bytes, hook->target_addr, 5);
    
    // 创建跳板
    hook->trampoline = create_trampoline(hook->target_addr, hook->detour_addr);
    
    // 修改内存保护
    VirtualProtect(hook->target_addr, 5, PAGE_EXECUTE_READWRITE, &old_protect);
    
    // 写入 JMP 指令
    BYTE* code = (BYTE*)hook->target_addr;
    code[0] = 0xE9;  // JMP
    *(DWORD*)(code + 1) = (DWORD)hook->detour_addr - (DWORD)hook->target_addr - 5;
    
    // 恢复内存保护
    VirtualProtect(hook->target_addr, 5, old_protect, &old_protect);
    
    return TRUE;
}

// 卸载 Hook
BOOL uninstall_inline_hook(InlineHook* hook) {
    DWORD old_protect;
    VirtualProtect(hook->target_addr, 5, PAGE_EXECUTE_READWRITE, &old_protect);
    memcpy(hook->target_addr, hook->original_bytes, 5);
    VirtualProtect(hook->target_addr, 5, old_protect, &old_protect);
    VirtualFree(hook->trampoline, 0, MEM_RELEASE);
    return TRUE;
}
```

### x64 注意事项

```
64位程序的地址空间很大，JMP 的 32 位相对偏移可能不够用。
需要使用间接跳转:

方法1: JMP [RIP+0]
       8字节绝对地址

方法2: MOV RAX, addr
       JMP RAX
       共12字节

推荐使用库: MinHook, Detours, PolyHook
```

### 使用 MinHook（推荐）

```c
#include <MinHook.h>

// 原始函数指针
typedef int (WINAPI *MessageBoxW_t)(HWND, LPCWSTR, LPCWSTR, UINT);
MessageBoxW_t fpMessageBoxW = NULL;

// Hook 函数
int WINAPI MessageBoxW_Hook(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType) {
    // 修改参数
    lpText = L"Hooked!";
    
    // 调用原始函数
    return fpMessageBoxW(hWnd, lpText, lpCaption, uType);
}

// 安装 Hook
void install_hook() {
    MH_Initialize();
    MH_CreateHookApi(L"user32", "MessageBoxW", &MessageBoxW_Hook, (LPVOID*)&fpMessageBoxW);
    MH_EnableHook(MH_ALL_HOOKS);
}

// 卸载 Hook
void remove_hook() {
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
}
```

---

## IAT Hook

### 原理

IAT（导入地址表）存储程序导入的外部函数地址。修改 IAT 中的指针即可 Hook：

```
IAT 表:
┌─────────────────────────────────┐
│ MessageBoxW → 0x7FFE1234        │  ← 原始地址
│ CreateFileW → 0x7FFE5678        │
│ ...                             │
└─────────────────────────────────┘

Hook 后:
┌─────────────────────────────────┐
│ MessageBoxW → MyHookFunc        │  ← 指向我们的函数
│ CreateFileW → 0x7FFE5678        │
│ ...                             │
└─────────────────────────────────┘
```

### 实现

```c
#include <windows.h>

BOOL iat_hook(HMODULE hModule, const char* dll_name, const char* func_name, LPVOID new_func) {
    // 获取导入表
    ULONG size;
    PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)
        ImageDirectoryEntryToData(hModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);
    
    if (!import_desc) return FALSE;
    
    // 遍历导入表
    while (import_desc->Name) {
        char* module_name = (char*)((BYTE*)hModule + import_desc->Name);
        
        if (_stricmp(module_name, dll_name) == 0) {
            // 找到目标 DLL
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)
                ((BYTE*)hModule + import_desc->FirstThunk);
            
            while (thunk->u1.Function) {
                FARPROC* func_ptr = (FARPROC*)&thunk->u1.Function;
                
                if (*func_ptr == GetProcAddress(GetModuleHandleA(dll_name), func_name)) {
                    // 找到目标函数，修改 IAT
                    DWORD old_protect;
                    VirtualProtect(func_ptr, sizeof(FARPROC), PAGE_READWRITE, &old_protect);
                    *func_ptr = new_func;
                    VirtualProtect(func_ptr, sizeof(FARPROC), old_protect, &old_protect);
                    return TRUE;
                }
                thunk++;
            }
        }
        import_desc++;
    }
    return FALSE;
}

// 使用示例
int WINAPI MessageBoxW_Hook(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType) {
    return MessageBoxW(hWnd, L"Hooked by IAT!", lpCaption, uType);
}

// 在 DllMain 中安装
iat_hook(GetModuleHandle(NULL), "user32.dll", "MessageBoxW", MessageBoxW_Hook);
```

---

## EAT Hook

### 原理

EAT（导出地址表）存储 DLL 导出函数的地址。修改 EAT 可以 Hook 所有调用该 DLL 的进程：

```c
BOOL eat_hook(HMODULE hModule, const char* func_name, LPVOID new_func, LPVOID* original_func) {
    // 获取导出表
    ULONG size;
    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)
        ImageDirectoryEntryToData(hModule, FALSE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size);
    
    if (!export_dir) return FALSE;
    
    DWORD* functions = (DWORD*)((BYTE*)hModule + export_dir->AddressOfFunctions);
    DWORD* names = (DWORD*)((BYTE*)hModule + export_dir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)hModule + export_dir->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < export_dir->NumberOfNames; i++) {
        char* name = (char*)((BYTE*)hModule + names[i]);
        if (strcmp(name, func_name) == 0) {
            // 找到目标函数
            DWORD old_protect;
            DWORD func_rva = functions[ordinals[i]];
            
            if (original_func)
                *original_func = (BYTE*)hModule + func_rva;
            
            VirtualProtect(&functions[ordinals[i]], sizeof(DWORD), PAGE_READWRITE, &old_protect);
            functions[ordinals[i]] = (DWORD)new_func - (DWORD)hModule;  // 转为 RVA
            VirtualProtect(&functions[ordinals[i]], sizeof(DWORD), old_protect, &old_protect);
            
            return TRUE;
        }
    }
    return FALSE;
}
```

---

## VMT Hook

### 原理

C++ 虚函数通过虚函数表（VMT）调用。修改 VMT 中的函数指针即可 Hook：

```
对象内存:
┌────────────────┐
│ vtable_ptr ─────┼──→ VMT: [func1] [func2] [func3] ...
│ member1         │
│ member2         │
└────────────────┘

Hook 后:
VMT: [func1] [MyHook] [func3] ...
                  ↑
            被替换为我们的函数
```

### 实现

```c
class VmtHook {
public:
    void* object;          // 目标对象
    void** vtable;         // 原始虚表
    void** new_vtable;     // 新虚表
    int vfunc_count;       // 虚函数数量
    
    bool install(void* obj) {
        object = obj;
        vtable = *(void***)obj;
        
        // 计算虚函数数量
        vfunc_count = 0;
        while (vtable[vfunc_count]) vfunc_count++;
        
        // 创建新的虚表
        new_vtable = new void*[vfunc_count];
        memcpy(new_vtable, vtable, vfunc_count * sizeof(void*));
        
        // 替换对象的虚表指针
        *(void***)obj = new_vtable;
        
        return true;
    }
    
    bool hook(int index, void* new_func, void** original) {
        if (index >= vfunc_count) return false;
        *original = new_vtable[index];
        new_vtable[index] = new_func;
        return true;
    }
    
    void uninstall() {
        *(void***)object = vtable;
        delete[] new_vtable;
    }
};

// 使用示例
// Hook DirectX 的 Present 函数
VmtHook d3d_hook;
void* present_original;

HRESULT __stdcall Present_Hook(IDirect3DDevice9* pDevice, RECT* src, RECT* dst, 
                                HWND hWnd, void* pDirtyRegion) {
    // 在这里绘制 Overlay
    draw_overlay(pDevice);
    return ((HRESULT(__stdcall*)(IDirect3DDevice9*, RECT*, RECT*, HWND, void*))
            present_original)(pDevice, src, dst, hWnd, pDirtyRegion);
}

// 安装
d3d_hook.install(d3d_device);
d3d_hook.hook(17, Present_Hook, &present_original);  // Present 在 VMT 的第17位
```

---

## DLL 注入

### 注入方式对比

| 方式 | 原理 | 难度 | 检测难度 |
|------|------|------|----------|
| CreateRemoteThread | 远程线程调用 LoadLibrary | 低 | 低 |
| NtCreateThreadEx | 内核级线程创建 | 中 | 中 |
| APC 注入 | 异步过程调用 | 中 | 中 |
| SetWindowsHookEx | 消息钩子 | 低 | 低 |
| 反射注入 | 手动加载 DLL | 高 | 高 |

### CreateRemoteThread 注入

```c
BOOL inject_dll(DWORD pid, const char* dll_path) {
    // 打开目标进程
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return FALSE;
    
    // 在目标进程分配内存
    LPVOID remote_mem = VirtualAllocEx(hProc, NULL, strlen(dll_path) + 1,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_mem) {
        CloseHandle(hProc);
        return FALSE;
    }
    
    // 写入 DLL 路径
    WriteProcessMemory(hProc, remote_mem, dll_path, strlen(dll_path) + 1, NULL);
    
    // 创建远程线程调用 LoadLibraryA
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"),
        remote_mem, 0, NULL);
    
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }
    
    VirtualFreeEx(hProc, remote_mem, 0, MEM_RELEASE);
    CloseHandle(hProc);
    return TRUE;
}
```

### 反射注入

```c
// DLL 自加载（不需要文件存在于磁盘）
// 在 DllMain 中实现自加载逻辑
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // 初始化 Hook
        init_hooks();
    }
    return TRUE;
}

// 注入端：将 DLL 数据写入目标进程并执行
void reflective_inject(DWORD pid, BYTE* dll_data, DWORD dll_size) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    
    // 分配内存
    LPVOID remote_mem = VirtualAllocEx(hProc, NULL, dll_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    // 写入 DLL 数据
    WriteProcessMemory(hProc, remote_mem, dll_data, dll_size, NULL);
    
    // 计算入口点偏移（从 PE 头获取）
    DWORD entry_offset = get_entry_point_offset(dll_data);
    
    // 创建远程线程执行 DLL 入口
    CreateRemoteThread(hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)((BYTE*)remote_mem + entry_offset),
        remote_mem, 0, NULL);
    
    CloseHandle(hProc);
}
```

---

## 渲染 Hook

### DirectX 9 Hook

```c
#include <d3d9.h>

// 获取 D3D9 设备的 VMT
void** get_d3d9_vmt() {
    // 创建临时 D3D 设备
    IDirect3D9* d3d = Direct3DCreate9(D3D_SDK_VERSION);
    D3DPRESENT_PARAMETERS pp = {};
    pp.Windowed = TRUE;
    pp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    pp.hDeviceWindow = GetDesktopWindow();
    
    IDirect3DDevice9* device;
    d3d->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, pp.hDeviceWindow,
        D3DCREATE_SOFTWARE_VERTEXPROCESSING, &pp, &device);
    
    void** vmt = *(void***)device;
    
    device->Release();
    d3d->Release();
    
    return vmt;
}

// Hook EndScene (VMT index 42)
typedef HRESULT(__stdcall* EndScene_t)(IDirect3DDevice9*);
EndScene_t oEndScene = NULL;

HRESULT __stdcall EndScene_Hook(IDirect3DDevice9* pDevice) {
    // 初始化 ImGui（如果还没初始化）
    static bool initialized = false;
    if (!initialized) {
        ImGui::CreateContext();
        ImGui_ImplWin32_Init(GetActiveWindow());
        ImGui_ImplDX9_Init(pDevice);
        initialized = true;
    }
    
    // 开始新帧
    ImGui_ImplDX9_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();
    
    // 绘制菜单/ESP
    draw_menu();
    draw_esp();
    
    // 渲染
    ImGui::EndFrame();
    ImGui::Render();
    ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
    
    return oEndScene(pDevice);
}
```

### OpenGL Hook

```c
#include <GL/gl.h>
#include <detours.h>

// Hook wglSwapBuffers（在缓冲区交换时绘制）
typedef BOOL(WINAPI* wglSwapBuffers_t)(HDC);
wglSwapBuffers_t owglSwapBuffers = NULL;

BOOL WINAPI wglSwapBuffers_Hook(HDC hdc) {
    // 保存 OpenGL 状态
    glPushAttrib(GL_ALL_ATTRIB_BITS);
    glPushMatrix();
    
    // 切换到 2D 绘制模式
    glMatrixMode(GL_PROJECTION);
    glLoadIdentity();
    glOrtho(0, screen_width, screen_height, 0, -1, 1);
    glMatrixMode(GL_MODELVIEW);
    glLoadIdentity();
    
    // 禁用深度测试
    glDisable(GL_DEPTH_TEST);
    
    // 绘制 ESP
    draw_esp_2d();
    
    // 恢复 OpenGL 状态
    glPopMatrix();
    glPopAttrib();
    
    return owglSwapBuffers(hdc);
}
```

---

## 异常 Hook

### 原理

利用调试寄存器（DR0-DR3）设置硬件断点，通过异常处理拦截：

```c
#include <windows.h>

// 设置硬件断点
void set_hw_breakpoint(HANDLE hThread, LPVOID addr, int reg) {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(hThread, &ctx);
    
    switch (reg) {
        case 0: ctx.Dr0 = (DWORD_PTR)addr; break;
        case 1: ctx.Dr1 = (DWORD_PTR)addr; break;
        case 2: ctx.Dr2 = (DWORD_PTR)addr; break;
        case 3: ctx.Dr3 = (DWORD_PTR)addr; break;
    }
    
    // 设置条件：执行时触发
    ctx.Dr7 |= (1 << (reg * 2));           // 局部启用
    ctx.Dr7 |= (0 << (16 + reg * 4));      // 条件：执行
    ctx.Dr7 |= (0 << (18 + reg * 4));      // 长度：1字节
    
    SetThreadContext(hThread, &ctx);
}

// VEH 异常处理
LONG WINAPI vectored_handler(EXCEPTION_POINTERS* ep) {
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        // 检查是否是我们的断点
        if (ep->ContextRecord->Dr6 & 1) {  // DR0 触发
            // 执行自定义逻辑
            handle_hook(ep);
            
            // 设置单步以在执行原始指令后恢复
            ep->ContextRecord->EFlags |= 0x100;  // TF 标志
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        
        // 单步执行后的恢复
        if (ep->ContextRecord->EFlags & 0x100) {
            // 重新设置硬件断点
            set_hw_breakpoint(GetCurrentThread(), hook_addr, 0);
            ep->ContextRecord->EFlags &= ~0x100;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// 安装
AddVectoredExceptionHandler(1, vectored_handler);
```

---

## 实战案例

### 案例：Hook DirectX 绘制 ESP

```
1. 创建一个 D3D9 临时设备获取 VMT
2. Hook EndScene 函数（VMT index 42）
3. 在 Hook 函数中初始化 ImGui
4. 绘制 ESP 框、血条、距离等信息
5. 打包为 DLL，注入到游戏进程
```

### 案例：Hook 游戏伤害函数

```
1. IDA 分析找到伤害计算函数地址
2. 使用 MinHook 创建 Inline Hook
3. 在 Hook 中修改伤害值:
   - 原始伤害 * 倍率
   - 或直接返回固定值
4. 打包为 DLL 注入游戏
```

### 案例：Hook 网络发送函数

```
1. Hook send/WSASend 函数
2. 在 Hook 中记录或修改发送的数据
3. 实现协议分析或自动发送功能
```
