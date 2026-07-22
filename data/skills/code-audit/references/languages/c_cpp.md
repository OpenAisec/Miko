# C/C++ Security Audit

> C/C++ 代码安全审计模块
> 适用于: C, C++, 嵌入式系统, 系统编程

## 识别特征

```c
// C/C++项目识别
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 文件结构
├── Makefile / CMakeLists.txt
├── src/
├── include/
├── lib/
└── tests/
```

---

## C/C++特定漏洞

### 1. 缓冲区溢出

```c
// 栈溢出
char buffer[64];
strcpy(buffer, user_input);  // 溢出!
sprintf(buffer, "%s", user_input);  // 溢出!
gets(buffer);  // 极度危险, 已弃用

// 堆溢出
char *buf = malloc(64);
memcpy(buf, user_data, user_length);  // 长度未验证!

// 整数溢出导致的缓冲区问题
size_t len = user_controlled_value;
char *buf = malloc(len + 1);  // 如果len = SIZE_MAX, 溢出为0

// 安全替代
strncpy(buffer, input, sizeof(buffer) - 1);
snprintf(buffer, sizeof(buffer), "%s", input);
fgets(buffer, sizeof(buffer), stdin);

// 搜索模式
strcpy|sprintf|gets|strcat|scanf
memcpy|memmove + 未验证长度
```

### 2. 格式化字符串

```c
// 危险: 用户输入作为格式字符串
printf(user_input);  // 格式化字符串攻击!
fprintf(stderr, user_input);
sprintf(buf, user_input);
syslog(LOG_ERR, user_input);

// 利用
%x%x%x%x  // 泄露栈数据
%n        // 写入内存
%s        // 读取任意地址

// 安全
printf("%s", user_input);

// 搜索模式
printf\([^,]*\$|fprintf\([^,]*,[^,]*\$|sprintf\([^,]*,[^,]*\$
```

### 3. 命令执行

```c
// 危险
system(user_command);  // RCE!
popen(user_command, "r");
execl("/bin/sh", "sh", "-c", user_command, NULL);
execvp(user_program, user_args);

// 动态库加载
dlopen(user_path, RTLD_NOW);  // 加载恶意库

// 搜索模式
system|popen|exec[lv]p?e?|dlopen
```

### 4. 整数溢出

```c
// 有符号溢出
int size = user_value;
if (size < 0) return;  // 检查负数
char *buf = malloc(size);  // 如果size很大呢?

// 乘法溢出
size_t total = count * sizeof(struct item);  // 可能溢出
char *buf = malloc(total);

// 安全: 使用溢出检查
if (count > SIZE_MAX / sizeof(struct item)) {
    return -1;  // 溢出
}

// 搜索模式
malloc\(.*\*|size.*\*
```

### 5. Use-After-Free

```c
// 危险模式
free(ptr);
// ... 其他代码 ...
use(ptr);  // Use-After-Free!

// Double-Free
free(ptr);
free(ptr);  // Double-Free!

// 安全: 释放后置NULL
free(ptr);
ptr = NULL;

// 搜索模式: 较难静态检测，需要数据流分析
```

### 6. 文件操作

```c
// 路径遍历
char path[256];
snprintf(path, sizeof(path), "/data/%s", user_filename);
FILE *f = fopen(path, "r");  // ../../../etc/passwd

// 符号链接攻击
// 检查文件存在 -> 打开文件 之间的TOCTOU
if (access(path, R_OK) == 0) {
    // 攻击者可能在此刻替换符号链接
    fd = open(path, O_RDONLY);
}

// 临时文件预测
tmpnam(temp_path);  // 可预测! 使用mkstemp

// 搜索模式
fopen|open + 用户输入路径
tmpnam|tempnam  # 不安全临时文件
```

### 7. 密码学问题

```c
// 弱随机
srand(time(NULL));
int key = rand();  // 可预测!

// 应使用
#include <fcntl.h>
int fd = open("/dev/urandom", O_RDONLY);
read(fd, &key, sizeof(key));

// 或 getrandom() (Linux 3.17+)
getrandom(&key, sizeof(key), 0);

// 搜索模式
srand|rand\(\)|random\(\)
```

### 8. 竞态条件

```c
// TOCTOU (Time-of-Check to Time-of-Use)
if (access(file, W_OK) == 0) {
    // 窗口期: 攻击者可修改文件
    fd = open(file, O_WRONLY);
}

// 安全: 直接操作，检查返回值
fd = open(file, O_WRONLY);
if (fd < 0) {
    // 处理错误
}

// 搜索模式
access.*open|stat.*open
```

---

## C/C++审计清单

```
缓冲区溢出:
- [ ] 搜索 strcpy/sprintf/gets/strcat
- [ ] 搜索 memcpy + 未验证长度
- [ ] 检查 scanf 格式宽度

格式化字符串:
- [ ] 搜索 printf(变量)
- [ ] 验证格式化函数参数

命令执行:
- [ ] 搜索 system/popen/exec*
- [ ] 搜索 dlopen

整数安全:
- [ ] 检查 malloc 参数溢出
- [ ] 检查有符号/无符号转换
- [ ] 验证数组索引

内存安全:
- [ ] 检查 free 后使用
- [ ] 检查 double-free
- [ ] 验证指针有效性

文件操作:
- [ ] 检查路径构造
- [ ] 搜索 tmpnam/tempnam
- [ ] 检查 TOCTOU 问题

密码学:
- [ ] 搜索 rand()/srand()
- [ ] 验证随机数来源
- [ ] 检查自实现加密
```

---

## 审计正则

```regex
# 缓冲区溢出
strcpy|sprintf|gets|strcat|scanf
memcpy\s*\([^)]*,[^)]*,[^)]*\$

# 格式化字符串
printf\s*\([^,)]*\)|fprintf\s*\([^,]*,[^,)]*\)

# 命令执行
system\s*\(|popen\s*\(|exec[lvpe]+\s*\(|dlopen\s*\(

# 整数溢出
malloc\s*\(.*\*|calloc\s*\(

# 文件操作
tmpnam\s*\(|tempnam\s*\(|access\s*\(.*\)\s*.*open\s*\(

# 弱随机
srand\s*\(|rand\s*\(\)
```

---

## 常用工具

```bash
# 静态分析
cppcheck --enable=all src/
clang --analyze src/
scan-build make

# 动态分析
valgrind --leak-check=full ./program
AddressSanitizer: gcc -fsanitize=address
UndefinedBehaviorSanitizer: gcc -fsanitize=undefined

# Fuzzing
afl-fuzz -i testcases -o findings ./program @@
```

---

## 最小 PoC 示例
```c
// 缓冲区溢出
char buf[8];
gets(buf); // PoC: echo AAAAAAAAAAAAAAAAA | ./vuln

// 格式化字符串
printf(user_input); // PoC: ./vuln "%x %x %x %n"
```

---

## 高级漏洞类型

### 9. 堆利用漏洞

#### Heap Overflow (堆溢出)

```c
// 🔴 堆溢出
struct chunk {
    size_t size;
    char data[64];
    void (*handler)(void);  // 函数指针被覆盖
};

struct chunk *c = malloc(sizeof(struct chunk));
strcpy(c->data, user_input);  // 溢出到 handler

// 搜索模式: 堆分配后的危险操作
malloc.*strcpy|malloc.*memcpy|calloc.*sprintf
```

#### Use-After-Free (UAF)

```c
// 🔴 经典 UAF
void *ptr = malloc(64);
free(ptr);
// ... 程序其他逻辑 ...
memcpy(ptr, user_data, 64);  // UAF!

// 🔴 回调函数中的 UAF
struct obj {
    void (*callback)(void);
    char data[32];
};

struct obj *o = create_obj();
register_callback(o->callback);  // 存储指针
free(o);
// 稍后 callback 被调用 -> UAF

// 搜索模式
free\s*\([^)]+\).*\n.*\1  # 正则较难，需数据流分析
```

#### Double-Free

```c
// 🔴 显式 Double-Free
void *ptr = malloc(64);
free(ptr);
free(ptr);  // Double-Free!

// 🔴 隐式 Double-Free (多处释放)
void cleanup_a(void *ptr) { free(ptr); }
void cleanup_b(void *ptr) { free(ptr); }

cleanup_a(shared_ptr);
cleanup_b(shared_ptr);  // Double-Free!

// 🔴 错误处理路径中的 Double-Free
void *ptr = malloc(64);
if (error_condition) {
    free(ptr);
    return -1;  // 忘记 return 或继续执行
}
free(ptr);  // Double-Free!

// 搜索模式
free.*\n.*free|free.*goto.*free
```

#### Heap Feng Shui (堆布局控制)

```c
// 攻击技术: 通过控制分配/释放顺序来布局堆
// 利用场景:
// 1. UAF 时控制释放后的内存内容
// 2. Heap Overflow 时控制溢出目标

// 审计要点:
// - 分配大小是否用户可控
// - 释放时机是否用户可控
// - 是否存在类型混淆可能
```

### 10. 类型混淆

```c
// 🔴 类型双关 (Type Punning)
union {
    float f;
    uint32_t i;
} u;
u.f = user_float;
// 通过 u.i 读取可绕过浮点检查

// 🔴 void* 类型混淆
void process(void *data, int type) {
    if (type == TYPE_ADMIN) {
        struct admin *a = (struct admin *)data;
        // ...
    } else {
        struct user *u = (struct user *)data;  // 错误类型?
        // ...
    }
}

// 🔴 C++ 虚函数类型混淆
class Base { virtual void func(); };
class Derived : public Base { void func() override; };

Base *obj = user_controlled_cast();
obj->func();  // 虚表被控制 -> RCE

// 搜索模式
\(.*\*\)\s*[a-zA-Z_]|reinterpret_cast|dynamic_cast
```

### 11. 空指针解引用

```c
// 🔴 未检查 malloc 返回值
char *buf = malloc(size);
memcpy(buf, src, size);  // 如果 malloc 返回 NULL?

// 🔴 未检查函数返回值
struct config *cfg = get_config();
printf("value: %s\n", cfg->value);  // cfg 可能为 NULL

// 🔴 条件检查后的空指针
if (ptr == NULL) {
    log_error("ptr is null");
    // 忘记 return!
}
ptr->field = value;  // 空指针解引用

// 🟢 安全
char *buf = malloc(size);
if (buf == NULL) {
    return -ENOMEM;
}

// 搜索模式
malloc.*(?!if.*NULL)|=.*\(\).*\n.*->(?!.*if.*NULL)
```

### 12. 未初始化变量

```c
// 🔴 栈未初始化
void func(int flag) {
    char buffer[256];  // 未初始化!
    if (flag) {
        strcpy(buffer, "data");
    }
    printf("%s\n", buffer);  // flag=0 时泄露栈数据
}

// 🔴 堆未初始化
struct user *u = malloc(sizeof(*u));
if (condition) {
    u->is_admin = 0;
}
// is_admin 可能保留之前的堆数据

// 🟢 安全
char buffer[256] = {0};  // 初始化
struct user *u = calloc(1, sizeof(*u));  // 零初始化

// 搜索模式
char\s+[a-zA-Z_]+\[[0-9]+\];(?!.*=)
malloc\s*\((?!.*memset|.*calloc)
```

### 13. 信号处理竞态

```c
// 🔴 非异步信号安全的函数
void handler(int sig) {
    printf("Signal received\n");  // printf 非异步安全!
    free(global_ptr);  // free 非异步安全!
    exit(1);  // 可能导致问题
}

// 🔴 信号处理中的全局变量
volatile sig_atomic_t flag = 0;  // 需要 volatile
int normal_var = 0;  // 非原子访问

void handler(int sig) {
    normal_var = 1;  // 竞态!
}

// 异步信号安全函数列表 (POSIX):
// _Exit, abort, accept, access, alarm, bind, cfgetispeed, ...
// 不包含: printf, malloc, free, exit 等

// 搜索模式
signal\s*\(.*\n.*printf|signal\s*\(.*\n.*malloc|signal\s*\(.*\n.*free
```

### 14. 整数截断与符号问题

```c
// 🔴 有符号/无符号比较
int user_len = get_user_input();  // 可能为负数
if (user_len < MAX_SIZE) {  // -1 < MAX_SIZE 为真
    char *buf = malloc(user_len);  // malloc(-1) = malloc(SIZE_MAX)
}

// 🔴 整数截断
size_t big_size = get_size();  // 大数
uint16_t small_size = big_size;  // 截断!
char *buf = malloc(small_size);
memcpy(buf, data, big_size);  // 溢出!

// 🔴 size_t 回绕
size_t len = user_len + 1;  // 如果 user_len = SIZE_MAX?
char *buf = malloc(len);  // malloc(0)

// 🟢 安全检查
if (user_len > 0 && user_len < MAX_SIZE) {
    // 同时检查正数和上限
}

// 安全加法
if (a > SIZE_MAX - b) {
    return -1;  // 溢出
}
size_t sum = a + b;

// 搜索模式
int.*=.*size_t|size_t.*=.*int|uint16_t.*=.*size_t|\+\s*1\s*\)
```

### 15. 内存泄露

```c
// 🔴 错误处理路径泄露
void *buf1 = malloc(64);
void *buf2 = malloc(64);
if (error) {
    return -1;  // 泄露 buf1 和 buf2!
}

// 🔴 重复赋值泄露
char *ptr = malloc(32);
ptr = malloc(64);  // 第一次分配泄露!

// 🔴 异常处理泄露 (C++)
try {
    char *buf = new char[64];
    throw std::exception();
} catch (...) {
    // buf 泄露!
}

// 🟢 安全: RAII (C++)
std::unique_ptr<char[]> buf(new char[64]);
// 自动释放

// 搜索模式
malloc.*\n.*return(?!.*free)|new\s+.*throw(?!.*delete)
```

---

## 现代利用技术审计要点

### Stack Canary 绕过

```c
// 审计要点:
// 1. 是否启用 -fstack-protector-all
// 2. 是否存在信息泄露可获取 canary
// 3. 是否存在绕过 canary 的写入路径 (如只覆盖局部变量)

// 检查编译选项
grep -r "fstack-protector\|fno-stack-protector" Makefile CMakeLists.txt
```

### ASLR/PIE 绕过

```c
// 审计要点:
// 1. 是否存在地址泄露
// 2. 是否启用 PIE (-fPIE -pie)
// 3. 是否存在未随机化的区域

// 常见泄露源:
// - printf %p 或 %s 泄露
// - 错误消息包含指针
// - 未初始化数据包含指针

// 检查 PIE
file ./binary | grep "shared object"  # PIE 编译
readelf -h ./binary | grep Type  # EXEC 表示非 PIE
```

### NX/DEP 绕过

```c
// 现代利用技术:
// 1. ROP (Return-Oriented Programming)
// 2. JOP (Jump-Oriented Programming)
// 3. ret2libc

// 审计要点:
// - 是否存在有用的 gadget
// - 是否可控制返回地址
// - 是否存在 libc 版本泄露

// 检查 NX
readelf -l ./binary | grep GNU_STACK
# RW 表示可执行栈 (危险)
# RW- 或无 E 表示 NX 启用
```

### RELRO 绕过

```c
// RELRO 保护 GOT 表:
// Partial RELRO: 某些 GOT 条目可写
// Full RELRO: GOT 完全只读

// 审计要点:
// - 是否启用 Full RELRO
// - 是否存在其他可覆盖的函数指针

// 检查 RELRO
readelf -l ./binary | grep GNU_RELRO
checksec --file=./binary
```

---

## 安全编译选项检查

```bash
# 检查二进制安全特性
checksec --file=./binary

# 手动检查
# Stack Canary
readelf -s ./binary | grep __stack_chk

# FORTIFY_SOURCE
objdump -d ./binary | grep __fortify

# PIE
file ./binary

# RELRO
readelf -l ./binary | grep GNU_RELRO

# NX
readelf -l ./binary | grep GNU_STACK
```

**推荐编译选项**:
```makefile
CFLAGS = -fstack-protector-all \
         -D_FORTIFY_SOURCE=2 \
         -fPIE -pie \
         -Wl,-z,relro,-z,now \
         -Wl,-z,noexecstack
```

---

## 高级审计清单

```
堆漏洞:
- [ ] 搜索 malloc 后的 strcpy/memcpy
- [ ] 追踪 free 后的指针使用
- [ ] 检查 double-free 可能
- [ ] 分析分配大小是否可控

类型安全:
- [ ] 检查 void* 转换
- [ ] 检查 union 类型双关
- [ ] 验证 C++ 虚函数调用

整数安全:
- [ ] 检查有符号/无符号混用
- [ ] 检查整数截断
- [ ] 验证算术运算溢出

指针安全:
- [ ] 检查 NULL 指针检查
- [ ] 检查未初始化变量
- [ ] 验证数组边界

编译保护:
- [ ] 检查 Stack Canary
- [ ] 检查 ASLR/PIE
- [ ] 检查 NX/DEP
- [ ] 检查 RELRO
```

---

## 越界读取 (CWE-125)

### 危险模式

```c
// 1. 数组越界读取
// 危险: 无边界检查
int arr[10];
int value = arr[index];  // index 可能 >= 10，泄露栈/堆数据

// 安全: 边界检查
if (index >= 0 && index < 10) {
    value = arr[index];
}

// 2. 字符串越界读取
// 危险: 依赖 NUL 终止符
char* get_char(char* str, int pos) {
    return str[pos];  // pos 可能超过字符串长度
}

// 安全: 使用 strnlen 或传递长度
char get_char_safe(char* str, size_t len, size_t pos) {
    if (pos < len) {
        return str[pos];
    }
    return '\0';
}

// 3. 指针算术越界
// 危险: 指针运算无边界
void read_buffer(char* buf, int offset) {
    char* ptr = buf + offset;  // offset 可能导致越界
    char c = *ptr;  // 越界读取
}

// 安全: 验证指针范围
void read_buffer_safe(char* buf, size_t buf_len, size_t offset) {
    if (offset < buf_len) {
        char c = buf[offset];
    }
}

// 4. 结构体成员越界
// 危险: 变长数组成员
struct packet {
    int length;
    char data[1];  // 柔性数组
};

void process_packet(struct packet* pkt) {
    // 读取 data[pkt->length - 1] 可能越界
    for (int i = 0; i < pkt->length; i++) {
        process_byte(pkt->data[i]);  // 需验证 length 合法性
    }
}

// 安全: 验证长度
void process_packet_safe(struct packet* pkt, size_t total_size) {
    size_t max_data_len = total_size - offsetof(struct packet, data);
    if (pkt->length > max_data_len) {
        return;  // 长度不合法
    }
    for (size_t i = 0; i < pkt->length; i++) {
        process_byte(pkt->data[i]);
    }
}
```

### 信息泄露场景

```c
// Heartbleed 类型漏洞
// 危险: 用户控制的长度参数
void heartbeat_response(char* payload, int payload_len, int claimed_len) {
    char response[1024];
    // 使用用户声称的长度而非实际长度
    memcpy(response, payload, claimed_len);  // 越界读取！
    send(sock, response, claimed_len, 0);    // 泄露内存数据
}

// 安全: 使用实际长度
void heartbeat_response_safe(char* payload, size_t actual_len, size_t claimed_len) {
    char response[1024];
    size_t copy_len = (claimed_len < actual_len) ? claimed_len : actual_len;
    copy_len = (copy_len < sizeof(response)) ? copy_len : sizeof(response);
    memcpy(response, payload, copy_len);
    send(sock, response, copy_len, 0);
}

// 格式化字符串泄露
// 危险: %s 无长度限制
printf("Data: %s\n", user_data);  // 可能读到 NUL 之后的数据

// 安全: 使用精度限制
printf("Data: %.100s\n", user_data);  // 最多100字符
```

### C++ 特有问题

```cpp
// 1. vector 越界
std::vector<int> v = {1, 2, 3};
int x = v[10];  // 未定义行为，无异常

// 安全: 使用 at()
try {
    int x = v.at(10);  // 抛出 std::out_of_range
} catch (const std::out_of_range& e) {
    // 处理越界
}

// 2. string 越界
std::string s = "hello";
char c = s[100];  // 未定义行为

// 安全
if (index < s.size()) {
    char c = s[index];
}

// 3. 迭代器越界
std::vector<int>::iterator it = v.begin();
std::advance(it, 100);  // 越界迭代器
int val = *it;  // 未定义行为

// 安全: 检查距离
if (std::distance(v.begin(), it) < v.size()) {
    int val = *it;
}
```

### 检测命令

```bash
# 查找数组访问
grep -rn "\[.*\]" --include="*.c" --include="*.cpp" | grep -v "define\|const"

# 查找指针算术
grep -rn "\*.*+\|+.*\*" --include="*.c" --include="*.cpp"

# 查找 memcpy/memmove 无长度验证
grep -rn "memcpy\|memmove" --include="*.c" --include="*.cpp" -B 2 | grep -v "sizeof\|strlen\|min"

# 静态分析工具
cppcheck --enable=all --inconclusive src/
scan-build make
```

---

**版本**: 2.0
**更新日期**: 2026-02-04
**覆盖漏洞类型**: 20+ (含CWE-125越界读取)
