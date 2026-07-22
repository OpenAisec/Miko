# .NET 反编译与反混淆参考

用于只有 `bin/*.dll`、`.exe`、`.aspx` 指向后端类但缺少 `.cs` 源码，或反编译产物疑似混淆的 .NET / ASP.NET 目标。

## 复用规则

已有 manifest 且 `status=success`、`input_dir` 与当前目标一致时，优先复用已有产物；`partial` 可复用成功项但必须标注失败范围；缺 manifest 的目录只能辅助阅读，不能当作完整证据。

## 混淆识别

反编译前先判断是否混淆；出现任一特征时，先反混淆再反编译：

- 成员名或类名出现 `\u0001`、`\u0002` 等不可见 Unicode。
- 类名、方法名、命名空间是无意义短名或符号。
- 字符串运行时解密、常量不可读。
- 方法体存在大量无意义跳转、try/catch、控制流平坦化。
- 元数据或字符串中出现 `Confuser`、`Eazfuscator`、`SmartAssembly`、`Dotfuscator`、`.NET Reactor` 等。

快速检查：

```bash
strings <目标.dll> | grep -iE 'confuser|eazfuscator|smartassembly|dotfuscator|reactor'
```

如果已生成反编译产物，也可以检查：

```bash
grep -rE '\\u00[0-9a-fA-F]{2}' <反编译目录> | head
```

## de4dot 反混淆

默认使用 `de4dot` 做 .NET 反混淆；多 DLL 目标必须整目录一次性处理，避免程序集间引用被重命名后断链。

检测混淆器：

```bash
de4dot -d -r <bin目录> -ru
```

整目录反混淆：

```bash
de4dot -r <bin目录> -ru -ro <反混淆目录>/bin_clean
```

单文件反混淆：

```bash
de4dot <目标.dll> -o <反混淆目录>/bin_clean/<目标-clean.dll>
```

反混淆后必须记录工具、版本、输入路径、产物位置、处理的 DLL/EXE、成功/失败/跳过原因。反混淆产物仅用于静态审计，不要替换生产程序集运行。

## ilspycmd 反编译

默认使用 `ilspycmd` 将 .NET 程序集导出为可检索的 C# 项目。

安装和验证：

```bash
dotnet tool install -g ilspycmd
ilspycmd --version
```

单个 DLL 反编译：

```bash
ilspycmd <目标.dll> -p --referencepath <bin目录> -o <反编译目录>/<程序集名>
```

若已经反混淆，输入与引用目录都改用 `bin_clean`：

```bash
ilspycmd <反混淆目录>/bin_clean/<目标.dll> -p --referencepath <反混淆目录>/bin_clean -o <反编译目录>/<程序集名>
```

批量反编译时只处理项目程序集，跳过常见系统/第三方库：

```bash
for f in <bin目录>/*.dll; do
  name=$(basename "$f" .dll)
  case "$name" in
    System.*|Microsoft.*|Mono.*|netstandard|mscorlib) continue ;;
  esac
  ilspycmd "$f" -p --referencepath <bin目录> -o "<反编译目录>/$name"
done
```

反编译失败、部分成功或跳过都必须写入 manifest；不要静默忽略入口程序集失败。
