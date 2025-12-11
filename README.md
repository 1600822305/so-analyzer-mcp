# SO Analyzer MCP

Native库（SO文件）分析工具，支持Flutter应用抓包。**免费开源的IDA Pro替代品！**

## 🎯 特色功能

- ✅ **反编译** - 支持radare2/Ghidra/轻量级模式
- ✅ **函数识别** - 识别所有函数（包括未导出）
- ✅ **调用图分析** - 生成DOT格式可视化
- ✅ **控制流图** - 基本块分析
- ✅ **Flutter SSL绕过** - 一键完成
- ✅ **字符串加密检测** - 熵值分析+XOR检测

## 📊 工具总览 (30个)

### SO基础分析 (8个)

| 工具 | 说明 |
|------|------|
| `so_check_env` | 检查分析环境 |
| `so_list_libs` | 列出APK中的所有SO库 |
| `so_extract` | 从APK提取SO文件 |
| `so_info` | 获取SO基本信息 |
| `so_exports` | 获取导出函数列表 |
| `so_imports` | 获取导入函数列表 |
| `so_strings` | 提取字符串 |
| `so_search_symbol` | 搜索符号 |

### Flutter专用 (6个)

| 工具 | 说明 |
|------|------|
| `flutter_detect` | 检测是否是Flutter应用 |
| `flutter_get_version` | 获取Flutter版本 |
| `flutter_find_ssl` | 查找SSL验证函数 |
| `flutter_ssl_offset_v2` | ⭐智能定位SSL函数 |
| `flutter_patch_ssl` | Patch SSL验证（绕过证书） |
| `flutter_patch_apk` | **一键patch Flutter APK** |

### 二进制修改 (5个)

| 工具 | 说明 |
|------|------|
| `so_patch_bytes` | 修改指定偏移的字节 |
| `so_search_bytes` | 搜索字节模式 |
| `so_replace_bytes` | 查找并替换字节 |
| `so_disassemble` | 反汇编代码 |
| `so_get_function_bytes` | 获取函数字节码 |

### 交叉引用分析 (4个)

| 工具 | 说明 |
|------|------|
| `so_xref_string` | ⭐查找字符串交叉引用 |
| `so_find_function` | 根据地址查找函数 |
| `so_analyze_function` | 分析函数特征 |
| `so_get_sections` | 获取代码段信息 |

### ⭐ 高级分析 (9个) - NEW!

| 工具 | 说明 |
|------|------|
| `so_list_all_functions` | 识别所有函数（包括未导出） |
| `so_callgraph` | 生成调用关系图 + DOT图 |
| `so_get_cfg` | 生成控制流图 + DOT图 |
| `so_analyze_function_advanced` | 全面函数分析 |
| `so_decompile` | ⭐反编译生成伪代码 |
| `so_detect_encryption` | 字符串加密检测 |
| `so_trace_register` | 数据流/寄存器追踪 |
| `so_check_radare2` | 检查radare2环境 |
| `so_check_ghidra` | 检查Ghidra环境 |

## 安装

```bash
cd so-analyzer-mcp
pip install -r requirements.txt
```

## MCP配置

```json
{
  "mcpServers": {
    "so-analyzer": {
      "command": "python",
      "args": ["K:/path/to/so-analyzer-mcp/run_server.py"]
    }
  }
}
```

## 使用示例

```python
# 1. 列出SO库
so_list_libs(apk_path="app.apk")

# 2. 检测Flutter
flutter_detect(apk_path="app.apk")

# 3. 提取SO文件
so_extract(apk_path="app.apk", lib_name="libflutter.so", arch="arm64-v8a")

# 4. 搜索SSL相关函数
so_search_symbol(so_path="libflutter.so", pattern="ssl")

# 5. 提取字符串
so_strings(so_path="libflutter.so", search="certificate")
```

## 项目结构

```
so-analyzer-mcp/
├── so_analyzer/
│   ├── __init__.py
│   ├── config.py           # 配置
│   ├── server.py           # MCP服务器 (30个工具)
│   ├── so_utils.py         # SO基础分析
│   ├── flutter_utils.py    # Flutter专用工具
│   ├── flutter_utils_v2.py # Flutter SSL智能定位
│   ├── patch_utils.py      # 二进制修改
│   ├── xref_utils.py       # 交叉引用分析
│   ├── advanced_utils.py   # 高级分析 (NEW!)
│   └── decompile_utils.py  # 反编译工具 (NEW!)
├── radare2/               # radare2 (可选)
├── run_server.py          # 启动脚本
├── requirements.txt
└── README.md
```

## 依赖

**必需**:
- **mcp** - MCP协议库
- **lief** - 二进制文件解析库
- **capstone** - 反汇编引擎

**可选**:
- **radare2** - 反编译 (推荐，~50MB)
- **Ghidra** - 高质量反编译 (~400MB)

## 已完成功能 ✅

- [x] Flutter SSL Patch (一键绕过)
- [x] SO文件修改
- [x] 反编译 (radare2/Ghidra/简单模式)
- [x] 函数识别 (包括未导出)
- [x] 调用图分析
- [x] 控制流图
- [x] 字符串加密检测
- [x] 数据流分析

## 与 IDA Pro MCP 对比

| 功能 | IDA Pro MCP | SO Analyzer MCP |
|------|-------------|-----------------|
| 反编译 | ✅ Hex-Rays | ✅ radare2 |
| 函数识别 | ✅ | ✅ |
| 调用图 | ✅ | ✅ |
| 控制流图 | ✅ | ✅ |
| Flutter SSL | ❌ | ✅ 一键完成 |
| APK操作 | ❌ | ✅ |
| 价格 | $1000+ | **免费** |
