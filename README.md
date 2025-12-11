# SO Analyzer MCP

Native库（SO文件）分析工具，支持Flutter应用抓包。

## 功能

### SO基础分析

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

### Flutter工具

| 工具 | 说明 |
|------|------|
| `flutter_detect` | 检测是否是Flutter应用 |
| `flutter_get_version` | 获取Flutter版本 |
| `flutter_find_ssl` | 查找SSL验证函数 |
| `flutter_patch_ssl` | **Patch SSL验证（绕过证书）** |
| `flutter_patch_apk` | **一键patch Flutter APK** |

### 二进制修改

| 工具 | 说明 |
|------|------|
| `so_patch_bytes` | 修改指定偏移的字节 |
| `so_search_bytes` | 搜索字节模式 |
| `so_replace_bytes` | 查找并替换字节 |
| `so_disassemble` | 反汇编代码 |
| `so_get_function_bytes` | 获取函数字节码 |

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
│   ├── config.py          # 配置
│   ├── server.py          # MCP服务器
│   ├── so_utils.py        # SO基础分析
│   └── flutter_utils.py   # Flutter专用工具（待实现）
├── workspace/             # 工作目录
├── run_server.py          # 启动脚本
├── requirements.txt
└── README.md
```

## 依赖

- **mcp** - MCP协议库
- **lief** - 二进制文件解析库

## 后续计划

- [ ] Flutter SSL Patch
- [ ] SO文件修改
- [ ] Frida脚本生成
