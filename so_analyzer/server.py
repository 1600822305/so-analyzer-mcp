"""SO Analyzer MCP Server"""
import json
from mcp.server import Server
from mcp.types import Tool, TextContent

from .so_utils import (
    check_lief,
    list_libs_from_apk,
    extract_so_from_apk,
    get_so_info,
    get_exports,
    get_imports,
    get_strings,
    search_symbol,
    detect_flutter
)
from .flutter_utils import (
    get_flutter_version,
    find_ssl_verify_function,
    patch_ssl_verify,
    flutter_patch_apk
)
from .patch_utils import (
    patch_bytes,
    search_bytes,
    replace_bytes,
    disassemble,
    get_function_bytes
)

# 创建MCP服务器
server = Server("so-analyzer")


def get_all_tools() -> list[Tool]:
    """获取所有工具定义"""
    return [
        # ===== SO基础分析 =====
        Tool(
            name="so_check_env",
            description="检查SO分析环境（lief库是否可用）",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="so_list_libs",
            description="列出APK中的所有SO库",
            inputSchema={
                "type": "object",
                "properties": {
                    "apk_path": {"type": "string", "description": "APK文件路径"}
                },
                "required": ["apk_path"]
            }
        ),
        Tool(
            name="so_extract",
            description="从APK中提取SO文件",
            inputSchema={
                "type": "object",
                "properties": {
                    "apk_path": {"type": "string", "description": "APK文件路径"},
                    "lib_name": {"type": "string", "description": "SO库名称（如 libflutter.so）"},
                    "arch": {"type": "string", "description": "架构（默认arm64-v8a）"},
                    "output_dir": {"type": "string", "description": "输出目录（可选）"}
                },
                "required": ["apk_path", "lib_name"]
            }
        ),
        Tool(
            name="so_info",
            description="获取SO文件基本信息（架构、导出/导入数量、依赖等）",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"}
                },
                "required": ["so_path"]
            }
        ),
        Tool(
            name="so_exports",
            description="获取SO导出函数列表",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "search": {"type": "string", "description": "搜索过滤"},
                    "limit": {"type": "integer", "description": "最多返回数量（默认100）"}
                },
                "required": ["so_path"]
            }
        ),
        Tool(
            name="so_imports",
            description="获取SO导入函数列表",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "search": {"type": "string", "description": "搜索过滤"},
                    "limit": {"type": "integer", "description": "最多返回数量（默认100）"}
                },
                "required": ["so_path"]
            }
        ),
        Tool(
            name="so_strings",
            description="提取SO文件中的字符串",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "min_length": {"type": "integer", "description": "最小字符串长度（默认4）"},
                    "search": {"type": "string", "description": "搜索过滤"},
                    "limit": {"type": "integer", "description": "最多返回数量（默认200）"}
                },
                "required": ["so_path"]
            }
        ),
        Tool(
            name="so_search_symbol",
            description="搜索符号（导出+导入函数）",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "pattern": {"type": "string", "description": "搜索模式"},
                    "limit": {"type": "integer", "description": "最多返回数量（默认50）"}
                },
                "required": ["so_path", "pattern"]
            }
        ),
        
        # ===== Flutter工具 =====
        Tool(
            name="flutter_detect",
            description="检测是否是Flutter应用",
            inputSchema={
                "type": "object",
                "properties": {
                    "apk_path": {"type": "string", "description": "APK文件路径"}
                },
                "required": ["apk_path"]
            }
        ),
        Tool(
            name="flutter_get_version",
            description="获取Flutter版本",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "libflutter.so文件路径"}
                },
                "required": ["so_path"]
            }
        ),
        Tool(
            name="flutter_find_ssl",
            description="查找SSL验证函数",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"}
                },
                "required": ["so_path"]
            }
        ),
        Tool(
            name="flutter_patch_ssl",
            description="Patch SSL验证（绕过证书检测，用于抓包）",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "libflutter.so文件路径"},
                    "output_path": {"type": "string", "description": "输出路径（可选）"}
                },
                "required": ["so_path"]
            }
        ),
        Tool(
            name="flutter_patch_apk",
            description="自动patch Flutter APK的SSL验证（一键操作）",
            inputSchema={
                "type": "object",
                "properties": {
                    "apk_path": {"type": "string", "description": "APK文件路径"},
                    "output_path": {"type": "string", "description": "输出路径（可选）"},
                    "arch": {"type": "string", "description": "架构（默认arm64-v8a）"}
                },
                "required": ["apk_path"]
            }
        ),
        
        # ===== 二进制修改工具 =====
        Tool(
            name="so_patch_bytes",
            description="在指定偏移处修改字节",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "文件路径"},
                    "offset": {"type": "integer", "description": "偏移量"},
                    "new_bytes": {"type": "string", "description": "新字节（十六进制字符串）"},
                    "output_path": {"type": "string", "description": "输出路径（可选）"}
                },
                "required": ["file_path", "offset", "new_bytes"]
            }
        ),
        Tool(
            name="so_search_bytes",
            description="搜索字节模式",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "文件路径"},
                    "pattern": {"type": "string", "description": "字节模式（十六进制字符串）"},
                    "limit": {"type": "integer", "description": "最多返回数量（默认20）"}
                },
                "required": ["file_path", "pattern"]
            }
        ),
        Tool(
            name="so_replace_bytes",
            description="查找并替换字节",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "文件路径"},
                    "find_pattern": {"type": "string", "description": "查找模式（十六进制）"},
                    "replace_with": {"type": "string", "description": "替换内容（十六进制）"},
                    "output_path": {"type": "string", "description": "输出路径（可选）"},
                    "replace_all": {"type": "boolean", "description": "是否替换所有"}
                },
                "required": ["file_path", "find_pattern", "replace_with"]
            }
        ),
        Tool(
            name="so_disassemble",
            description="反汇编指定地址的代码",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "address": {"type": "integer", "description": "起始地址"},
                    "size": {"type": "integer", "description": "字节数（默认64）"},
                    "arch": {"type": "string", "description": "架构（auto/arm64/arm）"}
                },
                "required": ["so_path", "address"]
            }
        ),
        Tool(
            name="so_get_function_bytes",
            description="获取函数的字节码",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "function_name": {"type": "string", "description": "函数名"},
                    "size": {"type": "integer", "description": "读取字节数（默认64）"}
                },
                "required": ["so_path", "function_name"]
            }
        )
    ]


@server.list_tools()
async def list_tools():
    """列出所有可用工具"""
    return get_all_tools()


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    """调用工具"""
    result = None
    
    try:
        # SO基础分析
        if name == "so_check_env":
            result = check_lief()
        
        elif name == "so_list_libs":
            result = list_libs_from_apk(apk_path=arguments["apk_path"])
        
        elif name == "so_extract":
            result = extract_so_from_apk(
                apk_path=arguments["apk_path"],
                lib_name=arguments["lib_name"],
                arch=arguments.get("arch", "arm64-v8a"),
                output_dir=arguments.get("output_dir")
            )
        
        elif name == "so_info":
            result = get_so_info(so_path=arguments["so_path"])
        
        elif name == "so_exports":
            result = get_exports(
                so_path=arguments["so_path"],
                search=arguments.get("search", ""),
                limit=arguments.get("limit", 100)
            )
        
        elif name == "so_imports":
            result = get_imports(
                so_path=arguments["so_path"],
                search=arguments.get("search", ""),
                limit=arguments.get("limit", 100)
            )
        
        elif name == "so_strings":
            result = get_strings(
                so_path=arguments["so_path"],
                min_length=arguments.get("min_length", 4),
                search=arguments.get("search", ""),
                limit=arguments.get("limit", 200)
            )
        
        elif name == "so_search_symbol":
            result = search_symbol(
                so_path=arguments["so_path"],
                pattern=arguments["pattern"],
                limit=arguments.get("limit", 50)
            )
        
        # Flutter工具
        elif name == "flutter_detect":
            result = detect_flutter(apk_path=arguments["apk_path"])
        
        elif name == "flutter_get_version":
            result = get_flutter_version(so_path=arguments["so_path"])
        
        elif name == "flutter_find_ssl":
            result = find_ssl_verify_function(so_path=arguments["so_path"])
        
        elif name == "flutter_patch_ssl":
            result = patch_ssl_verify(
                so_path=arguments["so_path"],
                output_path=arguments.get("output_path")
            )
        
        elif name == "flutter_patch_apk":
            result = flutter_patch_apk(
                apk_path=arguments["apk_path"],
                output_path=arguments.get("output_path"),
                arch=arguments.get("arch", "arm64-v8a")
            )
        
        # 二进制修改
        elif name == "so_patch_bytes":
            result = patch_bytes(
                file_path=arguments["file_path"],
                offset=arguments["offset"],
                new_bytes=bytes.fromhex(arguments["new_bytes"]),
                output_path=arguments.get("output_path")
            )
        
        elif name == "so_search_bytes":
            result = search_bytes(
                file_path=arguments["file_path"],
                pattern=bytes.fromhex(arguments["pattern"]),
                limit=arguments.get("limit", 20)
            )
        
        elif name == "so_replace_bytes":
            result = replace_bytes(
                file_path=arguments["file_path"],
                find_pattern=bytes.fromhex(arguments["find_pattern"]),
                replace_with=bytes.fromhex(arguments["replace_with"]),
                output_path=arguments.get("output_path"),
                replace_all=arguments.get("replace_all", False)
            )
        
        elif name == "so_disassemble":
            result = disassemble(
                so_path=arguments["so_path"],
                address=arguments["address"],
                size=arguments.get("size", 64),
                arch=arguments.get("arch", "auto")
            )
        
        elif name == "so_get_function_bytes":
            result = get_function_bytes(
                so_path=arguments["so_path"],
                function_name=arguments["function_name"],
                size=arguments.get("size", 64)
            )
        
        else:
            result = {"success": False, "error": f"Unknown tool: {name}"}
    
    except Exception as e:
        result = {"success": False, "error": str(e)}
    
    return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False, indent=2))]


async def main():
    """主入口"""
    from mcp.server.stdio import stdio_server
    
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )
