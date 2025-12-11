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
from .flutter_utils_v2 import find_ssl_verify_function_v2
from .patch_utils import (
    patch_bytes,
    search_bytes,
    replace_bytes,
    disassemble,
    get_function_bytes
)
from .xref_utils import (
    get_code_sections,
    find_string_offset,
    xref_string,
    find_function_by_address,
    analyze_function
)
from .advanced_utils import (
    list_all_functions,
    callgraph,
    get_cfg,
    analyze_function_advanced,
    detect_string_encryption,
    trace_register_value,
    find_instruction_pattern
)
from .decompile_utils import (
    check_ghidra,
    check_radare2,
    decompile
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
        Tool(
            name="flutter_ssl_offset_v2",
            description="⭐核心工具！模拟IDA分析流程：1.搜索ssl_client 2.xrefs_to 3.智能选择函数 4.生成脚本",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "libflutter.so文件路径"}
                },
                "required": ["so_path"]
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
        ),
        
        # ===== 交叉引用分析工具 =====
        Tool(
            name="so_xref_string",
            description="⭐核心工具！查找字符串的交叉引用（哪些代码引用了这个字符串）",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "search_string": {"type": "string", "description": "要搜索的字符串"},
                    "max_xrefs": {"type": "integer", "description": "最多返回的交叉引用数量（默认20）"}
                },
                "required": ["so_path", "search_string"]
            }
        ),
        Tool(
            name="so_find_function",
            description="根据地址查找所属的函数",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "address": {"type": "integer", "description": "地址"}
                },
                "required": ["so_path", "address"]
            }
        ),
        Tool(
            name="so_analyze_function",
            description="分析函数特征，判断是否是SSL验证函数",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "function_address": {"type": "integer", "description": "函数地址"},
                    "size": {"type": "integer", "description": "分析的字节数（默认256）"}
                },
                "required": ["so_path", "function_address"]
            }
        ),
        Tool(
            name="so_get_sections",
            description="获取所有代码段信息",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"}
                },
                "required": ["so_path"]
            }
        ),
        
        # ===== 高级分析工具 (新增) =====
        Tool(
            name="so_list_all_functions",
            description="⭐识别所有函数（包括未导出的内部函数），通过扫描函数开头特征识别",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "limit": {"type": "integer", "description": "最大返回数量（默认2000）"},
                    "search": {"type": "string", "description": "搜索过滤（函数名）"}
                },
                "required": ["so_path"]
            }
        ),
        Tool(
            name="so_callgraph",
            description="⭐分析函数调用关系图，识别BL/BLR调用指令，生成DOT格式调用图",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "function_addr": {"type": "integer", "description": "函数虚拟地址"},
                    "max_depth": {"type": "integer", "description": "最大递归深度（默认3）"}
                },
                "required": ["so_path", "function_addr"]
            }
        ),
        Tool(
            name="so_get_cfg",
            description="⭐生成函数的控制流图(CFG)，识别基本块和分支边，生成DOT格式图",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "function_addr": {"type": "integer", "description": "函数虚拟地址"},
                    "max_size": {"type": "integer", "description": "最大分析字节数（默认8192）"}
                },
                "required": ["so_path", "function_addr"]
            }
        ),
        Tool(
            name="so_analyze_function_advanced",
            description="⭐全面分析函数特征：调用关系、系统调用、字符串引用、复杂度、类型判断(SSL/加密/网络)",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "function_address": {"type": "integer", "description": "函数虚拟地址"},
                    "size": {"type": "integer", "description": "分析的字节数（默认512）"}
                },
                "required": ["so_path", "function_address"]
            }
        ),
        Tool(
            name="so_decompile",
            description="⭐反编译函数生成伪代码。支持radare2(默认,轻量)/ghidra(高质量)/simple(无依赖)",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "address": {"type": "integer", "description": "函数虚拟地址"},
                    "method": {"type": "string", "description": "反编译方法: radare2(默认)/ghidra/simple"},
                    "size": {"type": "integer", "description": "分析字节数(simple模式，默认256)"}
                },
                "required": ["so_path", "address"]
            }
        ),
        Tool(
            name="so_check_ghidra",
            description="检查Ghidra环境是否可用",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="so_check_radare2",
            description="检查Radare2环境是否可用",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="so_detect_encryption",
            description="⭐检测字符串加密/混淆：分析熵值、检测XOR/Base64、查找解密函数",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "min_length": {"type": "integer", "description": "最小字符串长度（默认8）"},
                    "max_strings": {"type": "integer", "description": "最大分析字符串数（默认100）"}
                },
                "required": ["so_path"]
            }
        ),
        Tool(
            name="so_trace_register",
            description="⭐数据流分析：追踪寄存器值的来源，分析参数传递和返回值",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "function_addr": {"type": "integer", "description": "函数虚拟地址"},
                    "register": {"type": "string", "description": "目标寄存器（默认x0）"},
                    "size": {"type": "integer", "description": "分析字节数（默认512）"}
                },
                "required": ["so_path", "function_addr"]
            }
        ),
        Tool(
            name="so_find_instruction",
            description="⭐搜索指令模式。支持:简单指令(bl/svc/ret)、预定义模式(syscall/compare/xor)、正则表达式、指令序列(stp;mov;bl)",
            inputSchema={
                "type": "object",
                "properties": {
                    "so_path": {"type": "string", "description": "SO文件路径"},
                    "pattern": {"type": "string", "description": "搜索模式：指令名/预定义/正则/序列(分号分隔)"},
                    "operand_filter": {"type": "string", "description": "操作数过滤（可选，支持正则）"},
                    "limit": {"type": "integer", "description": "最大返回数量（默认100）"}
                },
                "required": ["so_path", "pattern"]
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
        
        elif name == "flutter_ssl_offset_v2":
            result = find_ssl_verify_function_v2(so_path=arguments["so_path"])
        
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
        
        # 交叉引用分析
        elif name == "so_xref_string":
            result = xref_string(
                so_path=arguments["so_path"],
                search_string=arguments["search_string"],
                max_xrefs=arguments.get("max_xrefs", 20)
            )
        
        elif name == "so_find_function":
            result = find_function_by_address(
                so_path=arguments["so_path"],
                address=arguments["address"]
            )
        
        elif name == "so_analyze_function":
            result = analyze_function(
                so_path=arguments["so_path"],
                function_address=arguments["function_address"],
                size=arguments.get("size", 256)
            )
        
        elif name == "so_get_sections":
            result = get_code_sections(so_path=arguments["so_path"])
        
        # 高级分析工具
        elif name == "so_list_all_functions":
            result = list_all_functions(
                so_path=arguments["so_path"],
                limit=arguments.get("limit", 2000),
                search=arguments.get("search", "")
            )
        
        elif name == "so_callgraph":
            result = callgraph(
                so_path=arguments["so_path"],
                function_addr=arguments["function_addr"],
                max_depth=arguments.get("max_depth", 3)
            )
        
        elif name == "so_get_cfg":
            result = get_cfg(
                so_path=arguments["so_path"],
                function_addr=arguments["function_addr"],
                max_size=arguments.get("max_size", 0x2000)
            )
        
        elif name == "so_analyze_function_advanced":
            result = analyze_function_advanced(
                so_path=arguments["so_path"],
                function_address=arguments["function_address"],
                size=arguments.get("size", 512)
            )
        
        elif name == "so_decompile":
            result = decompile(
                so_path=arguments["so_path"],
                address=arguments["address"],
                method=arguments.get("method", "radare2"),
                size=arguments.get("size", 256)
            )
        
        elif name == "so_check_ghidra":
            result = check_ghidra()
        
        elif name == "so_check_radare2":
            result = check_radare2()
        
        elif name == "so_detect_encryption":
            result = detect_string_encryption(
                so_path=arguments["so_path"],
                min_length=arguments.get("min_length", 8),
                max_strings=arguments.get("max_strings", 100)
            )
        
        elif name == "so_trace_register":
            result = trace_register_value(
                so_path=arguments["so_path"],
                function_addr=arguments["function_addr"],
                target_register=arguments.get("register", "x0"),
                size=arguments.get("size", 512)
            )
        
        elif name == "so_find_instruction":
            result = find_instruction_pattern(
                so_path=arguments["so_path"],
                pattern=arguments["pattern"],
                operand_filter=arguments.get("operand_filter", ""),
                limit=arguments.get("limit", 100)
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
