"""Flutter libapp.so 分析工具 - 符号恢复与逆向分析"""
import os
import re
import json
import shutil
import subprocess
import tempfile
from typing import Optional, List, Dict
from pathlib import Path

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False


# ==================== 配置 ====================

# Blutter 路径（可通过环境变量设置）
BLUTTER_PATH = os.environ.get("BLUTTER_PATH", "")

# Darter 是否可用
try:
    import darter
    DARTER_AVAILABLE = True
except ImportError:
    DARTER_AVAILABLE = False


# ==================== Blutter 集成 ====================

def check_blutter() -> dict:
    """
    检查 Blutter 环境是否可用
    
    Returns:
        dict: {"available": bool, "path": str, "message": str}
    """
    global BLUTTER_PATH
    
    # 检查环境变量
    if BLUTTER_PATH and os.path.exists(BLUTTER_PATH):
        blutter_py = os.path.join(BLUTTER_PATH, "blutter.py")
        if os.path.exists(blutter_py):
            return {
                "available": True,
                "path": BLUTTER_PATH,
                "blutter_py": blutter_py,
                "message": "Blutter available"
            }
    
    # 检查常见路径
    common_paths = [
        os.path.expanduser("~/blutter"),
        os.path.expanduser("~/tools/blutter"),
        "C:/tools/blutter",
        "D:/tools/blutter",
        "/opt/blutter",
        "/usr/local/blutter",
    ]
    
    for path in common_paths:
        blutter_py = os.path.join(path, "blutter.py")
        if os.path.exists(blutter_py):
            BLUTTER_PATH = path
            return {
                "available": True,
                "path": path,
                "blutter_py": blutter_py,
                "message": "Blutter found"
            }
    
    # 检查 PATH
    try:
        result = subprocess.run(
            ["python", "-c", "import blutter"],
            capture_output=True,
            timeout=5
        )
        if result.returncode == 0:
            return {
                "available": True,
                "path": "system",
                "message": "Blutter available in Python path"
            }
    except:
        pass
    
    return {
        "available": False,
        "path": "",
        "message": "Blutter not found. Install from: https://github.com/worawit/blutter",
        "install_guide": [
            "git clone https://github.com/worawit/blutter",
            "cd blutter",
            "pip install -r requirements.txt",
            "set BLUTTER_PATH=<path_to_blutter>"
        ]
    }


def analyze_libapp_with_blutter(lib_dir: str, output_dir: Optional[str] = None,
                                 rebuild: bool = False) -> dict:
    """
    使用 Blutter 分析 Flutter libapp.so
    
    Args:
        lib_dir: 包含 libapp.so 和 libflutter.so 的目录 (如 lib/arm64-v8a)
        output_dir: 输出目录（可选）
        rebuild: 是否强制重新编译 Blutter
    
    Returns:
        dict: {
            "success": bool,
            "output_dir": str,
            "symbols": list,
            "frida_script": str,
            "objects": list
        }
    """
    # 检查 Blutter
    blutter_check = check_blutter()
    if not blutter_check["available"]:
        return {"success": False, "error": blutter_check["message"]}
    
    # 验证输入目录
    if not os.path.isdir(lib_dir):
        return {"success": False, "error": f"Directory not found: {lib_dir}"}
    
    libapp_path = os.path.join(lib_dir, "libapp.so")
    libflutter_path = os.path.join(lib_dir, "libflutter.so")
    
    if not os.path.exists(libapp_path):
        return {"success": False, "error": f"libapp.so not found in {lib_dir}"}
    
    if not os.path.exists(libflutter_path):
        return {"success": False, "error": f"libflutter.so not found in {lib_dir}"}
    
    # 创建输出目录
    if not output_dir:
        output_dir = os.path.join(os.path.dirname(lib_dir), "blutter_output")
    
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        # 构建命令
        blutter_py = blutter_check.get("blutter_py", "blutter.py")
        cmd = ["python", blutter_py, lib_dir, output_dir]
        
        if rebuild:
            cmd.append("--rebuild")
        
        # 执行 Blutter
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,  # 10分钟超时
            cwd=BLUTTER_PATH if BLUTTER_PATH else None
        )
        
        if result.returncode != 0:
            return {
                "success": False,
                "error": f"Blutter failed: {result.stderr}",
                "stdout": result.stdout
            }
        
        # 解析输出
        symbols = []
        frida_script = ""
        objects = []
        
        # 读取 asm 文件
        asm_dir = os.path.join(output_dir, "asm")
        if os.path.isdir(asm_dir):
            for asm_file in os.listdir(asm_dir):
                if asm_file.endswith(".txt"):
                    asm_path = os.path.join(asm_dir, asm_file)
                    symbols.extend(parse_blutter_asm(asm_path))
        
        # 读取 Frida 脚本
        frida_path = os.path.join(output_dir, "blutter_frida.js")
        if os.path.exists(frida_path):
            with open(frida_path, 'r', encoding='utf-8') as f:
                frida_script = f.read()
        
        # 读取对象池
        pp_path = os.path.join(output_dir, "pp.txt")
        if os.path.exists(pp_path):
            objects = parse_blutter_objects(pp_path)
        
        return {
            "success": True,
            "output_dir": output_dir,
            "symbols_count": len(symbols),
            "symbols": symbols[:100],  # 返回前100个
            "frida_script_path": frida_path if os.path.exists(frida_path) else None,
            "frida_script_preview": frida_script[:2000] if frida_script else None,
            "objects_count": len(objects),
            "objects_preview": objects[:50],
            "files": os.listdir(output_dir),
            "stdout": result.stdout[-1000:] if result.stdout else "",
            "error": ""
        }
    
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Blutter analysis timeout (>10 minutes)"}
    except Exception as e:
        import traceback
        return {"success": False, "error": f"{str(e)}\n{traceback.format_exc()}"}


def parse_blutter_asm(asm_path: str) -> List[dict]:
    """解析 Blutter ASM 输出文件"""
    symbols = []
    
    try:
        with open(asm_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # 匹配函数定义
        # 格式: library_url 'package:xxx/xxx.dart'
        #       class ClassName
        #         Function 'methodName': ... {
        
        current_library = ""
        current_class = ""
        
        # 匹配库
        lib_pattern = re.compile(r"library_url\s+'([^']+)'")
        # 匹配类
        class_pattern = re.compile(r"class\s+(\w+)")
        # 匹配函数
        func_pattern = re.compile(r"Function\s+'([^']+)':\s*\[([^\]]+)\]\s*\{")
        # 匹配地址
        addr_pattern = re.compile(r"0x([0-9a-fA-F]+)")
        
        lines = content.split('\n')
        i = 0
        while i < len(lines):
            line = lines[i]
            
            # 检查库
            lib_match = lib_pattern.search(line)
            if lib_match:
                current_library = lib_match.group(1)
            
            # 检查类
            class_match = class_pattern.search(line)
            if class_match:
                current_class = class_match.group(1)
            
            # 检查函数
            func_match = func_pattern.search(line)
            if func_match:
                func_name = func_match.group(1)
                func_addr_str = func_match.group(2)
                
                addr_match = addr_pattern.search(func_addr_str)
                func_addr = addr_match.group(1) if addr_match else "unknown"
                
                symbols.append({
                    "library": current_library,
                    "class": current_class,
                    "function": func_name,
                    "full_name": f"{current_class}.{func_name}" if current_class else func_name,
                    "address": f"0x{func_addr}",
                    "type": "function"
                })
            
            i += 1
    
    except Exception as e:
        pass
    
    return symbols


def parse_blutter_objects(pp_path: str) -> List[dict]:
    """解析 Blutter 对象池文件"""
    objects = []
    
    try:
        with open(pp_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                # 简单解析对象行
                parts = line.split(' ', 2)
                if len(parts) >= 2:
                    objects.append({
                        "offset": parts[0],
                        "type": parts[1] if len(parts) > 1 else "unknown",
                        "value": parts[2] if len(parts) > 2 else ""
                    })
    except:
        pass
    
    return objects


# ==================== 符号提取 ====================

def extract_dart_symbols(libapp_path: str) -> dict:
    """
    从 libapp.so 提取 Dart 符号信息（无需 Blutter）
    
    通过分析二进制特征提取有限信息
    
    Args:
        libapp_path: libapp.so 路径
    
    Returns:
        dict: {"success": bool, "dart_version": str, "strings": list}
    """
    if not os.path.exists(libapp_path):
        return {"success": False, "error": f"File not found: {libapp_path}"}
    
    try:
        with open(libapp_path, 'rb') as f:
            data = f.read()
        
        results = {
            "success": True,
            "file_size": len(data),
            "dart_strings": [],
            "package_names": [],
            "class_hints": [],
            "url_strings": [],
            "api_endpoints": [],
            "interesting_strings": []
        }
        
        # 提取可打印字符串
        strings = extract_strings(data, min_length=8)
        
        for s in strings:
            s_lower = s.lower()
            
            # Dart 包名
            if s.startswith("package:"):
                results["package_names"].append(s)
            
            # URL/API
            elif s.startswith("http://") or s.startswith("https://"):
                results["url_strings"].append(s)
            elif "/api/" in s or "/v1/" in s or "/v2/" in s:
                results["api_endpoints"].append(s)
            
            # 类名提示 (驼峰命名)
            elif re.match(r'^[A-Z][a-z]+[A-Z]', s) and len(s) < 50:
                results["class_hints"].append(s)
            
            # Dart 相关
            elif "dart:" in s or "flutter" in s_lower:
                results["dart_strings"].append(s)
            
            # 有趣的字符串（VIP/会员等）
            elif any(k in s_lower for k in ["vip", "premium", "member", "license", 
                                             "subscribe", "paid", "pro", "unlock"]):
                results["interesting_strings"].append(s)
        
        # 限制数量
        for key in results:
            if isinstance(results[key], list) and len(results[key]) > 100:
                results[key] = results[key][:100]
                results[f"{key}_truncated"] = True
        
        results["total_strings"] = len(strings)
        
        return results
    
    except Exception as e:
        import traceback
        return {"success": False, "error": f"{str(e)}\n{traceback.format_exc()}"}


def extract_strings(data: bytes, min_length: int = 4) -> List[str]:
    """从二进制数据提取字符串"""
    strings = []
    current = []
    
    for byte in data:
        if 0x20 <= byte <= 0x7E:  # 可打印字符
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                strings.append(''.join(current))
            current = []
    
    if len(current) >= min_length:
        strings.append(''.join(current))
    
    return strings


# ==================== Frida 脚本生成 ====================

def generate_flutter_hook_script(symbols: List[dict], hook_type: str = "trace",
                                  filter_pattern: str = "") -> dict:
    """
    生成 Flutter Frida Hook 脚本
    
    Args:
        symbols: 符号列表（来自 Blutter 分析）
        hook_type: Hook 类型
            - "trace": 追踪函数调用
            - "modify": 修改返回值
            - "args": 打印参数
        filter_pattern: 过滤模式（正则表达式）
    
    Returns:
        dict: {"success": bool, "script": str}
    """
    try:
        # 过滤符号
        if filter_pattern:
            pattern = re.compile(filter_pattern, re.IGNORECASE)
            filtered_symbols = [
                s for s in symbols 
                if pattern.search(s.get("full_name", "") or s.get("function", ""))
            ]
        else:
            filtered_symbols = symbols
        
        if not filtered_symbols:
            return {"success": False, "error": "No symbols matched filter"}
        
        # 生成脚本
        script_lines = [
            "// Auto-generated Flutter Hook Script",
            "// Generated by so-analyzer-mcp",
            "",
            "'use strict';",
            "",
            "// Wait for Flutter engine to load",
            "function waitForModule(moduleName, callback) {",
            "    var module = Process.findModuleByName(moduleName);",
            "    if (module) {",
            "        callback(module);",
            "    } else {",
            "        setTimeout(function() {",
            "            waitForModule(moduleName, callback);",
            "        }, 100);",
            "    }",
            "}",
            "",
            "waitForModule('libapp.so', function(libapp) {",
            "    console.log('[*] libapp.so loaded at: ' + libapp.base);",
            "",
        ]
        
        for i, sym in enumerate(filtered_symbols[:50]):  # 限制50个
            func_name = sym.get("full_name") or sym.get("function", f"func_{i}")
            addr = sym.get("address", "0x0")
            
            # 清理地址格式
            if isinstance(addr, str):
                addr = addr.replace("0x", "")
            
            if hook_type == "trace":
                script_lines.extend([
                    f"    // Hook: {func_name}",
                    f"    try {{",
                    f"        Interceptor.attach(libapp.base.add(0x{addr}), {{",
                    f"            onEnter: function(args) {{",
                    f"                console.log('[CALL] {func_name}');",
                    f"            }},",
                    f"            onLeave: function(retval) {{",
                    f"                console.log('[RET] {func_name} => ' + retval);",
                    f"            }}",
                    f"        }});",
                    f"    }} catch(e) {{",
                    f"        console.log('[ERROR] Failed to hook {func_name}: ' + e);",
                    f"    }}",
                    "",
                ])
            
            elif hook_type == "modify":
                script_lines.extend([
                    f"    // Hook & Modify: {func_name}",
                    f"    try {{",
                    f"        Interceptor.attach(libapp.base.add(0x{addr}), {{",
                    f"            onLeave: function(retval) {{",
                    f"                console.log('[MOD] {func_name}: ' + retval + ' => 1');",
                    f"                retval.replace(1);  // Return true",
                    f"            }}",
                    f"        }});",
                    f"    }} catch(e) {{}}",
                    "",
                ])
            
            elif hook_type == "args":
                script_lines.extend([
                    f"    // Hook & Print Args: {func_name}",
                    f"    try {{",
                    f"        Interceptor.attach(libapp.base.add(0x{addr}), {{",
                    f"            onEnter: function(args) {{",
                    f"                console.log('[ARGS] {func_name}:');",
                    f"                for (var i = 0; i < 5; i++) {{",
                    f"                    try {{",
                    f"                        console.log('  arg' + i + ': ' + args[i]);",
                    f"                    }} catch(e) {{}}",
                    f"                }}",
                    f"            }}",
                    f"        }});",
                    f"    }} catch(e) {{}}",
                    "",
                ])
        
        script_lines.extend([
            "    console.log('[*] Hooks installed: " + str(len(filtered_symbols[:50])) + " functions');",
            "});",
            "",
            "console.log('[*] Flutter Hook Script Loaded');",
        ])
        
        script = "\n".join(script_lines)
        
        return {
            "success": True,
            "script": script,
            "hook_type": hook_type,
            "symbols_hooked": len(filtered_symbols[:50]),
            "filter_pattern": filter_pattern,
            "error": ""
        }
    
    except Exception as e:
        import traceback
        return {"success": False, "error": f"{str(e)}\n{traceback.format_exc()}"}


# ==================== APK 完整分析流程 ====================

def analyze_flutter_apk(apk_path: str, output_dir: Optional[str] = None,
                        use_blutter: bool = True) -> dict:
    """
    完整分析 Flutter APK
    
    自动流程:
    1. 解压 APK
    2. 提取 libapp.so 和 libflutter.so
    3. 使用 Blutter 分析（如果可用）
    4. 提取字符串和符号
    5. 生成 Frida Hook 脚本
    
    Args:
        apk_path: APK 文件路径
        output_dir: 输出目录
        use_blutter: 是否使用 Blutter（需要安装）
    
    Returns:
        dict: 完整分析结果
    """
    import zipfile
    
    if not os.path.exists(apk_path):
        return {"success": False, "error": f"APK not found: {apk_path}"}
    
    try:
        # 创建输出目录
        if not output_dir:
            output_dir = os.path.splitext(apk_path)[0] + "_flutter_analysis"
        
        os.makedirs(output_dir, exist_ok=True)
        
        results = {
            "success": True,
            "apk_path": apk_path,
            "output_dir": output_dir,
            "steps": []
        }
        
        # Step 1: 解压 APK
        extract_dir = os.path.join(output_dir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)
        
        with zipfile.ZipFile(apk_path, 'r') as zf:
            # 只解压 lib 目录
            for member in zf.namelist():
                if member.startswith("lib/"):
                    zf.extract(member, extract_dir)
        
        results["steps"].append({
            "step": "extract_apk",
            "status": "success",
            "path": extract_dir
        })
        
        # Step 2: 查找 libapp.so
        lib_dirs = []
        for arch in ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"]:
            lib_path = os.path.join(extract_dir, "lib", arch)
            if os.path.isdir(lib_path):
                libapp = os.path.join(lib_path, "libapp.so")
                if os.path.exists(libapp):
                    lib_dirs.append({
                        "arch": arch,
                        "path": lib_path,
                        "libapp": libapp,
                        "libflutter": os.path.join(lib_path, "libflutter.so")
                    })
        
        if not lib_dirs:
            return {"success": False, "error": "No Flutter libs found (libapp.so missing)"}
        
        results["lib_dirs"] = lib_dirs
        results["steps"].append({
            "step": "find_libs",
            "status": "success",
            "architectures": [d["arch"] for d in lib_dirs]
        })
        
        # Step 3: 分析 arm64-v8a（首选）
        target_lib = None
        for lib in lib_dirs:
            if lib["arch"] == "arm64-v8a":
                target_lib = lib
                break
        
        if not target_lib:
            target_lib = lib_dirs[0]
        
        results["target_arch"] = target_lib["arch"]
        
        # Step 4: 提取字符串
        strings_result = extract_dart_symbols(target_lib["libapp"])
        results["strings_analysis"] = strings_result
        results["steps"].append({
            "step": "extract_strings",
            "status": "success" if strings_result.get("success") else "failed",
            "total_strings": strings_result.get("total_strings", 0)
        })
        
        # Step 5: Blutter 分析（可选）
        blutter_result = None
        if use_blutter:
            blutter_check = check_blutter()
            if blutter_check["available"]:
                blutter_output = os.path.join(output_dir, "blutter")
                blutter_result = analyze_libapp_with_blutter(
                    target_lib["path"],
                    blutter_output
                )
                results["blutter_analysis"] = blutter_result
                results["steps"].append({
                    "step": "blutter_analysis",
                    "status": "success" if blutter_result.get("success") else "failed",
                    "symbols_count": blutter_result.get("symbols_count", 0)
                })
            else:
                results["steps"].append({
                    "step": "blutter_analysis",
                    "status": "skipped",
                    "reason": blutter_check["message"]
                })
        
        # Step 6: 生成 Frida 脚本
        symbols = []
        if blutter_result and blutter_result.get("success"):
            symbols = blutter_result.get("symbols", [])
        
        # 从字符串推断符号
        if not symbols and strings_result.get("success"):
            for pkg in strings_result.get("package_names", [])[:20]:
                symbols.append({
                    "full_name": pkg,
                    "function": pkg.split("/")[-1] if "/" in pkg else pkg,
                    "address": "0x0",
                    "type": "package"
                })
        
        if symbols:
            hook_script = generate_flutter_hook_script(symbols, "trace")
            if hook_script.get("success"):
                script_path = os.path.join(output_dir, "flutter_hook.js")
                with open(script_path, 'w', encoding='utf-8') as f:
                    f.write(hook_script["script"])
                
                results["hook_script_path"] = script_path
                results["steps"].append({
                    "step": "generate_hook",
                    "status": "success",
                    "path": script_path
                })
        
        # 汇总
        results["summary"] = {
            "apk": os.path.basename(apk_path),
            "architecture": target_lib["arch"],
            "packages_found": len(strings_result.get("package_names", [])),
            "interesting_strings": len(strings_result.get("interesting_strings", [])),
            "symbols_recovered": blutter_result.get("symbols_count", 0) if blutter_result else 0,
            "frida_script_generated": "hook_script_path" in results
        }
        
        return results
    
    except Exception as e:
        import traceback
        return {"success": False, "error": f"{str(e)}\n{traceback.format_exc()}"}


# ==================== 快速VIP函数定位 ====================

def find_flutter_vip_functions(libapp_path: str, blutter_output_dir: Optional[str] = None) -> dict:
    """
    在 Flutter libapp.so 中查找 VIP/会员相关函数
    
    Args:
        libapp_path: libapp.so 路径
        blutter_output_dir: Blutter 输出目录（可选，如果已分析过）
    
    Returns:
        dict: {"success": bool, "functions": list}
    """
    vip_keywords = [
        "isVip", "isPremium", "isMember", "isPro", "isSubscribed",
        "checkVip", "checkPremium", "checkLicense", "checkMember",
        "validateLicense", "verifyLicense", "verifyPurchase",
        "isPaid", "isUnlocked", "isTrial", "isExpired",
        "hasSubscription", "hasPremium", "hasPro",
        "getVipStatus", "getPremiumStatus", "getMemberLevel",
        "showAd", "isAdFree", "removeAds",
        "purchase", "buy", "subscribe", "upgrade"
    ]
    
    found_functions = []
    
    try:
        # 如果有 Blutter 输出，从那里搜索
        if blutter_output_dir and os.path.isdir(blutter_output_dir):
            asm_dir = os.path.join(blutter_output_dir, "asm")
            if os.path.isdir(asm_dir):
                for asm_file in os.listdir(asm_dir):
                    if asm_file.endswith(".txt"):
                        symbols = parse_blutter_asm(os.path.join(asm_dir, asm_file))
                        for sym in symbols:
                            func_name = sym.get("full_name", "") or sym.get("function", "")
                            for keyword in vip_keywords:
                                if keyword.lower() in func_name.lower():
                                    found_functions.append({
                                        **sym,
                                        "matched_keyword": keyword,
                                        "source": "blutter_asm"
                                    })
                                    break
        
        # 从字符串搜索
        if os.path.exists(libapp_path):
            strings_result = extract_dart_symbols(libapp_path)
            
            # 检查包名
            for pkg in strings_result.get("package_names", []):
                for keyword in vip_keywords:
                    if keyword.lower() in pkg.lower():
                        found_functions.append({
                            "full_name": pkg,
                            "address": "unknown (string reference)",
                            "matched_keyword": keyword,
                            "source": "string_analysis",
                            "type": "package_reference"
                        })
                        break
            
            # 有趣的字符串
            for s in strings_result.get("interesting_strings", []):
                found_functions.append({
                    "full_name": s,
                    "address": "unknown",
                    "source": "interesting_string",
                    "type": "string"
                })
        
        # 去重
        seen = set()
        unique_functions = []
        for f in found_functions:
            key = f.get("full_name", "")
            if key and key not in seen:
                seen.add(key)
                unique_functions.append(f)
        
        return {
            "success": True,
            "functions": unique_functions,
            "count": len(unique_functions),
            "keywords_searched": len(vip_keywords),
            "suggestion": "Use Blutter for accurate function addresses" if not blutter_output_dir else "",
            "error": ""
        }
    
    except Exception as e:
        import traceback
        return {"success": False, "error": f"{str(e)}\n{traceback.format_exc()}"}
