"""Blutter输出结果解析工具 - 解析符号、函数、字符串等"""
import os
import re
import json
from typing import Optional, List, Dict
from pathlib import Path


# ==================== Blutter输出解析 ====================

def parse_blutter_output(blutter_dir: str) -> dict:
    """
    解析Blutter完整输出目录
    
    Args:
        blutter_dir: Blutter输出目录
    
    Returns:
        dict: {
            "success": bool,
            "packages": list,      # 包列表
            "functions": list,     # 函数列表
            "strings": list,       # 字符串列表
            "classes": list,       # 类列表
            "frida_script": str,   # Frida脚本路径
            "ida_script": str      # IDA脚本路径
        }
    """
    if not os.path.isdir(blutter_dir):
        return {"success": False, "error": f"Directory not found: {blutter_dir}"}
    
    try:
        result = {
            "success": True,
            "blutter_dir": blutter_dir,
            "packages": [],
            "functions": [],
            "classes": [],
            "strings": [],
            "objects": [],
            "files": {}
        }
        
        # 1. 解析asm目录 - 获取包和函数
        asm_dir = os.path.join(blutter_dir, "asm")
        if os.path.isdir(asm_dir):
            packages, functions, classes = parse_asm_directory(asm_dir)
            result["packages"] = packages
            result["functions"] = functions[:500]  # 限制数量
            result["functions_total"] = len(functions)
            result["classes"] = classes[:200]
            result["classes_total"] = len(classes)
        
        # 2. 解析pp.txt - 获取字符串和对象
        pp_path = os.path.join(blutter_dir, "pp.txt")
        if os.path.exists(pp_path):
            strings, objects = parse_pp_file(pp_path)
            result["strings"] = strings[:500]
            result["strings_total"] = len(strings)
            result["objects"] = objects[:200]
            result["objects_total"] = len(objects)
        
        # 3. 检查其他文件
        frida_path = os.path.join(blutter_dir, "blutter_frida.js")
        if os.path.exists(frida_path):
            result["files"]["frida_script"] = frida_path
            result["files"]["frida_size"] = os.path.getsize(frida_path)
        
        ida_script_dir = os.path.join(blutter_dir, "ida_script")
        if os.path.isdir(ida_script_dir):
            result["files"]["ida_script_dir"] = ida_script_dir
            ida_files = os.listdir(ida_script_dir)
            result["files"]["ida_files"] = ida_files
        
        objs_path = os.path.join(blutter_dir, "objs.txt")
        if os.path.exists(objs_path):
            result["files"]["objs_txt"] = objs_path
            result["files"]["objs_size"] = os.path.getsize(objs_path)
        
        return result
    
    except Exception as e:
        import traceback
        return {"success": False, "error": f"{str(e)}\n{traceback.format_exc()}"}


def parse_asm_directory(asm_dir: str) -> tuple:
    """解析asm目录，提取包、函数和类"""
    packages = []
    functions = []
    classes = []
    
    # 遍历包目录
    for pkg_name in os.listdir(asm_dir):
        pkg_path = os.path.join(asm_dir, pkg_name)
        if not os.path.isdir(pkg_path):
            continue
        
        pkg_info = {
            "name": pkg_name,
            "path": pkg_path,
            "files": [],
            "function_count": 0
        }
        
        # 递归解析dart文件
        for root, dirs, files in os.walk(pkg_path):
            for file in files:
                if file.endswith(".dart"):
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, pkg_path)
                    pkg_info["files"].append(rel_path)
                    
                    # 解析文件内容
                    file_funcs, file_classes = parse_dart_asm_file(file_path, pkg_name)
                    functions.extend(file_funcs)
                    classes.extend(file_classes)
                    pkg_info["function_count"] += len(file_funcs)
        
        packages.append(pkg_info)
    
    return packages, functions, classes


def parse_dart_asm_file(file_path: str, package: str) -> tuple:
    """解析单个dart asm文件"""
    functions = []
    classes = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # 提取文件URL
        url_match = re.search(r'url:\s*(package:[^\s]+)', content)
        file_url = url_match.group(1) if url_match else ""
        
        # 匹配类定义
        # class ClassName {
        class_pattern = re.compile(r'^class\s+(\S+)\s*{', re.MULTILINE)
        for match in class_pattern.finditer(content):
            class_name = match.group(1)
            classes.append({
                "name": class_name,
                "package": package,
                "file": os.path.basename(file_path),
                "url": file_url
            })
        
        # 匹配函数定义
        # ** addr: 0xXXXXXX, size: 0xXX
        func_pattern = re.compile(
            r'(static\s+|)(\w+(?:<[^>]+>)?)\s+(\w+)\s*\([^)]*\)\s*(?:async\s*)?{\s*\n\s*//\s*\*\*\s*addr:\s*(0x[0-9a-fA-F]+),\s*size:\s*(0x[0-9a-fA-F]+)',
            re.MULTILINE
        )
        
        current_class = ""
        for match in func_pattern.finditer(content):
            is_static = bool(match.group(1).strip())
            return_type = match.group(2)
            func_name = match.group(3)
            addr = match.group(4)
            size = match.group(5)
            
            # 查找所属类
            class_match = re.search(r'class\s+(\S+)\s*{[^}]*' + re.escape(match.group(0)), content, re.DOTALL)
            if class_match:
                current_class = class_match.group(1)
            
            functions.append({
                "name": func_name,
                "class": current_class,
                "full_name": f"{current_class}.{func_name}" if current_class else func_name,
                "address": addr,
                "size": size,
                "return_type": return_type,
                "is_static": is_static,
                "package": package,
                "file": os.path.basename(file_path),
                "url": file_url
            })
        
        # 简化匹配 - 直接匹配地址注释
        addr_pattern = re.compile(r'//\s*\*\*\s*addr:\s*(0x[0-9a-fA-F]+),\s*size:\s*(0x[0-9a-fA-F]+)')
        for match in addr_pattern.finditer(content):
            addr = match.group(1)
            # 检查是否已添加
            if not any(f["address"] == addr for f in functions):
                # 尝试获取函数名
                context_start = max(0, match.start() - 200)
                context = content[context_start:match.start()]
                name_match = re.search(r'(\w+)\s*\([^)]*\)\s*(?:async\s*)?{?\s*$', context)
                if name_match:
                    functions.append({
                        "name": name_match.group(1),
                        "address": addr,
                        "size": match.group(2),
                        "package": package,
                        "file": os.path.basename(file_path)
                    })
    
    except Exception as e:
        pass
    
    return functions, classes


def parse_pp_file(pp_path: str) -> tuple:
    """解析pp.txt对象池文件"""
    strings = []
    objects = []
    
    try:
        with open(pp_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                # 匹配字符串
                # [pp+0xXXX] String: "xxx"
                str_match = re.match(r'\[pp\+(0x[0-9a-fA-F]+)\]\s*String:\s*"(.+)"$', line)
                if str_match:
                    strings.append({
                        "offset": str_match.group(1),
                        "value": str_match.group(2),
                        "type": "string"
                    })
                    continue
                
                # 匹配对象
                # [pp+0xXXX] Obj!ClassName@xxx
                obj_match = re.match(r'\[pp\+(0x[0-9a-fA-F]+)\]\s*Obj!(\w+)@([0-9a-fA-F]+)', line)
                if obj_match:
                    objects.append({
                        "offset": obj_match.group(1),
                        "class": obj_match.group(2),
                        "instance_id": obj_match.group(3),
                        "type": "object"
                    })
                    continue
                
                # 匹配字段
                # [pp+0xXXX] Field <xxx>: static late final
                field_match = re.match(r'\[pp\+(0x[0-9a-fA-F]+)\]\s*Field\s*<([^>]+)>', line)
                if field_match:
                    objects.append({
                        "offset": field_match.group(1),
                        "field": field_match.group(2),
                        "type": "field"
                    })
                    continue
                
                # 匹配闭包
                # [pp+0xXXX] Closure: ...
                closure_match = re.match(r'\[pp\+(0x[0-9a-fA-F]+)\]\s*Closure:\s*(.+)', line)
                if closure_match:
                    objects.append({
                        "offset": closure_match.group(1),
                        "closure": closure_match.group(2),
                        "type": "closure"
                    })
    
    except Exception as e:
        pass
    
    return strings, objects


# ==================== VIP/会员函数搜索 ====================

def search_blutter_vip_functions(blutter_dir: str, 
                                  custom_keywords: Optional[List[str]] = None) -> dict:
    """
    在Blutter输出中搜索VIP/会员相关函数
    
    Args:
        blutter_dir: Blutter输出目录
        custom_keywords: 自定义关键词
    
    Returns:
        dict: {"success": bool, "functions": list}
    """
    # VIP相关关键词
    vip_keywords = custom_keywords or [
        # 会员状态
        "isVip", "isPremium", "isMember", "isPro", "isSubscribed",
        "isVIP", "IsPremium", "IsMember", "IsPro",
        "vip", "VIP", "Vip",
        "premium", "Premium", "PREMIUM",
        "member", "Member",
        "subscribe", "Subscribe",
        
        # 验证
        "checkVip", "checkPremium", "checkLicense", "checkMember",
        "validateLicense", "verifyLicense", "verifyPurchase",
        "checkSubscription", "validateSubscription",
        
        # 状态获取
        "getVipStatus", "getPremiumStatus", "getMemberLevel",
        "getSubscriptionStatus", "getUserLevel",
        
        # 付费相关
        "isPaid", "isUnlocked", "isTrial", "isExpired",
        "hasPurchased", "hasSubscription",
        
        # 广告
        "showAd", "isAdFree", "removeAds", "noAds",
        "hasAds", "shouldShowAd",
        
        # 功能限制
        "isLimited", "checkLimit", "hasAccess",
        "canAccess", "isEnabled", "isDisabled",
        
        # 购买
        "purchase", "buy", "upgrade", "unlock",
        "restore", "restorePurchase"
    ]
    
    if not os.path.isdir(blutter_dir):
        return {"success": False, "error": f"Directory not found: {blutter_dir}"}
    
    try:
        found_functions = []
        found_strings = []
        
        # 1. 搜索asm文件
        asm_dir = os.path.join(blutter_dir, "asm")
        if os.path.isdir(asm_dir):
            for root, dirs, files in os.walk(asm_dir):
                for file in files:
                    if file.endswith(".dart"):
                        file_path = os.path.join(root, file)
                        funcs = search_vip_in_asm_file(file_path, vip_keywords)
                        found_functions.extend(funcs)
        
        # 2. 搜索pp.txt字符串
        pp_path = os.path.join(blutter_dir, "pp.txt")
        if os.path.exists(pp_path):
            with open(pp_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    for keyword in vip_keywords:
                        if keyword.lower() in line.lower():
                            str_match = re.match(r'\[pp\+(0x[0-9a-fA-F]+)\]\s*String:\s*"(.+)"$', line.strip())
                            if str_match:
                                found_strings.append({
                                    "offset": str_match.group(1),
                                    "value": str_match.group(2),
                                    "matched_keyword": keyword
                                })
                            break
        
        # 生成修改建议
        for func in found_functions:
            func["suggestion"] = generate_patch_suggestion(func)
        
        return {
            "success": True,
            "functions": found_functions,
            "functions_count": len(found_functions),
            "strings": found_strings[:100],
            "strings_count": len(found_strings),
            "keywords_used": len(vip_keywords),
            "error": ""
        }
    
    except Exception as e:
        import traceback
        return {"success": False, "error": f"{str(e)}\n{traceback.format_exc()}"}


def search_vip_in_asm_file(file_path: str, keywords: List[str]) -> List[dict]:
    """在单个asm文件中搜索VIP相关函数"""
    found = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # 获取包名
        package = os.path.basename(os.path.dirname(file_path))
        
        for keyword in keywords:
            # 搜索函数名匹配
            pattern = re.compile(
                rf'(\w*{re.escape(keyword)}\w*)\s*\([^)]*\)\s*(?:async\s*)?{{\s*\n\s*//\s*\*\*\s*addr:\s*(0x[0-9a-fA-F]+),\s*size:\s*(0x[0-9a-fA-F]+)',
                re.IGNORECASE | re.MULTILINE
            )
            
            for match in pattern.finditer(content):
                func_name = match.group(1)
                addr = match.group(2)
                size = match.group(3)
                
                # 避免重复
                if not any(f["address"] == addr for f in found):
                    # 查找返回类型
                    context_start = max(0, match.start() - 100)
                    context = content[context_start:match.start()]
                    ret_match = re.search(r'(bool|int|String|void|Future<\w+>)\s+$', context)
                    return_type = ret_match.group(1) if ret_match else "unknown"
                    
                    found.append({
                        "name": func_name,
                        "address": addr,
                        "size": size,
                        "return_type": return_type,
                        "matched_keyword": keyword,
                        "package": package,
                        "file": os.path.basename(file_path),
                        "file_path": file_path
                    })
    
    except Exception as e:
        pass
    
    return found


def generate_patch_suggestion(func: dict) -> dict:
    """生成修改建议"""
    name = func.get("name", "").lower()
    return_type = func.get("return_type", "").lower()
    
    # 根据函数名和返回类型推断
    if "bool" in return_type:
        if any(k in name for k in ["expired", "limit", "disabled", "ad", "trial"]):
            return {
                "action": "return_false",
                "value": 0,
                "reason": "返回false禁用限制"
            }
        else:
            return {
                "action": "return_true",
                "value": 1,
                "reason": "返回true启用功能"
            }
    elif "int" in return_type:
        return {
            "action": "return_max",
            "value": "0x7FFFFFFF",
            "reason": "返回最大值"
        }
    else:
        return {
            "action": "return_true",
            "value": 1,
            "reason": "默认返回true"
        }


# ==================== 搜索函数 ====================

def search_blutter_functions(blutter_dir: str, query: str, 
                              search_type: str = "name") -> dict:
    """
    搜索Blutter解析出的函数
    
    Args:
        blutter_dir: Blutter输出目录
        query: 搜索关键词
        search_type: 搜索类型 (name/address/package/class)
    
    Returns:
        dict: {"success": bool, "results": list}
    """
    if not os.path.isdir(blutter_dir):
        return {"success": False, "error": f"Directory not found: {blutter_dir}"}
    
    try:
        results = []
        query_lower = query.lower()
        
        asm_dir = os.path.join(blutter_dir, "asm")
        if not os.path.isdir(asm_dir):
            return {"success": False, "error": "asm directory not found"}
        
        for root, dirs, files in os.walk(asm_dir):
            for file in files:
                if not file.endswith(".dart"):
                    continue
                
                file_path = os.path.join(root, file)
                package = os.path.basename(os.path.dirname(file_path))
                
                # 包名过滤
                if search_type == "package":
                    if query_lower not in package.lower():
                        continue
                
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # 搜索函数
                func_pattern = re.compile(
                    r'(\w+)\s*\([^)]*\)\s*(?:async\s*)?{\s*\n\s*//\s*\*\*\s*addr:\s*(0x[0-9a-fA-F]+),\s*size:\s*(0x[0-9a-fA-F]+)',
                    re.MULTILINE
                )
                
                for match in func_pattern.finditer(content):
                    func_name = match.group(1)
                    addr = match.group(2)
                    
                    # 根据类型匹配
                    matched = False
                    if search_type == "name":
                        matched = query_lower in func_name.lower()
                    elif search_type == "address":
                        matched = query_lower in addr.lower()
                    elif search_type == "package":
                        matched = True  # 已经过滤
                    elif search_type == "class":
                        # 查找类名
                        context_start = max(0, match.start() - 500)
                        context = content[context_start:match.start()]
                        class_match = re.search(r'class\s+(\w+)', context)
                        if class_match:
                            matched = query_lower in class_match.group(1).lower()
                    
                    if matched:
                        results.append({
                            "name": func_name,
                            "address": addr,
                            "size": match.group(3),
                            "package": package,
                            "file": file,
                            "file_path": file_path
                        })
                
                if len(results) >= 100:
                    break
            
            if len(results) >= 100:
                break
        
        return {
            "success": True,
            "query": query,
            "search_type": search_type,
            "results": results,
            "count": len(results),
            "error": ""
        }
    
    except Exception as e:
        import traceback
        return {"success": False, "error": f"{str(e)}\n{traceback.format_exc()}"}


# ==================== 字符串搜索 ====================

def search_blutter_strings(blutter_dir: str, query: str, 
                            case_sensitive: bool = False) -> dict:
    """
    搜索Blutter解析出的字符串
    
    Args:
        blutter_dir: Blutter输出目录
        query: 搜索关键词
        case_sensitive: 是否区分大小写
    
    Returns:
        dict: {"success": bool, "results": list}
    """
    pp_path = os.path.join(blutter_dir, "pp.txt")
    if not os.path.exists(pp_path):
        return {"success": False, "error": f"pp.txt not found in {blutter_dir}"}
    
    try:
        results = []
        query_match = query if case_sensitive else query.lower()
        
        with open(pp_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                str_match = re.match(r'\[pp\+(0x[0-9a-fA-F]+)\]\s*String:\s*"(.+)"$', line.strip())
                if str_match:
                    value = str_match.group(2)
                    value_match = value if case_sensitive else value.lower()
                    
                    if query_match in value_match:
                        results.append({
                            "offset": str_match.group(1),
                            "value": value
                        })
                
                if len(results) >= 200:
                    break
        
        return {
            "success": True,
            "query": query,
            "results": results,
            "count": len(results),
            "error": ""
        }
    
    except Exception as e:
        import traceback
        return {"success": False, "error": f"{str(e)}\n{traceback.format_exc()}"}


# ==================== 获取函数详情 ====================

def get_function_detail(blutter_dir: str, address: str) -> dict:
    """
    获取指定地址函数的详细信息
    
    Args:
        blutter_dir: Blutter输出目录
        address: 函数地址 (如 0xa716a8)
    
    Returns:
        dict: {"success": bool, "function": dict, "assembly": str}
    """
    if not os.path.isdir(blutter_dir):
        return {"success": False, "error": f"Directory not found: {blutter_dir}"}
    
    # 标准化地址格式
    if not address.startswith("0x"):
        address = "0x" + address
    address_lower = address.lower()
    
    try:
        asm_dir = os.path.join(blutter_dir, "asm")
        if not os.path.isdir(asm_dir):
            return {"success": False, "error": "asm directory not found"}
        
        for root, dirs, files in os.walk(asm_dir):
            for file in files:
                if not file.endswith(".dart"):
                    continue
                
                file_path = os.path.join(root, file)
                
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # 查找地址
                if address_lower not in content.lower():
                    continue
                
                # 找到包含该地址的函数块
                pattern = re.compile(
                    rf'(\w+)\s*\([^)]*\)\s*(?:async\s*)?{{\s*\n\s*//\s*\*\*\s*addr:\s*{address}.*?(?=\n\s*(?:\w+\s*\([^)]*\)\s*(?:async\s*)?{{|\}}\s*$|class\s+))',
                    re.IGNORECASE | re.DOTALL
                )
                
                match = pattern.search(content)
                if match:
                    func_name = match.group(1)
                    assembly = match.group(0)
                    
                    # 提取更多信息
                    size_match = re.search(r'size:\s*(0x[0-9a-fA-F]+)', assembly)
                    
                    # 获取返回类型
                    context_start = max(0, match.start() - 100)
                    context = content[context_start:match.start()]
                    ret_match = re.search(r'([\w<>?]+)\s+$', context)
                    
                    package = os.path.basename(os.path.dirname(file_path))
                    
                    return {
                        "success": True,
                        "function": {
                            "name": func_name,
                            "address": address,
                            "size": size_match.group(1) if size_match else "unknown",
                            "return_type": ret_match.group(1) if ret_match else "unknown",
                            "package": package,
                            "file": file,
                            "file_path": file_path
                        },
                        "assembly": assembly,
                        "error": ""
                    }
        
        return {"success": False, "error": f"Function at {address} not found"}
    
    except Exception as e:
        import traceback
        return {"success": False, "error": f"{str(e)}\n{traceback.format_exc()}"}


# ==================== 导出Frida Hook ====================

def export_frida_hooks(blutter_dir: str, functions: List[dict], 
                        hook_type: str = "trace") -> dict:
    """
    为指定函数生成Frida Hook脚本
    
    Args:
        blutter_dir: Blutter输出目录
        functions: 函数列表 [{address, name}, ...]
        hook_type: Hook类型 (trace/modify/log)
    
    Returns:
        dict: {"success": bool, "script": str}
    """
    try:
        # 读取blutter_frida.js模板
        frida_path = os.path.join(blutter_dir, "blutter_frida.js")
        if os.path.exists(frida_path):
            with open(frida_path, 'r', encoding='utf-8') as f:
                template = f.read()
        else:
            template = ""
        
        # 生成Hook代码
        hooks = []
        for func in functions:
            addr = func.get("address", "0x0")
            name = func.get("name", "unknown")
            
            if addr.startswith("0x"):
                addr = addr[2:]
            
            if hook_type == "trace":
                hook_code = f'''
    // Hook: {name}
    try {{
        Interceptor.attach(libapp.add(0x{addr}), {{
            onEnter: function(args) {{
                console.log('[CALL] {name} @ 0x{addr}');
            }},
            onLeave: function(retval) {{
                console.log('[RET] {name} => ' + retval);
            }}
        }});
    }} catch(e) {{ console.log('[ERR] {name}: ' + e); }}
'''
            elif hook_type == "modify":
                hook_code = f'''
    // Hook & Modify: {name}
    try {{
        Interceptor.attach(libapp.add(0x{addr}), {{
            onLeave: function(retval) {{
                console.log('[MOD] {name}: ' + retval + ' => 1');
                retval.replace(1);
            }}
        }});
    }} catch(e) {{}}
'''
            else:  # log
                hook_code = f'''
    // Log: {name}
    try {{
        Interceptor.attach(libapp.add(0x{addr}), {{
            onEnter: function(args) {{
                console.log('[LOG] {name} called');
                for (var i = 0; i < 4; i++) {{
                    try {{ console.log('  arg' + i + ': ' + args[i]); }} catch(e) {{}}
                }}
            }}
        }});
    }} catch(e) {{}}
'''
            hooks.append(hook_code)
        
        # 组装完整脚本
        script = f'''// Auto-generated Frida Hook Script
// Functions: {len(functions)}
// Type: {hook_type}

var libapp = null;

function onLibappLoaded() {{
    console.log('[*] libapp.so loaded at: ' + libapp);
{"".join(hooks)}
    console.log('[*] Hooks installed: {len(functions)} functions');
}}

function tryLoadLibapp() {{
    try {{
        libapp = Module.findBaseAddress('libapp.so');
    }} catch (e) {{
        libapp = Process.findModuleByName('libapp.so');
        if (libapp != null) libapp = libapp.base;
    }}
    if (libapp === null)
        setTimeout(tryLoadLibapp, 500);
    else
        onLibappLoaded();
}}
tryLoadLibapp();

console.log('[*] Flutter Hook Script Loaded');
'''
        
        return {
            "success": True,
            "script": script,
            "hook_type": hook_type,
            "functions_count": len(functions),
            "error": ""
        }
    
    except Exception as e:
        import traceback
        return {"success": False, "error": f"{str(e)}\n{traceback.format_exc()}"}
