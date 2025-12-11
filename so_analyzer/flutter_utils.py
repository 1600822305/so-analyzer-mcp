"""Flutter专用工具"""
import os
import re
import zipfile
import tempfile
import shutil
import struct
from pathlib import Path
from typing import Optional, List, Dict, Tuple
from .flutter_utils_v2 import find_ssl_verify_function_v2, vaddr_to_file_offset

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False


def find_ssl_verify_offset(so_path: str) -> dict:
    """
    使用正确的方法定位Flutter SSL验证函数
    
    策略：
    1. 找到JNI_OnLoad导出函数地址
    2. 搜索"ssl_client"和"ssl_server"字符串
    3. 通过字符串交叉引用找到ssl_crypto_x509_session_verify_cert_chain函数
    4. 计算与JNI_OnLoad的偏移
    
    Args:
        so_path: libflutter.so文件路径
    
    Returns:
        dict: {"success": bool, "offset": int, "jni_onload": int, "ssl_verify": int, "error": str}
    """
    if not LIEF_AVAILABLE:
        return {"success": False, "error": "lief not available"}
    
    if not os.path.exists(so_path):
        return {"success": False, "error": f"File not found: {so_path}"}
    
    try:
        with open(so_path, 'rb') as f:
            data = f.read()
        
        binary = lief.parse(so_path)
        if binary is None:
            return {"success": False, "error": "Failed to parse SO file"}
        
        result = {
            "success": False,
            "jni_onload_address": None,
            "ssl_verify_address": None,
            "offset_from_jni_onload": None,
            "ssl_client_offset": None,
            "ssl_server_offset": None,
            "frida_script_hint": None,
            "error": ""
        }
        
        # 1. 找JNI_OnLoad地址
        jni_onload_addr = None
        for func in binary.exported_functions:
            name = func.name if hasattr(func, 'name') else ""
            if "JNI_OnLoad" in name:
                jni_onload_addr = func.address
                result["jni_onload_address"] = hex(jni_onload_addr)
                break
        
        if jni_onload_addr is None:
            result["error"] = "JNI_OnLoad not found in exports"
            return result
        
        # 2. 搜索关键字符串
        ssl_client_offset = data.find(b"ssl_client\x00")
        ssl_server_offset = data.find(b"ssl_server\x00")
        
        result["ssl_client_offset"] = hex(ssl_client_offset) if ssl_client_offset != -1 else None
        result["ssl_server_offset"] = hex(ssl_server_offset) if ssl_server_offset != -1 else None
        
        if ssl_client_offset == -1 or ssl_server_offset == -1:
            result["error"] = "ssl_client or ssl_server string not found"
            return result
        
        # 3. 获取段信息用于地址计算
        text_section = None
        rodata_section = None
        
        for section in binary.sections:
            if section.name == ".text":
                text_section = section
            elif section.name == ".rodata":
                rodata_section = section
        
        if text_section is None:
            result["error"] = ".text section not found"
            return result
        
        # 4. 计算字符串的虚拟地址
        # 需要找到字符串所在段并计算虚拟地址
        ssl_client_vaddr = ssl_client_offset
        ssl_server_vaddr = ssl_server_offset
        
        if rodata_section:
            # 检查字符串是否在.rodata段
            if rodata_section.file_offset <= ssl_client_offset < rodata_section.file_offset + rodata_section.size:
                ssl_client_vaddr = rodata_section.virtual_address + (ssl_client_offset - rodata_section.file_offset)
            if rodata_section.file_offset <= ssl_server_offset < rodata_section.file_offset + rodata_section.size:
                ssl_server_vaddr = rodata_section.virtual_address + (ssl_server_offset - rodata_section.file_offset)
        
        result["ssl_client_vaddr"] = hex(ssl_client_vaddr)
        result["ssl_server_vaddr"] = hex(ssl_server_vaddr)
        
        # 5. 在.text段搜索同时引用这两个字符串的函数
        text_start = text_section.file_offset
        text_end = text_section.file_offset + text_section.size
        text_vaddr = text_section.virtual_address
        
        # 搜索引用ssl_client的代码位置
        ssl_client_refs = find_string_references(data, text_start, text_end, text_vaddr, ssl_client_vaddr)
        ssl_server_refs = find_string_references(data, text_start, text_end, text_vaddr, ssl_server_vaddr)
        
        result["ssl_client_refs_count"] = len(ssl_client_refs)
        result["ssl_server_refs_count"] = len(ssl_server_refs)
        
        # 6. 收集所有候选函数
        candidates = []
        seen_funcs = set()
        
        # 收集所有ssl_client引用的函数
        for ref in ssl_client_refs:
            ref_file_offset = ref - text_vaddr + text_start
            func_start = find_function_start(data, text_start, ref_file_offset)
            if func_start and func_start not in seen_funcs:
                seen_funcs.add(func_start)
                func_vaddr = text_vaddr + (func_start - text_start)
                # 检查这个函数是否也引用了ssl_server
                refs_ssl_server = any(abs(ref - srv) < 0x1000 for srv in ssl_server_refs)
                candidates.append({
                    "address": hex(func_vaddr),
                    "file_offset": hex(func_start),
                    "refs_both": refs_ssl_server,
                    "client_ref_at": hex(ref),
                    "offset_from_jni": hex(func_vaddr - jni_onload_addr)
                })
        
        # 收集所有ssl_server引用的函数
        for ref in ssl_server_refs:
            ref_file_offset = ref - text_vaddr + text_start
            func_start = find_function_start(data, text_start, ref_file_offset)
            if func_start and func_start not in seen_funcs:
                seen_funcs.add(func_start)
                func_vaddr = text_vaddr + (func_start - text_start)
                refs_ssl_client = any(abs(ref - cli) < 0x1000 for cli in ssl_client_refs)
                candidates.append({
                    "address": hex(func_vaddr),
                    "file_offset": hex(func_start),
                    "refs_both": refs_ssl_client,
                    "server_ref_at": hex(ref),
                    "offset_from_jni": hex(func_vaddr - jni_onload_addr)
                })
        
        # 按地址排序
        candidates.sort(key=lambda x: int(x["address"], 16))
        
        # 分析每个候选函数的特征
        for cand in candidates:
            func_file_offset = int(cand["file_offset"], 16)
            func_size = estimate_function_size(data, func_file_offset, text_end)
            cand["estimated_size"] = func_size
            
            # 计算置信度
            confidence = 0.5
            if cand["refs_both"]:
                confidence += 0.3  # 同时引用两个字符串
            
            # 函数大小评分 - SSL验证函数通常在300-800字节
            if 300 <= func_size <= 800:
                confidence += 0.25  # 最佳大小范围
            elif 200 < func_size < 1200:
                confidence += 0.15  # 可接受大小
            elif func_size > 1200:
                confidence -= 0.1  # 函数较大，可能是封装函数
            elif func_size < 200:
                confidence -= 0.1  # 函数太小
            
            cand["confidence"] = round(confidence, 2)
        
        # 按置信度排序，置信度相同时优先选择大小更接近500的
        ideal_size = 500
        candidates.sort(key=lambda x: (-x["confidence"], abs(x["estimated_size"] - ideal_size)))
        
        result["candidates"] = candidates
        result["candidates_count"] = len(candidates)
        
        # 选择最佳候选
        if candidates:
            best = candidates[0]
            result["recommended"] = best["address"]
            result["recommended_offset"] = best["offset_from_jni"]
            result["recommended_confidence"] = best["confidence"]
            
            # 生成Frida脚本
            offset_hex = best["offset_from_jni"]
            result["frida_script"] = f"""// Frida SSL Bypass 脚本
// 推荐地址: {best["address"]} (置信度: {best["confidence"]})

function hook_ssl_verify() {{
    var m = Process.findModuleByName("libflutter.so");
    var jni_onload = m.enumerateExports().find(e => e.name === "JNI_OnLoad").address;
    
    // 推荐的偏移
    var ssl_verify = ptr(jni_onload).add({offset_hex});
    console.log("Hooking SSL verify at: " + ssl_verify);
    
    Interceptor.attach(ssl_verify, {{
        onEnter: function(args) {{
            console.log("SSL verify called");
        }},
        onLeave: function(retval) {{
            console.log("Original return: " + retval);
            retval.replace(0x1);
            console.log("Bypassed! Return: 1");
        }}
    }});
}}

// 如果推荐地址不对，尝试其他候选:
// {chr(10).join([f"// - {c['address']} (置信度: {c['confidence']}, 偏移: {c['offset_from_jni']})" for c in candidates[:5]])}

setTimeout(hook_ssl_verify, 1000);
"""
        else:
            result["error"] = "No candidate functions found"
            return result
        
        result["success"] = True
        return result
        
    except Exception as e:
        import traceback
        return {"success": False, "error": f"{str(e)}\n{traceback.format_exc()}"}


def find_string_references(data: bytes, text_start: int, text_end: int, text_vaddr: int, string_vaddr: int) -> list:
    """
    在.text段中搜索引用指定虚拟地址的代码
    
    搜索ADRP + ADD/LDR模式
    """
    refs = []
    target_page = string_vaddr & ~0xFFF
    target_offset = string_vaddr & 0xFFF
    
    for file_offset in range(text_start, min(text_end, len(data) - 8), 4):
        insn = struct.unpack('<I', data[file_offset:file_offset+4])[0]
        
        # 检查ADRP指令
        if (insn & 0x9F000000) == 0x90000000:
            # 提取立即数
            immlo = (insn >> 29) & 0x3
            immhi = (insn >> 5) & 0x7FFFF
            imm = (immhi << 2) | immlo
            
            # 符号扩展
            if imm & 0x100000:
                imm = imm - 0x200000
            
            # 计算目标页
            current_vaddr = text_vaddr + (file_offset - text_start)
            pc_page = current_vaddr & ~0xFFF
            adrp_target = (pc_page + (imm << 12)) & 0xFFFFFFFFFFFFFFFF
            
            # 检查是否指向目标页
            if adrp_target == target_page:
                # 检查下一条ADD指令
                if file_offset + 4 < len(data):
                    next_insn = struct.unpack('<I', data[file_offset+4:file_offset+8])[0]
                    # ADD immediate (32位或64位)
                    if (next_insn & 0x7F800000) == 0x11000000 or (next_insn & 0xFF800000) == 0x91000000:
                        add_imm = (next_insn >> 10) & 0xFFF
                        if add_imm == target_offset:
                            refs.append(current_vaddr)
    
    return refs


def find_function_start(data: bytes, text_start: int, ref_offset: int) -> Optional[int]:
    """
    从引用位置向前搜索函数开头
    
    ARM64函数开头特征:
    - STP X29, X30, [SP, #-N]!  (常见)
    - PACIBSP (PAC指令)
    - SUB SP, SP, #N
    """
    # 向前搜索最多4KB
    search_start = max(text_start, ref_offset - 4096)
    
    # 从ref_offset向前搜索
    for offset in range(ref_offset, search_start, -4):
        if offset < 4:
            break
        
        insn = struct.unpack('<I', data[offset:offset+4])[0]
        
        # PACIBSP: 0xD503237F
        if insn == 0xD503237F:
            return offset
        
        # STP X29, X30, [SP, #imm]! - 函数入口常见模式
        # 编码: 101_0100_11_0_xxxxxxx_11110_11101_11111
        # 简化检查: (insn & 0xFFE003FF) == 0xA98003E0 表示 STP X29, X30
        if (insn & 0xFFC003FF) == 0xA98003E0:
            return offset
        
        # SUB SP, SP, #imm (64位)
        # 编码: 1101_0001_00_xxxxxxxxxxxx_11111_11111
        if (insn & 0xFF0003FF) == 0xD10003FF:
            return offset
    
    return None


def estimate_function_size(data: bytes, func_start: int, text_end: int) -> int:
    """
    估算函数大小
    
    通过查找RET指令或下一个函数开头来估算
    """
    max_search = min(func_start + 0x10000, text_end)  # 最多搜索64KB
    
    for offset in range(func_start + 4, max_search, 4):
        if offset + 4 > len(data):
            break
        
        insn = struct.unpack('<I', data[offset:offset+4])[0]
        
        # RET指令: 0xD65F03C0
        if insn == 0xD65F03C0:
            return offset - func_start + 4
        
        # 遇到下一个函数开头
        # PACIBSP
        if insn == 0xD503237F:
            return offset - func_start
        
        # STP X29, X30
        if (insn & 0xFFC003FF) == 0xA98003E0:
            # 检查前一条是否是RET或NOP
            if offset >= 4:
                prev_insn = struct.unpack('<I', data[offset-4:offset])[0]
                if prev_insn == 0xD65F03C0 or prev_insn == 0xD503201F:
                    return offset - func_start
    
    return max_search - func_start


# Flutter SSL验证函数的特征（不同版本可能不同）
SSL_VERIFY_PATTERNS = [
    # Flutter 3.x
    b"ssl_crypto_x509_session_verify_cert_chain",
    b"ssl_server_handshake",
    b"x509_verify_cert",
    # 通用SSL相关
    b"SSL_CTX_set_verify",
    b"SSL_set_verify",
]

# Flutter版本特征
FLUTTER_VERSION_PATTERNS = [
    rb"Flutter\s+(\d+\.\d+\.\d+)",
    rb"flutter/(\d+\.\d+\.\d+)",
    rb"engine/(\d+\.\d+\.\d+)",
]


def get_flutter_version(so_path: str) -> dict:
    """
    获取Flutter版本和信息
    
    Args:
        so_path: libflutter.so路径
    
    Returns:
        dict: {"success": bool, "info": dict, "error": str}
    """
    if not os.path.exists(so_path):
        return {"success": False, "info": {}, "error": f"File not found: {so_path}"}
    
    try:
        file_size = os.path.getsize(so_path)
        
        with open(so_path, 'rb') as f:
            data = f.read()
        
        info = {
            "file_size": file_size,
            "file_size_mb": round(file_size / 1024 / 1024, 2),
        }
        
        # 通过文件大小估计版本范围
        if file_size > 20 * 1024 * 1024:
            info["estimated_version"] = "3.x (large)"
        elif file_size > 10 * 1024 * 1024:
            info["estimated_version"] = "2.x-3.x"
        else:
            info["estimated_version"] = "2.x or earlier"
        
        # 检测架构
        if LIEF_AVAILABLE:
            binary = lief.parse(so_path)
            if binary and hasattr(binary, 'header'):
                arch = binary.header.machine_type.name if hasattr(binary.header.machine_type, 'name') else ""
                info["architecture"] = arch
                info["is_64bit"] = "AARCH64" in arch or "64" in arch
        
        # 搜索Flutter相关字符串
        flutter_strings = []
        dart_strings = []
        
        # 搜索关键标识
        if b"flutter" in data.lower():
            info["has_flutter_marker"] = True
        if b"dart" in data.lower():
            info["has_dart_marker"] = True
        
        # 搜索SSL相关函数（重要！）
        ssl_indicators = [
            b"ssl_crypto_x509",
            b"SSL_CTX",
            b"X509_verify",
            b"ssl_verify",
            b"certificate"
        ]
        
        ssl_found = []
        for indicator in ssl_indicators:
            if indicator in data:
                ssl_found.append(indicator.decode('utf-8', errors='ignore'))
        
        info["ssl_indicators_found"] = ssl_found
        info["ssl_patchable"] = len(ssl_found) > 0
        
        # 尝试提取版本字符串
        version_patterns = [
            rb'Flutter\s*(\d+\.\d+)',
            rb'flutter_(\d+\.\d+)',
            rb'engine.version[^\d]*(\d+\.\d+)',
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, data, re.IGNORECASE)
            if match:
                info["version_hint"] = match.group(1).decode('utf-8', errors='ignore')
                break
        
        return {
            "success": True,
            "info": info,
            "error": ""
        }
    except Exception as e:
        return {"success": False, "info": {}, "error": str(e)}


def find_ssl_verify_function(so_path: str) -> dict:
    """
    查找SSL验证相关内容（函数、字符串、字节模式）
    
    Args:
        so_path: SO文件路径
    
    Returns:
        dict: {"success": bool, "findings": dict, "error": str}
    """
    if not os.path.exists(so_path):
        return {"success": False, "findings": {}, "error": f"File not found: {so_path}"}
    
    try:
        with open(so_path, 'rb') as f:
            data = f.read()
        
        findings = {
            "exported_functions": [],
            "imported_functions": [],
            "string_references": [],
            "byte_patterns": [],
            "patchable": False
        }
        
        # 1. 搜索导出/导入函数（如果lief可用）
        if LIEF_AVAILABLE:
            binary = lief.parse(so_path)
            if binary:
                ssl_keywords = ['ssl', 'verify', 'cert', 'x509', 'tls', 'handshake']
                
                for func in binary.exported_functions:
                    name = func.name if hasattr(func, 'name') else str(func)
                    if any(kw in name.lower() for kw in ssl_keywords):
                        findings["exported_functions"].append({
                            "name": name,
                            "address": hex(func.address) if hasattr(func, 'address') else "0x0"
                        })
                
                for func in binary.imported_functions:
                    name = func.name if hasattr(func, 'name') else str(func)
                    if any(kw in name.lower() for kw in ssl_keywords):
                        findings["imported_functions"].append({
                            "name": name,
                            "library": func.library.name if hasattr(func, 'library') and func.library else "unknown"
                        })
        
        # 2. 搜索SSL相关字符串
        ssl_strings = [
            b"ssl_crypto_x509_session_verify_cert_chain",
            b"ssl_verify_cert_chain",
            b"x509_session_verify",
            b"CERTIFICATE_VERIFY_FAILED",
            b"certificate verify failed",
            b"SSL_CTX_set_verify",
            b"X509_verify_cert",
            b"handshake_failure",
            b"bad_certificate",
            b"certificate_unknown",
            b"ssl_x509",
            b"BoringSSL",
        ]
        
        for s in ssl_strings:
            pos = data.find(s)
            if pos != -1:
                findings["string_references"].append({
                    "string": s.decode('utf-8', errors='ignore'),
                    "offset": hex(pos),
                    "context": data[max(0, pos-20):pos+len(s)+20].hex()
                })
        
        # 3. 搜索特定字节模式（Flutter SSL验证相关）
        # 这些是已知的Flutter SSL验证函数的特征模式
        byte_patterns = [
            # ARM64: 常见的函数开头模式
            (b"\x7f\x23\x03\xd5", "ARM64 PACIBSP (function prologue)"),
            # 返回0的模式（patch目标）
            (b"\x00\x00\x80\xd2\xc0\x03\x5f\xd6", "ARM64 return 0"),
            # 返回1的模式
            (b"\x20\x00\x80\xd2\xc0\x03\x5f\xd6", "ARM64 return 1"),
        ]
        
        for pattern, desc in byte_patterns:
            count = data.count(pattern)
            if count > 0:
                # 找到前几个位置
                positions = []
                start = 0
                for _ in range(min(count, 5)):
                    pos = data.find(pattern, start)
                    if pos == -1:
                        break
                    positions.append(hex(pos))
                    start = pos + 1
                
                findings["byte_patterns"].append({
                    "pattern": pattern.hex(),
                    "description": desc,
                    "count": count,
                    "first_positions": positions
                })
        
        # 4. 判断是否可以patch
        # 如果找到SSL相关字符串，通常是可以patch的
        findings["patchable"] = len(findings["string_references"]) > 0
        
        # 5. 提供patch建议
        if findings["patchable"]:
            findings["patch_suggestion"] = {
                "method": "reFlutter style",
                "description": "使用flutter_patch_apk工具自动patch，或手动搜索ssl_verify相关函数并修改返回值",
                "note": "需要找到验证函数并让其返回成功(0)"
            }
        
        return {
            "success": True,
            "findings": findings,
            "summary": {
                "exported_ssl_funcs": len(findings["exported_functions"]),
                "imported_ssl_funcs": len(findings["imported_functions"]),
                "ssl_strings_found": len(findings["string_references"]),
                "patchable": findings["patchable"]
            },
            "error": ""
        }
    except Exception as e:
        return {"success": False, "findings": {}, "error": str(e)}


def patch_ssl_verify(
    so_path: str,
    output_path: Optional[str] = None
) -> dict:
    """
    Patch SSL验证函数（使其始终返回成功）
    
    使用 v2 算法定位函数，然后修改指令直接返回 1
    
    Args:
        so_path: SO文件路径
        output_path: 输出路径（可选）
    
    Returns:
        dict: {"success": bool, "output_path": str, "patches": list, "error": str}
    """
    if not LIEF_AVAILABLE:
        return {"success": False, "output_path": "", "patches": [], "error": "lief not available"}
    
    if not os.path.exists(so_path):
        return {"success": False, "output_path": "", "patches": [], "error": f"File not found: {so_path}"}
    
    try:
        # 1. 使用 v2 算法查找函数
        # print(f"Finding SSL verify function in {so_path}...")
        find_result = find_ssl_verify_function_v2(so_path)
        
        if not find_result["success"]:
            return {
                "success": False,
                "output_path": "",
                "patches": [],
                "error": f"Failed to find target function: {find_result.get('error')}"
            }
        
        func_vaddr = int(find_result["function_address"], 16)
        func_file_offset = int(find_result["function_file_offset"], 16)
        
        # print(f"Target function found at vaddr: 0x{func_vaddr:x} (offset: 0x{func_file_offset:x})")
        
        # 2. 准备 Patch 数据
        # ARM64: MOV W0, #1; RET
        # 20 00 80 52  MOV W0, #1
        # C0 03 5F D6  RET
        patch_code = bytes.fromhex("20008052C0035FD6")
        
        # 3. 读取并修改文件
        with open(so_path, 'rb') as f:
            data = bytearray(f.read())
            
        # 检查偏移是否有效
        if func_file_offset + len(patch_code) > len(data):
            return {"success": False, "output_path": "", "patches": [], "error": "Offset out of bounds"}
            
        # 应用 Patch
        original_bytes = data[func_file_offset:func_file_offset+len(patch_code)]
        data[func_file_offset:func_file_offset+len(patch_code)] = patch_code
        
        patches = [{
            "vaddr": hex(func_vaddr),
            "offset": hex(func_file_offset),
            "original": original_bytes.hex(),
            "patched": patch_code.hex(),
            "description": "MOV W0, #1; RET"
        }]
        
        # 4. 保存文件
        if not output_path:
            base, ext = os.path.splitext(so_path)
            output_path = f"{base}_patched{ext}"
            
        with open(output_path, 'wb') as f:
            f.write(data)
            
        return {
            "success": True,
            "output_path": output_path,
            "patches": patches,
            "error": ""
        }
        
    except Exception as e:
        import traceback
        return {"success": False, "output_path": "", "patches": [], "error": f"{str(e)}\n{traceback.format_exc()}"}


def flutter_patch_apk(
    apk_path: str,
    output_path: Optional[str] = None,
    arch: str = "arm64-v8a"
) -> dict:
    """
    自动patch Flutter APK的SSL验证
    
    流程：
    1. 提取libflutter.so
    2. Patch SSL验证
    3. 替换回APK
    4. 重新签名
    
    Args:
        apk_path: APK文件路径
        output_path: 输出路径（可选）
        arch: 架构（默认arm64-v8a）
    
    Returns:
        dict: {"success": bool, "output_path": str, "error": str}
    """
    if not os.path.exists(apk_path):
        return {"success": False, "output_path": "", "error": f"APK not found: {apk_path}"}
    
    temp_dir = tempfile.mkdtemp(prefix="flutter_patch_")
    
    try:
        # 1. 检测是否是Flutter应用
        from .so_utils import detect_flutter
        flutter_info = detect_flutter(apk_path)
        
        if not flutter_info.get("is_flutter"):
            shutil.rmtree(temp_dir, ignore_errors=True)
            return {
                "success": False,
                "output_path": "",
                "error": "Not a Flutter application"
            }
        
        # 2. 提取libflutter.so
        lib_path_in_apk = f"lib/{arch}/libflutter.so"
        extracted_so = os.path.join(temp_dir, "libflutter.so")
        
        with zipfile.ZipFile(apk_path, 'r') as zf:
            if lib_path_in_apk not in zf.namelist():
                # 尝试其他架构
                available_archs = flutter_info.get("architectures", [])
                if available_archs:
                    arch = available_archs[0]
                    lib_path_in_apk = f"lib/{arch}/libflutter.so"
                
                if lib_path_in_apk not in zf.namelist():
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    return {
                        "success": False,
                        "output_path": "",
                        "error": f"libflutter.so not found for arch: {arch}"
                    }
            
            with zf.open(lib_path_in_apk) as src, open(extracted_so, 'wb') as dst:
                dst.write(src.read())
        
        # 3. Patch SSL验证
        patched_so = os.path.join(temp_dir, "libflutter_patched.so")
        patch_result = patch_ssl_verify(extracted_so, patched_so)
        
        if not patch_result["success"]:
            shutil.rmtree(temp_dir, ignore_errors=True)
            return {
                "success": False,
                "output_path": "",
                "error": f"Patch failed: {patch_result['error']}"
            }
        
        # 4. 创建新APK
        if output_path is None:
            base, ext = os.path.splitext(apk_path)
            output_path = f"{base}_ssl_patched{ext}"
        
        # 复制原APK并替换libflutter.so
        shutil.copy2(apk_path, output_path)
        
        with zipfile.ZipFile(output_path, 'a') as zf:
            # 删除原来的
            # 注意：zipfile不支持直接删除，需要重新创建
            pass
        
        # 使用更可靠的方式：解压-替换-重新打包
        extract_dir = os.path.join(temp_dir, "apk_extracted")
        with zipfile.ZipFile(apk_path, 'r') as zf:
            zf.extractall(extract_dir)
        
        # 替换libflutter.so
        target_so = os.path.join(extract_dir, "lib", arch, "libflutter.so")
        if os.path.exists(target_so):
            shutil.copy2(patched_so, target_so)
        
        # 重新打包
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(extract_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, extract_dir)
                    zf.write(file_path, arcname)
        
        # 清理
        shutil.rmtree(temp_dir, ignore_errors=True)
        
        return {
            "success": True,
            "output_path": output_path,
            "architecture": arch,
            "patches_applied": len(patch_result.get("patches", [])),
            "note": "APK needs to be re-signed before installation",
            "error": ""
        }
    
    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return {"success": False, "output_path": "", "error": str(e)}
