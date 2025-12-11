"""Flutter专用工具"""
import os
import re
import zipfile
import tempfile
import shutil
from pathlib import Path
from typing import Optional, List, Dict, Tuple

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False


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
    
    警告：这是一个危险操作，仅用于安全研究！
    
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
        binary = lief.parse(so_path)
        if binary is None:
            return {"success": False, "output_path": "", "patches": [], "error": "Failed to parse SO file"}
        
        patches = []
        
        # 查找需要patch的函数
        target_functions = []
        for func in binary.exported_functions:
            name = func.name if hasattr(func, 'name') else str(func)
            # 查找证书验证相关函数
            if 'verify' in name.lower() and ('cert' in name.lower() or 'ssl' in name.lower() or 'x509' in name.lower()):
                target_functions.append({
                    "name": name,
                    "address": func.address if hasattr(func, 'address') else 0
                })
        
        if not target_functions:
            return {
                "success": False,
                "output_path": "",
                "patches": [],
                "error": "No SSL verify functions found to patch"
            }
        
        # 读取原始数据
        with open(so_path, 'rb') as f:
            data = bytearray(f.read())
        
        # 获取架构
        is_arm64 = False
        if hasattr(binary, 'header'):
            arch = binary.header.machine_type.name if hasattr(binary.header.machine_type, 'name') else ""
            is_arm64 = "AARCH64" in arch or "ARM64" in arch.upper()
        
        # Patch: 让函数直接返回0（成功）
        # ARM64: mov x0, #0; ret
        # ARM: mov r0, #0; bx lr
        if is_arm64:
            patch_bytes = bytes([0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6])  # mov x0, #0; ret
        else:
            patch_bytes = bytes([0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1])  # mov r0, #0; bx lr
        
        # 应用patch
        for func in target_functions:
            if func["address"] > 0:
                # 获取文件偏移
                offset = func["address"]
                
                # 检查偏移是否有效
                if offset < len(data) - len(patch_bytes):
                    original = bytes(data[offset:offset + len(patch_bytes)])
                    data[offset:offset + len(patch_bytes)] = patch_bytes
                    patches.append({
                        "function": func["name"],
                        "address": hex(offset),
                        "original": original.hex(),
                        "patched": patch_bytes.hex()
                    })
        
        if not patches:
            return {
                "success": False,
                "output_path": "",
                "patches": [],
                "error": "Could not apply patches (invalid addresses)"
            }
        
        # 保存patched文件
        if output_path is None:
            base, ext = os.path.splitext(so_path)
            output_path = f"{base}_patched{ext}"
        
        with open(output_path, 'wb') as f:
            f.write(data)
        
        return {
            "success": True,
            "output_path": output_path,
            "patches": patches,
            "architecture": "arm64" if is_arm64 else "arm32",
            "error": ""
        }
    except Exception as e:
        return {"success": False, "output_path": "", "patches": [], "error": str(e)}


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
