"""SO文件分析工具"""
import os
import zipfile
import tempfile
import shutil
from pathlib import Path
from typing import Optional, List, Dict

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False


def check_lief() -> dict:
    """检查lief库是否可用"""
    return {
        "available": LIEF_AVAILABLE,
        "message": "lief is available" if LIEF_AVAILABLE else "Please install: pip install lief"
    }


def list_libs_from_apk(apk_path: str) -> dict:
    """
    列出APK中的所有SO库
    
    Args:
        apk_path: APK文件路径
    
    Returns:
        dict: {"success": bool, "libs": list, "error": str}
    """
    if not os.path.exists(apk_path):
        return {"success": False, "libs": [], "error": f"APK not found: {apk_path}"}
    
    try:
        libs = []
        with zipfile.ZipFile(apk_path, 'r') as zf:
            for name in zf.namelist():
                if name.startswith("lib/") and name.endswith(".so"):
                    parts = name.split("/")
                    if len(parts) >= 3:
                        arch = parts[1]
                        lib_name = parts[2]
                        size = zf.getinfo(name).file_size
                        libs.append({
                            "name": lib_name,
                            "arch": arch,
                            "path": name,
                            "size": size,
                            "size_mb": round(size / 1024 / 1024, 2)
                        })
        
        # 按架构分组
        by_arch = {}
        for lib in libs:
            arch = lib["arch"]
            if arch not in by_arch:
                by_arch[arch] = []
            by_arch[arch].append(lib["name"])
        
        return {
            "success": True,
            "libs": libs,
            "by_arch": by_arch,
            "total": len(libs),
            "architectures": list(by_arch.keys()),
            "error": ""
        }
    except Exception as e:
        return {"success": False, "libs": [], "error": str(e)}


def extract_so_from_apk(
    apk_path: str,
    lib_name: str,
    arch: str = "arm64-v8a",
    output_dir: Optional[str] = None
) -> dict:
    """
    从APK中提取SO文件
    
    Args:
        apk_path: APK文件路径
        lib_name: SO库名称（如 libflutter.so）
        arch: 架构（arm64-v8a, armeabi-v7a, x86, x86_64）
        output_dir: 输出目录（可选）
    
    Returns:
        dict: {"success": bool, "output_path": str, "error": str}
    """
    if not os.path.exists(apk_path):
        return {"success": False, "output_path": "", "error": f"APK not found: {apk_path}"}
    
    lib_path_in_apk = f"lib/{arch}/{lib_name}"
    
    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            if lib_path_in_apk not in zf.namelist():
                return {
                    "success": False,
                    "output_path": "",
                    "error": f"Library not found: {lib_path_in_apk}"
                }
            
            if output_dir is None:
                output_dir = tempfile.mkdtemp(prefix="so_extract_")
            
            output_path = os.path.join(output_dir, lib_name)
            
            with zf.open(lib_path_in_apk) as src, open(output_path, 'wb') as dst:
                dst.write(src.read())
            
            return {
                "success": True,
                "output_path": output_path,
                "arch": arch,
                "error": ""
            }
    except Exception as e:
        return {"success": False, "output_path": "", "error": str(e)}


def get_so_info(so_path: str) -> dict:
    """
    获取SO文件基本信息
    
    Args:
        so_path: SO文件路径
    
    Returns:
        dict: SO信息
    """
    if not LIEF_AVAILABLE:
        return {"success": False, "error": "lief not available. Install: pip install lief"}
    
    if not os.path.exists(so_path):
        return {"success": False, "error": f"File not found: {so_path}"}
    
    try:
        binary = lief.parse(so_path)
        if binary is None:
            return {"success": False, "error": "Failed to parse SO file"}
        
        # 基本信息
        info = {
            "name": os.path.basename(so_path),
            "format": binary.format.name if hasattr(binary.format, 'name') else str(binary.format),
            "size": os.path.getsize(so_path),
            "size_mb": round(os.path.getsize(so_path) / 1024 / 1024, 2),
        }
        
        # ELF特有信息
        if hasattr(binary, 'header'):
            header = binary.header
            info["architecture"] = header.machine_type.name if hasattr(header.machine_type, 'name') else str(header.machine_type)
            info["is_64bit"] = header.identity_class.name == "CLASS64" if hasattr(header.identity_class, 'name') else False
            info["endianness"] = header.identity_data.name if hasattr(header.identity_data, 'name') else "unknown"
        
        # 导出函数数量
        if hasattr(binary, 'exported_functions'):
            info["exported_functions_count"] = len(list(binary.exported_functions))
        
        # 导入函数数量
        if hasattr(binary, 'imported_functions'):
            info["imported_functions_count"] = len(list(binary.imported_functions))
        
        # 依赖库
        if hasattr(binary, 'libraries'):
            info["dependencies"] = list(binary.libraries)
        
        return {
            "success": True,
            "info": info,
            "error": ""
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_exports(so_path: str, search: str = "", limit: int = 100) -> dict:
    """
    获取SO导出函数列表
    
    Args:
        so_path: SO文件路径
        search: 搜索过滤
        limit: 最多返回数量
    
    Returns:
        dict: {"success": bool, "exports": list, "error": str}
    """
    if not LIEF_AVAILABLE:
        return {"success": False, "exports": [], "error": "lief not available"}
    
    if not os.path.exists(so_path):
        return {"success": False, "exports": [], "error": f"File not found: {so_path}"}
    
    try:
        binary = lief.parse(so_path)
        if binary is None:
            return {"success": False, "exports": [], "error": "Failed to parse SO file"}
        
        exports = []
        for func in binary.exported_functions:
            name = func.name if hasattr(func, 'name') else str(func)
            if search and search.lower() not in name.lower():
                continue
            exports.append({
                "name": name,
                "address": hex(func.address) if hasattr(func, 'address') else "0x0"
            })
        
        total = len(exports)
        
        return {
            "success": True,
            "exports": exports[:limit],
            "total": total,
            "returned": min(total, limit),
            "error": ""
        }
    except Exception as e:
        return {"success": False, "exports": [], "error": str(e)}


def get_imports(so_path: str, search: str = "", limit: int = 100) -> dict:
    """
    获取SO导入函数列表
    
    Args:
        so_path: SO文件路径
        search: 搜索过滤
        limit: 最多返回数量
    
    Returns:
        dict: {"success": bool, "imports": list, "error": str}
    """
    if not LIEF_AVAILABLE:
        return {"success": False, "imports": [], "error": "lief not available"}
    
    if not os.path.exists(so_path):
        return {"success": False, "imports": [], "error": f"File not found: {so_path}"}
    
    try:
        binary = lief.parse(so_path)
        if binary is None:
            return {"success": False, "imports": [], "error": "Failed to parse SO file"}
        
        imports = []
        for func in binary.imported_functions:
            name = func.name if hasattr(func, 'name') else str(func)
            if search and search.lower() not in name.lower():
                continue
            imports.append({
                "name": name,
                "library": func.library.name if hasattr(func, 'library') and func.library else "unknown"
            })
        
        total = len(imports)
        
        return {
            "success": True,
            "imports": imports[:limit],
            "total": total,
            "returned": min(total, limit),
            "error": ""
        }
    except Exception as e:
        return {"success": False, "imports": [], "error": str(e)}


def get_strings(so_path: str, min_length: int = 4, search: str = "", limit: int = 200) -> dict:
    """
    提取SO文件中的字符串
    
    Args:
        so_path: SO文件路径
        min_length: 最小字符串长度
        search: 搜索过滤
        limit: 最多返回数量
    
    Returns:
        dict: {"success": bool, "strings": list, "error": str}
    """
    if not os.path.exists(so_path):
        return {"success": False, "strings": [], "error": f"File not found: {so_path}"}
    
    try:
        strings = []
        with open(so_path, 'rb') as f:
            data = f.read()
        
        # 提取ASCII字符串
        current = []
        for byte in data:
            if 32 <= byte < 127:  # 可打印ASCII
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    s = ''.join(current)
                    if not search or search.lower() in s.lower():
                        strings.append(s)
                current = []
        
        # 处理最后一个字符串
        if len(current) >= min_length:
            s = ''.join(current)
            if not search or search.lower() in s.lower():
                strings.append(s)
        
        total = len(strings)
        
        return {
            "success": True,
            "strings": strings[:limit],
            "total": total,
            "returned": min(total, limit),
            "error": ""
        }
    except Exception as e:
        return {"success": False, "strings": [], "error": str(e)}


def search_symbol(so_path: str, pattern: str, limit: int = 50) -> dict:
    """
    搜索符号（导出+导入）
    
    Args:
        so_path: SO文件路径
        pattern: 搜索模式
        limit: 最多返回数量
    
    Returns:
        dict: {"success": bool, "results": list, "error": str}
    """
    if not LIEF_AVAILABLE:
        return {"success": False, "results": [], "error": "lief not available"}
    
    if not os.path.exists(so_path):
        return {"success": False, "results": [], "error": f"File not found: {so_path}"}
    
    try:
        binary = lief.parse(so_path)
        if binary is None:
            return {"success": False, "results": [], "error": "Failed to parse SO file"}
        
        results = []
        pattern_lower = pattern.lower()
        
        # 搜索导出
        for func in binary.exported_functions:
            name = func.name if hasattr(func, 'name') else str(func)
            if pattern_lower in name.lower():
                results.append({
                    "name": name,
                    "type": "export",
                    "address": hex(func.address) if hasattr(func, 'address') else "0x0"
                })
        
        # 搜索导入
        for func in binary.imported_functions:
            name = func.name if hasattr(func, 'name') else str(func)
            if pattern_lower in name.lower():
                results.append({
                    "name": name,
                    "type": "import",
                    "library": func.library.name if hasattr(func, 'library') and func.library else "unknown"
                })
        
        return {
            "success": True,
            "results": results[:limit],
            "total": len(results),
            "pattern": pattern,
            "error": ""
        }
    except Exception as e:
        return {"success": False, "results": [], "error": str(e)}


def detect_flutter(apk_path: str) -> dict:
    """
    检测是否是Flutter应用
    
    Args:
        apk_path: APK文件路径
    
    Returns:
        dict: {"success": bool, "is_flutter": bool, "details": dict, "error": str}
    """
    if not os.path.exists(apk_path):
        return {"success": False, "is_flutter": False, "error": f"APK not found: {apk_path}"}
    
    try:
        flutter_indicators = {
            "libflutter.so": False,
            "libapp.so": False,
            "flutter_assets": False,
            "kernel_blob.bin": False
        }
        
        flutter_archs = []
        
        with zipfile.ZipFile(apk_path, 'r') as zf:
            for name in zf.namelist():
                # 检查libflutter.so
                if "libflutter.so" in name:
                    flutter_indicators["libflutter.so"] = True
                    # 提取架构
                    parts = name.split("/")
                    if len(parts) >= 2 and parts[0] == "lib":
                        arch = parts[1]
                        if arch not in flutter_archs:
                            flutter_archs.append(arch)
                
                # 检查libapp.so（Dart代码编译后）
                if "libapp.so" in name:
                    flutter_indicators["libapp.so"] = True
                
                # 检查flutter_assets
                if "flutter_assets" in name:
                    flutter_indicators["flutter_assets"] = True
                
                # 检查kernel_blob.bin
                if "kernel_blob.bin" in name:
                    flutter_indicators["kernel_blob.bin"] = True
        
        is_flutter = flutter_indicators["libflutter.so"] and flutter_indicators["libapp.so"]
        
        return {
            "success": True,
            "is_flutter": is_flutter,
            "indicators": flutter_indicators,
            "architectures": flutter_archs,
            "confidence": sum(flutter_indicators.values()) / len(flutter_indicators) * 100,
            "error": ""
        }
    except Exception as e:
        return {"success": False, "is_flutter": False, "error": str(e)}
