"""反编译工具 - Ghidra Headless 集成 + 简单伪代码生成"""
import os
import subprocess
import tempfile
import shutil
import struct
from typing import Optional, Dict, List
from pathlib import Path

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False


# Ghidra 安装路径（可通过环境变量配置）
GHIDRA_HOME = os.environ.get("GHIDRA_HOME", "")

# Radare2 路径配置
RADARE2_PATH = os.environ.get("RADARE2_PATH", r"K:\Cherry\androidmtmangebg\radare2\radare2-5.9.6-w64\bin\radare2.exe")

# Ghidra 反编译脚本
GHIDRA_DECOMPILE_SCRIPT = '''
# Ghidra Headless 反编译脚本
# @category: Analysis
# @author: SO-Analyzer

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import json

def decompile_function(program, address):
    """反编译指定地址的函数"""
    decompiler = DecompInterface()
    decompiler.openProgram(program)
    
    func_manager = program.getFunctionManager()
    addr = program.getAddressFactory().getAddress(hex(address))
    
    func = func_manager.getFunctionContaining(addr)
    if func is None:
        # 如果没有函数，尝试创建一个
        from ghidra.program.model.symbol import SourceType
        func = createFunction(addr, None)
        if func is None:
            return {"error": "Cannot find or create function at address"}
    
    monitor = ConsoleTaskMonitor()
    result = decompiler.decompileFunction(func, 60, monitor)
    
    if result.decompileCompleted():
        decomp_func = result.getDecompiledFunction()
        if decomp_func:
            return {
                "success": True,
                "function_name": func.getName(),
                "address": hex(func.getEntryPoint().getOffset()),
                "code": decomp_func.getC(),
                "signature": func.getSignature().getPrototypeString()
            }
    
    return {"success": False, "error": result.getErrorMessage()}

# 主逻辑
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        addr = int(sys.argv[1], 16) if sys.argv[1].startswith("0x") else int(sys.argv[1])
        result = decompile_function(currentProgram, addr)
        print("===DECOMPILE_RESULT===")
        print(json.dumps(result, indent=2))
        print("===END_RESULT===")
'''


def check_ghidra() -> dict:
    """
    检查 Ghidra 环境是否可用
    
    Returns:
        dict: {"available": bool, "ghidra_home": str, "message": str}
    """
    global GHIDRA_HOME
    
    # 检查环境变量
    if not GHIDRA_HOME:
        # 尝试常见路径
        common_paths = [
            r"C:\ghidra",
            r"C:\Program Files\ghidra",
            r"D:\ghidra",
            "/opt/ghidra",
            "/usr/local/ghidra",
            os.path.expanduser("~/ghidra"),
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                # 查找 analyzeHeadless
                for root, dirs, files in os.walk(path):
                    if "analyzeHeadless.bat" in files or "analyzeHeadless" in files:
                        GHIDRA_HOME = path
                        break
                if GHIDRA_HOME:
                    break
    
    if not GHIDRA_HOME or not os.path.exists(GHIDRA_HOME):
        return {
            "available": False,
            "ghidra_home": "",
            "message": "Ghidra not found. Set GHIDRA_HOME environment variable.",
            "install_hint": "Download from https://ghidra-sre.org/"
        }
    
    # 查找 analyzeHeadless
    analyze_headless = None
    for root, dirs, files in os.walk(GHIDRA_HOME):
        if os.name == 'nt':
            if "analyzeHeadless.bat" in files:
                analyze_headless = os.path.join(root, "analyzeHeadless.bat")
                break
        else:
            if "analyzeHeadless" in files:
                analyze_headless = os.path.join(root, "analyzeHeadless")
                break
    
    if not analyze_headless:
        return {
            "available": False,
            "ghidra_home": GHIDRA_HOME,
            "message": "analyzeHeadless not found in GHIDRA_HOME"
        }
    
    return {
        "available": True,
        "ghidra_home": GHIDRA_HOME,
        "analyze_headless": analyze_headless,
        "message": "Ghidra is available"
    }


def decompile_with_ghidra(so_path: str, address: int, timeout: int = 120) -> dict:
    """
    使用 Ghidra Headless 反编译函数
    
    Args:
        so_path: SO文件路径
        address: 函数虚拟地址
        timeout: 超时时间（秒）
    
    Returns:
        dict: {"success": bool, "code": str, "error": str}
    """
    ghidra_info = check_ghidra()
    if not ghidra_info["available"]:
        return {"success": False, "code": "", "error": ghidra_info["message"]}
    
    if not os.path.exists(so_path):
        return {"success": False, "code": "", "error": f"File not found: {so_path}"}
    
    temp_dir = tempfile.mkdtemp(prefix="ghidra_decompile_")
    
    try:
        # 创建 Ghidra 脚本
        script_path = os.path.join(temp_dir, "DecompileFunction.py")
        with open(script_path, 'w') as f:
            f.write(GHIDRA_DECOMPILE_SCRIPT)
        
        # 准备项目目录
        project_dir = os.path.join(temp_dir, "project")
        os.makedirs(project_dir, exist_ok=True)
        
        analyze_headless = ghidra_info["analyze_headless"]
        
        # 构建命令
        cmd = [
            analyze_headless,
            project_dir,
            "TempProject",
            "-import", so_path,
            "-postScript", script_path, hex(address),
            "-deleteProject",
            "-noanalysis"  # 跳过完整分析，加快速度
        ]
        
        # 执行
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=temp_dir
        )
        
        # 解析输出
        output = result.stdout + result.stderr
        
        if "===DECOMPILE_RESULT===" in output:
            start = output.find("===DECOMPILE_RESULT===") + len("===DECOMPILE_RESULT===")
            end = output.find("===END_RESULT===")
            if end > start:
                import json
                result_json = output[start:end].strip()
                try:
                    decompile_result = json.loads(result_json)
                    return decompile_result
                except:
                    pass
        
        return {
            "success": False,
            "code": "",
            "error": f"Ghidra output parsing failed. Return code: {result.returncode}",
            "stdout": output[:2000]
        }
    
    except subprocess.TimeoutExpired:
        return {"success": False, "code": "", "error": f"Ghidra timeout after {timeout}s"}
    except Exception as e:
        import traceback
        return {"success": False, "code": "", "error": f"{str(e)}\n{traceback.format_exc()}"}
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def decompile_simple(so_path: str, address: int, size: int = 256) -> dict:
    """
    简单伪代码生成（基于模式匹配，无需Ghidra）
    
    这是一个轻量级的反编译器，通过识别常见的ARM64指令模式
    生成类C的伪代码。精度不如Ghidra，但速度快。
    
    Args:
        so_path: SO文件路径
        address: 函数虚拟地址
        size: 分析字节数
    
    Returns:
        dict: {"success": bool, "code": str, "instructions": list}
    """
    if not LIEF_AVAILABLE or not CAPSTONE_AVAILABLE:
        return {"success": False, "code": "", 
                "error": "lief and capstone required"}
    
    if not os.path.exists(so_path):
        return {"success": False, "code": "", 
                "error": f"File not found: {so_path}"}
    
    try:
        with open(so_path, 'rb') as f:
            data = f.read()
        
        binary = lief.parse(so_path)
        if binary is None:
            return {"success": False, "code": "", 
                    "error": "Failed to parse SO file"}
        
        # 获取 .text 段
        text_section = None
        for section in binary.sections:
            if section.name == ".text":
                text_section = section
                break
        
        if text_section is None:
            return {"success": False, "code": "", 
                    "error": ".text section not found"}
        
        text_file_start = text_section.file_offset
        text_vaddr_base = text_section.virtual_address
        
        # 计算文件偏移
        file_offset = text_file_start + (address - text_vaddr_base)
        
        # 获取导出函数名
        exported_funcs = {}
        for func in binary.exported_functions:
            if hasattr(func, 'address') and hasattr(func, 'name'):
                exported_funcs[func.address] = func.name
        
        func_name = exported_funcs.get(address, f"sub_{address:x}")
        
        # 读取代码
        code_bytes = bytes(data[file_offset:file_offset + size])
        
        # 反汇编
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        md.detail = True
        
        instructions = list(md.disasm(code_bytes, address))
        
        # 生成伪代码
        pseudo_lines = []
        pseudo_lines.append(f"// Function: {func_name}")
        pseudo_lines.append(f"// Address: 0x{address:x}")
        pseudo_lines.append(f"// Size: {size} bytes")
        pseudo_lines.append("")
        pseudo_lines.append(f"int {func_name}() {{")
        
        # 跟踪寄存器状态
        reg_state = {}
        indent = "    "
        
        # 分支目标
        branch_targets = set()
        for insn in instructions:
            if insn.mnemonic.startswith('b') and insn.operands:
                for op in insn.operands:
                    if hasattr(op, 'imm'):
                        branch_targets.add(op.imm)
        
        for insn in instructions:
            mnemonic = insn.mnemonic.lower()
            ops = insn.op_str
            addr = insn.address
            
            # 检查是否是分支目标
            if addr in branch_targets:
                pseudo_lines.append(f"\nlabel_{addr:x}:")
            
            comment = f"// 0x{addr:x}: {insn.mnemonic} {ops}"
            
            # 转换指令到伪代码
            if mnemonic == "ret":
                pseudo_lines.append(f"{indent}return;  {comment}")
            
            elif mnemonic == "mov":
                parts = ops.split(',')
                if len(parts) >= 2:
                    dst = parts[0].strip()
                    src = parts[1].strip()
                    pseudo_lines.append(f"{indent}{dst} = {src};  {comment}")
            
            elif mnemonic in ["movz", "movk"]:
                parts = ops.split(',')
                if len(parts) >= 2:
                    dst = parts[0].strip()
                    src = ','.join(parts[1:]).strip()
                    pseudo_lines.append(f"{indent}{dst} = {src};  {comment}")
            
            elif mnemonic == "add":
                parts = ops.split(',')
                if len(parts) >= 3:
                    dst = parts[0].strip()
                    src1 = parts[1].strip()
                    src2 = parts[2].strip()
                    pseudo_lines.append(f"{indent}{dst} = {src1} + {src2};  {comment}")
            
            elif mnemonic == "sub":
                parts = ops.split(',')
                if len(parts) >= 3:
                    dst = parts[0].strip()
                    src1 = parts[1].strip()
                    src2 = parts[2].strip()
                    pseudo_lines.append(f"{indent}{dst} = {src1} - {src2};  {comment}")
            
            elif mnemonic == "mul":
                parts = ops.split(',')
                if len(parts) >= 3:
                    dst = parts[0].strip()
                    src1 = parts[1].strip()
                    src2 = parts[2].strip()
                    pseudo_lines.append(f"{indent}{dst} = {src1} * {src2};  {comment}")
            
            elif mnemonic == "ldr":
                parts = ops.split(',', 1)
                if len(parts) >= 2:
                    dst = parts[0].strip()
                    src = parts[1].strip()
                    pseudo_lines.append(f"{indent}{dst} = *({src});  {comment}")
            
            elif mnemonic == "str":
                parts = ops.split(',', 1)
                if len(parts) >= 2:
                    src = parts[0].strip()
                    dst = parts[1].strip()
                    pseudo_lines.append(f"{indent}*({dst}) = {src};  {comment}")
            
            elif mnemonic == "stp":
                pseudo_lines.append(f"{indent}// store pair  {comment}")
            
            elif mnemonic == "ldp":
                pseudo_lines.append(f"{indent}// load pair  {comment}")
            
            elif mnemonic == "bl":
                target = ops.strip()
                # 查找函数名
                if insn.operands:
                    target_addr = insn.operands[0].imm
                    target_name = exported_funcs.get(target_addr, f"sub_{target_addr:x}")
                    pseudo_lines.append(f"{indent}{target_name}();  {comment}")
                else:
                    pseudo_lines.append(f"{indent}call({target});  {comment}")
            
            elif mnemonic == "blr":
                pseudo_lines.append(f"{indent}(*{ops})();  {comment}")
            
            elif mnemonic == "cmp":
                parts = ops.split(',')
                if len(parts) >= 2:
                    pseudo_lines.append(f"{indent}// compare {parts[0].strip()} with {parts[1].strip()}  {comment}")
            
            elif mnemonic.startswith("b.") or mnemonic in ["cbz", "cbnz", "tbz", "tbnz"]:
                cond = mnemonic[2:] if mnemonic.startswith("b.") else mnemonic
                target = ops.split(',')[-1].strip()
                if insn.operands:
                    target_addr = insn.operands[-1].imm if hasattr(insn.operands[-1], 'imm') else 0
                    pseudo_lines.append(f"{indent}if ({cond}) goto label_{target_addr:x};  {comment}")
                else:
                    pseudo_lines.append(f"{indent}if ({cond}) goto {target};  {comment}")
            
            elif mnemonic == "b":
                if insn.operands:
                    target_addr = insn.operands[0].imm
                    pseudo_lines.append(f"{indent}goto label_{target_addr:x};  {comment}")
                else:
                    pseudo_lines.append(f"{indent}goto {ops};  {comment}")
            
            elif mnemonic in ["adrp", "adr"]:
                parts = ops.split(',')
                if len(parts) >= 2:
                    pseudo_lines.append(f"{indent}{parts[0].strip()} = &page({parts[1].strip()});  {comment}")
            
            elif mnemonic == "nop":
                pass  # 忽略 NOP
            
            elif mnemonic in ["pacibsp", "autibsp", "paciasp", "autiasp"]:
                pseudo_lines.append(f"{indent}// PAC: {mnemonic}  {comment}")
            
            else:
                pseudo_lines.append(f"{indent}// {insn.mnemonic} {ops}  {comment}")
        
        pseudo_lines.append("}")
        
        return {
            "success": True,
            "function_name": func_name,
            "address": hex(address),
            "code": "\n".join(pseudo_lines),
            "instruction_count": len(instructions),
            "note": "Simple pattern-based decompilation. Use Ghidra for better results.",
            "error": ""
        }
    
    except Exception as e:
        import traceback
        return {"success": False, "code": "", 
                "error": f"{str(e)}\n{traceback.format_exc()}"}


def check_radare2() -> dict:
    """
    检查 Radare2 环境是否可用
    
    Returns:
        dict: {"available": bool, "path": str, "version": str}
    """
    global RADARE2_PATH
    
    # 检查配置的路径
    if os.path.exists(RADARE2_PATH):
        try:
            result = subprocess.run(
                [RADARE2_PATH, "-v"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                version = result.stdout.split('\n')[0] if result.stdout else "unknown"
                return {
                    "available": True,
                    "path": RADARE2_PATH,
                    "version": version
                }
        except:
            pass
    
    # 尝试系统PATH
    try:
        result = subprocess.run(
            ["radare2", "-v"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            RADARE2_PATH = "radare2"
            version = result.stdout.split('\n')[0] if result.stdout else "unknown"
            return {
                "available": True,
                "path": "radare2 (system)",
                "version": version
            }
    except:
        pass
    
    return {
        "available": False,
        "path": "",
        "version": "",
        "message": "Radare2 not found. Set RADARE2_PATH or install radare2."
    }


def decompile_with_radare2(so_path: str, address: int, timeout: int = 60) -> dict:
    """
    使用 Radare2 + r2dec/pdc 反编译函数
    
    Args:
        so_path: SO文件路径
        address: 函数虚拟地址
        timeout: 超时时间（秒）
    
    Returns:
        dict: {"success": bool, "code": str, "error": str}
    """
    r2_info = check_radare2()
    if not r2_info["available"]:
        return {"success": False, "code": "", "error": r2_info.get("message", "Radare2 not available")}
    
    if not os.path.exists(so_path):
        return {"success": False, "code": "", "error": f"File not found: {so_path}"}
    
    try:
        # 构建radare2命令
        # 使用pdc（简单反编译）或pdg（如果r2ghidra可用）
        r2_commands = f"aaa;s {hex(address)};pdc"
        
        result = subprocess.run(
            [RADARE2_PATH, "-q", "-c", r2_commands, so_path],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        if result.returncode == 0 and result.stdout:
            code = result.stdout.strip()
            
            # 检查是否有有效输出
            if code and len(code) > 50:
                return {
                    "success": True,
                    "code": code,
                    "address": hex(address),
                    "error": ""
                }
            else:
                # 尝试使用pdf（反汇编+注释）作为后备
                r2_commands_fallback = f"aaa;s {hex(address)};pdf"
                result2 = subprocess.run(
                    [RADARE2_PATH, "-q", "-c", r2_commands_fallback, so_path],
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
                if result2.returncode == 0 and result2.stdout:
                    return {
                        "success": True,
                        "code": result2.stdout.strip(),
                        "address": hex(address),
                        "note": "Using disassembly (pdf) as fallback",
                        "error": ""
                    }
        
        return {
            "success": False,
            "code": "",
            "error": f"Radare2 failed: {result.stderr or 'No output'}",
            "stdout": result.stdout[:500] if result.stdout else ""
        }
    
    except subprocess.TimeoutExpired:
        return {"success": False, "code": "", "error": f"Radare2 timeout after {timeout}s"}
    except Exception as e:
        import traceback
        return {"success": False, "code": "", "error": f"{str(e)}\n{traceback.format_exc()}"}


def decompile(so_path: str, address: int, method: str = "radare2",
              size: int = 256, timeout: int = 120) -> dict:
    """
    反编译函数（统一接口）
    
    Args:
        so_path: SO文件路径
        address: 函数虚拟地址
        method: 反编译方法 ("radare2", "ghidra", "simple")
        size: 简单反编译时的字节数
        timeout: 超时时间
    
    Returns:
        dict: {"success": bool, "code": str, "method": str}
    """
    if method == "ghidra":
        result = decompile_with_ghidra(so_path, address, timeout)
        result["method"] = "ghidra"
    elif method == "radare2":
        result = decompile_with_radare2(so_path, address, timeout)
        result["method"] = "radare2"
    else:
        result = decompile_simple(so_path, address, size)
        result["method"] = "simple"
    
    return result
