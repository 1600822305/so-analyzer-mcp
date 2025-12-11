"""配置文件"""
import os
from pathlib import Path

# 工作目录
WORKSPACE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "workspace")

# 临时目录
TEMP_DIR = os.path.join(WORKSPACE_DIR, "temp")

# 确保目录存在
Path(WORKSPACE_DIR).mkdir(parents=True, exist_ok=True)
Path(TEMP_DIR).mkdir(parents=True, exist_ok=True)

# 默认限制
DEFAULT_LIMIT = 100
MAX_STRING_LENGTH = 200
MIN_STRING_LENGTH = 4
