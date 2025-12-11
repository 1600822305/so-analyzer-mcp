#!/usr/bin/env python3
"""SO Analyzer MCP Server 启动脚本"""

import asyncio
import sys
import os

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from so_analyzer.server import main

if __name__ == "__main__":
    asyncio.run(main())
