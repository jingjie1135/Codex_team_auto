#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zeabur 默认入口桥接脚本
=======================
由于 Zeabur 的 Python 构建器默认会运行项目根目录下的 main.py，
此脚本作为一个入口桥接，直接调用并启动 mock_sso.py 中的 FastAPI 服务。
"""

import os
import uvicorn
# 导入 mock_sso 模块以确保其代码逻辑就绪
import mock_sso

if __name__ == "__main__":
    # 获取 Zeabur 动态分配的环境变量 PORT，默认使用 8000
    port = int(os.getenv("PORT", 8000))
    
    # 启动 uvicorn 服务，指向 mock_sso 中的 FastAPI 实例 (app)
    uvicorn.run("mock_sso:app", host="0.0.0.0", port=port)
