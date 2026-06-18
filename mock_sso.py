#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mock OIDC SSO 服务端 (FastAPI)
================================
专门用于与本项目中的自动化脚本 (codex_protocol_login.py 等) 进行对接。
提供免密、免人工交互的 /api/login 和 /api/register 接口，一键返回带有授权码的重定向回调链接。
同时暴露标准的 OIDC 发现端点、JWKS 公钥端点和 Token 交换端点，供 OpenAI 服务端验证子/母账号的身份。

安装依赖：
  pip install fastapi uvicorn PyJWT[crypto]

使用方法：
  python mock_sso.py --port 8000 --domain dfhdg.store --admin-token YOUR_ADMIN_TOKEN
"""

import os
import sys
import time
import uuid
import base64
import argparse
import logging
from typing import Dict, Optional
from fastapi import FastAPI, Request, HTTPException, Depends, Form
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# ── 日志配置 ──────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s - %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger("MockSSO")

# ── 命令行参数解析 ──────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="Mock OIDC SSO Server for Codex Automation")
parser.add_argument("--host", default="0.0.0.0", help="监听 IP (默认: 0.0.0.0)")
parser.add_argument("--port", type=int, default=8000, help="监听端口 (默认: 8000)")
parser.add_argument("--domain", default=os.getenv("DOMAIN", "dfhdg.store"), help="子/母账号生成的邮箱域名后缀")
parser.add_argument("--admin-token", default=os.getenv("ADMIN_TOKEN", "mock-sso-admin-secret-2026"), help="调用管理/注册接口所需的 Bearer Token")
parser.add_argument("--issuer-url", default=os.getenv("ISSUER_URL", ""), help="自定义外部 Issuer URL。如果不设置，将根据请求地址动态生成")
args, _ = parser.parse_known_args()

# ── 全局核心组件初始化 ──────────────────────────────────────────────
app = FastAPI(title="Mock OIDC SSO Server")
security = HTTPBearer()

# 缓存与数据内存存储（使用 Dict 模拟缓存）
# 授权码缓存：code -> {account, client_id, redirect_uri, nonce, code_challenge}
auth_codes: Dict[str, dict] = {}

# 密钥存储路径与内存缓存
KEY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "private_key.pem")
KID = "mock-sso-key-id-2026"

_cached_private_key: Optional[rsa.RSAPrivateKey] = None
_cached_jwks: Optional[dict] = None

# ── 性能优化：密钥生成与缓存处理 ──────────────────────────────────
def init_keys():
    """初始化并缓存 RSA 私钥和公钥 JWKS"""
    global _cached_private_key, _cached_jwks
    
    os.makedirs(KEY_DIR, exist_ok=True)
    
    # 加载或生成 RSA 私钥
    if os.path.exists(PRIVATE_KEY_PATH):
        logger.info(f"正在从本地加载私钥: {PRIVATE_KEY_PATH}")
        with open(PRIVATE_KEY_PATH, "rb") as f:
            _cached_private_key = serialization.load_pem_private_key(
                f.read(), password=None
            )
    else:
        logger.info("本地私钥不存在，正在生成新的 2048 位 RSA 私钥...")
        _cached_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        # 写入本地文件备份
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(
                _cached_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
        logger.info(f"私钥已成功保存至: {PRIVATE_KEY_PATH}")

    # 构建并缓存 JWKS
    public_key = _cached_private_key.public_key()
    pub_numbers = public_key.public_numbers()
    
    # 整数转 Base64URL 辅助函数
    def int_to_base64url(val: int) -> str:
        val_bytes = val.to_bytes((val.bit_length() + 7) // 8, byteorder="big")
        return base64.urlsafe_b64encode(val_bytes).decode("utf-8").rstrip("=")

    n_b64 = int_to_base64url(pub_numbers.n)
    e_b64 = int_to_base64url(pub_numbers.e)
    
    _cached_jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": KID,
                "use": "sig",
                "alg": "RS256",
                "n": n_b64,
                "e": e_b64
            }
        ]
    }
    logger.info("JWKS 公钥集合初始化并缓存成功。")

# ── 安全验证中间件 ────────────────────────────────────────────────
def verify_admin_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """校验是否持有正确的管理员 Token"""
    if credentials.credentials != args.admin_token:
        raise HTTPException(status_code=401, detail="Invalid admin token")
    return credentials.credentials

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    """精美的主页，用于直观验证 SSO 服务是否正常在线并展示元数据端点"""
    base_url = args.issuer_url or str(request.base_url).rstrip("/")
    return f"""
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Mock OIDC SSO Server</title>
        <style>
            :root {{
                --bg-color: #0b0f19;
                --card-bg: #151d30;
                --text-main: #f8fafc;
                --text-muted: #94a3b8;
                --primary: #38bdf8;
                --primary-glow: rgba(56, 189, 248, 0.15);
                --success: #10b981;
                --border-color: #1e293b;
            }}
            body {{
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
                background-color: var(--bg-color);
                color: var(--text-main);
                margin: 0;
                display: flex;
                align-items: center;
                justify-content: center;
                min-height: 100vh;
            }}
            .card {{
                background-color: var(--card-bg);
                border: 1px solid var(--border-color);
                border-radius: 16px;
                padding: 40px;
                max-width: 600px;
                width: 90%;
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
                text-align: center;
                animation: fadeIn 0.6s ease-out;
            }}
            @keyframes fadeIn {{
                from {{ opacity: 0; transform: translateY(10px); }}
                to {{ opacity: 1; transform: translateY(0); }}
            }}
            .badge-container {{
                display: flex;
                justify-content: center;
                gap: 10px;
                margin-bottom: 20px;
            }}
            .badge {{
                display: inline-flex;
                align-items: center;
                gap: 6px;
                font-size: 13px;
                font-weight: 600;
                padding: 6px 14px;
                border-radius: 30px;
                border: 1px solid transparent;
            }}
            .badge-online {{
                background-color: rgba(16, 185, 129, 0.1);
                color: var(--success);
                border-color: rgba(16, 185, 129, 0.2);
            }}
            .badge-online .dot {{
                width: 8px;
                height: 8px;
                background-color: var(--success);
                border-radius: 50%;
                box-shadow: 0 0 8px var(--success);
                animation: pulse 2s infinite;
            }}
            @keyframes pulse {{
                0% {{ transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }}
                70% {{ transform: scale(1); box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }}
                100% {{ transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }}
            }}
            .badge-domain {{
                background-color: rgba(56, 189, 248, 0.1);
                color: var(--primary);
                border-color: rgba(56, 189, 248, 0.2);
            }}
            h1 {{
                font-size: 28px;
                margin: 0 0 10px 0;
                background: linear-gradient(135deg, #f8fafc 0%, #94a3b8 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }}
            p {{
                color: var(--text-muted);
                line-height: 1.6;
                margin: 0 0 30px 0;
                font-size: 15px;
            }}
            .endpoints-title {{
                text-align: left;
                font-size: 14px;
                font-weight: 600;
                color: var(--text-muted);
                margin-bottom: 12px;
                text-transform: uppercase;
                letter-spacing: 0.05em;
            }}
            .endpoint-row {{
                background-color: rgba(11, 15, 25, 0.5);
                border: 1px solid var(--border-color);
                border-radius: 8px;
                padding: 12px 16px;
                margin-bottom: 12px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                gap: 15px;
            }}
            .endpoint-row:hover {{
                border-color: rgba(56, 189, 248, 0.4);
                box-shadow: 0 0 10px var(--primary-glow);
                transition: all 0.3s ease;
            }}
            .endpoint-path {{
                font-family: 'Fira Code', 'Courier New', Courier, monospace;
                font-size: 13px;
                color: var(--primary);
                word-break: break-all;
                text-align: left;
            }}
            .copy-btn {{
                background: none;
                border: 1px solid var(--border-color);
                color: var(--text-muted);
                cursor: pointer;
                padding: 6px 12px;
                font-size: 12px;
                border-radius: 6px;
                white-space: nowrap;
                transition: all 0.2s;
            }}
            .copy-btn:hover {{
                background-color: var(--primary);
                color: var(--bg-color);
                border-color: var(--primary);
            }}
        </style>
        <script>
            function copyText(text, btnId) {{
                navigator.clipboard.writeText(text).then(() => {{
                    const btn = document.getElementById(btnId);
                    const originalText = btn.innerText;
                    btn.innerText = "已复制 ✓";
                    btn.style.backgroundColor = "var(--success)";
                    btn.style.borderColor = "var(--success)";
                    btn.style.color = "#ffffff";
                    setTimeout(() => {{
                        btn.innerText = originalText;
                        btn.style.backgroundColor = "";
                        btn.style.borderColor = "";
                        btn.style.color = "";
                    }}, 1500);
                }});
            }}
        </script>
    </head>
    <body>
        <div class="card">
            <div class="badge-container">
                <span class="badge badge-online">
                    <span class="dot"></span> Running
                </span>
                <span class="badge badge-domain">
                    @{args.domain}
                </span>
            </div>
            <h1>Mock OIDC SSO Server</h1>
            <p>专门为 OpenAI/Codex 自动化集成测试量身定制的单点登录服务已成功在云端部署运行！</p>
            
            <div class="endpoints-title">OIDC 集成核心端点</div>
            
            <div class="endpoint-row">
                <span class="endpoint-path">{base_url}/.well-known/openid-configuration</span>
                <button id="btn-discovery" class="copy-btn" onclick="copyText('{base_url}/.well-known/openid-configuration', 'btn-discovery')">复制发现链接</button>
            </div>
            
            <div class="endpoint-row">
                <span class="endpoint-path">{base_url}/jwks.json</span>
                <button id="btn-jwks" class="copy-btn" onclick="copyText('{base_url}/jwks.json', 'btn-jwks')">复制公钥链接</button>
            </div>
        </div>
    </body>
    </html>
    """

# ── OIDC 发现与 JWKS 端点 ──────────────────────────────────────────
@app.get("/.well-known/openid-configuration")
def openid_configuration(request: Request):
    """标准的 OIDC Discovery 元数据端点"""
    # 优先使用配置的 issuer-url，否则根据当前请求的 Base URL 动态生成
    base_url = args.issuer_url or str(request.base_url).rstrip("/")
    
    return {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/authorize",
        "token_endpoint": f"{base_url}/token",
        "jwks_uri": f"{base_url}/jwks.json",
        "response_types_supported": ["code", "token", "id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"]
    }

@app.get("/jwks.json")
def jwks():
    """返回 JWKS，OpenAI 服务端用来验证 ID Token 签名"""
    return JSONResponse(content=_cached_jwks)

# ── 本项目定制 of API 登录与注册端点 ──────────────────────────────────
def generate_redirect_response(payload: dict, code_type: str) -> dict:
    """生成授权码并构建重定向链接"""
    account = payload.get("account")
    client_id = payload.get("client_id")
    redirect_uri = payload.get("redirect_uri")
    state = payload.get("state")
    nonce = payload.get("nonce")
    code_challenge = payload.get("code_challenge")
    
    if not account or not redirect_uri:
        raise HTTPException(status_code=400, detail="Missing account or redirect_uri")
    
    # 1. 生成并存入内存授权码（包含必要的元数据）
    code = f"mock_code_{uuid.uuid4().hex}"
    auth_codes[code] = {
        "account": account,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "timestamp": time.time()
    }
    
    # 2. 拼接最终的 OIDC 回调跳转地址
    query_glue = "&" if "?" in redirect_uri else "?"
    callback_url = f"{redirect_uri}{query_glue}code={code}&state={state or ''}"
    
    logger.info(f"[{code_type.upper()}] 成功为账号 {account} 生成授权码: {code}")
    return {"redirect_uri": callback_url}

@app.post("/api/register")
def api_register(payload: dict, token: str = Depends(verify_admin_token)):
    """注册子号 (兼容后台纯创建与OAuth登录流)"""
    account = payload.get("account")
    invite_code = payload.get("invite_code")
    redirect_uri = payload.get("redirect_uri")
    
    logger.info(f"收到注册请求: 账号前缀={account}, 邀请码={invite_code}, 重定向={redirect_uri}")
    
    if not redirect_uri:
        # 如果没有重定向地址，说明是脚本在后台自动建立账号 (例如 auto_create_seeds)
        # 直接返回成功注册响应即可
        return {
            "user": {
                "created": True,
                "email": f"{account}@{args.domain}"
            }
        }
        
    # 如果有重定向地址，说明是子号在 OIDC 登录过程中触发自动注册，走 OAuth 码生成流
    return generate_redirect_response(payload, "register")

@app.post("/api/login")
def api_login(payload: dict, token: str = Depends(verify_admin_token)):
    """直接登录母号"""
    logger.info(f"收到母号登录请求: 账号前缀={payload.get('account')}")
    return generate_redirect_response(payload, "login")

# ── 模拟的标准 OIDC 授权端点 (防备常规跳转流) ───────────────────────────
@app.get("/authorize")
def authorize(
    request: Request,
    client_id: str,
    redirect_uri: str,
    response_type: str,
    scope: str = "openid",
    state: str = "",
    nonce: str = "",
    code_challenge: str = "",
    code_challenge_method: str = ""
):
    """标准的 /authorize 端点，如果脚本或浏览器不慎跳转进来，也给出一个默认的简易登录表单"""
    html_content = f"""
    <html>
      <head><title>Mock SSO Authorization</title></head>
      <body style="font-family: sans-serif; padding: 40px; text-align: center;">
        <h2>Mock SSO 登录授权</h2>
        <p>你已跳转至 Mock SSO。请输入想使用的邮箱前缀以完成模拟登录：</p>
        <form action="/authorize/submit" method="post" style="margin-top: 20px;">
          <input type="hidden" name="client_id" value="{client_id}"/>
          <input type="hidden" name="redirect_uri" value="{redirect_uri}"/>
          <input type="hidden" name="state" value="{state}"/>
          <input type="hidden" name="nonce" value="{nonce}"/>
          <input type="hidden" name="code_challenge" value="{code_challenge}"/>
          <input type="text" name="account" placeholder="例如 seed1" required style="padding: 8px; font-size: 16px;"/>
          <button type="submit" style="padding: 8px 16px; font-size: 16px; margin-left: 10px; cursor: pointer;">授权并登录</button>
        </form>
      </body>
    </html>
    """
    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=html_content)

@app.post("/authorize/submit")
def authorize_submit(
    account: str = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    state: str = Form(...),
    nonce: str = Form(""),
    code_challenge: str = Form("")
):
    """处理手动表单提交的授权，转至 generate_redirect_response 最终重定向"""
    res = generate_redirect_response({
        "account": account,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge
    }, "browser_auth")
    return RedirectResponse(url=res["redirect_uri"], status_code=303)

# ── 标准 OIDC Token 交换端点 ──────────────────────────────────────────
@app.post("/token")
def token_endpoint(
    request: Request,
    grant_type: str = Form(...),
    code: str = Form(...),
    redirect_uri: str = Form(None),
    code_verifier: str = Form(None),
    client_id: str = Form(None)
):
    """当 OpenAI 收到 code 后，在后台用 code 换取 id_token 与 access_token"""
    if grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail="Unsupported grant_type")
    
    # 1. 检验授权码有效性
    auth_data = auth_codes.pop(code, None)
    if not auth_data:
        logger.warning(f"无效或已过期的 Authorization Code 尝试交换 Token: {code}")
        raise HTTPException(status_code=400, detail="Invalid grant: authorization code not found or expired")
    
    # 性能优化：清理过期的授权码以释放内存
    now = time.time()
    expired_keys = [k for k, v in auth_codes.items() if now - v["timestamp"] > 300]
    for k in expired_keys:
        auth_codes.pop(k, None)

    account = auth_data["account"]
    nonce = auth_data["nonce"]
    target_client_id = client_id or auth_data["client_id"] or "app_EMoamEEZ73f0CkXaXp7hrann"
    
    # 2. 构造 JWT (ID Token)
    email_address = f"{account}@{args.domain}"
    base_url = args.issuer_url or str(request.base_url).rstrip("/")
    
    payload = {
        "iss": base_url,
        "sub": f"user_{account}",
        "aud": target_client_id,
        "exp": int(now) + 3600,
        "iat": int(now),
        "email": email_address,
        "email_verified": True,
        "name": account.capitalize()
    }
    
    if nonce:
        payload["nonce"] = nonce
        
    # 3. 使用 RSA 私钥对 JWT 签名 (RS256)
    headers = {"kid": KID}
    id_token = jwt.encode(
        payload, 
        _cached_private_key, 
        algorithm="RS256", 
        headers=headers
    )
    
    logger.info(f"成功为 Code {code} (帐号: {email_address}) 兑换 ID Token")
    
    return {
        "access_token": f"mock_access_token_{uuid.uuid4().hex}",
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "openid email profile"
    }

# ── 启动前置钩子 ──────────────────────────────────────────────────────
@app.on_event("startup")
def startup_event():
    """服务启动时生成/加载密钥"""
    init_keys()
    logger.info("=" * 60)
    logger.info(f"Mock OIDC SSO 服务器已成功启动！")
    logger.info(f"监听配置: http://{args.host}:{args.port}")
    logger.info(f"默认生成的邮箱后缀: @{args.domain}")
    logger.info(f"管理接口 Token (Bearer): {args.admin_token}")
    logger.info("=" * 60)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port)
