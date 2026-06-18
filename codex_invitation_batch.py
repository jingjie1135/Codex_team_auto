#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Codex 批量并行邀请调度器
========================
扫描一个目录下所有母号 auth.json，先准备所有母号的邀请邮箱，再统一发起邀请请求。

用法：
  python codex_invitation_batch.py --auth-dir ./accounts --domain dfhdg.store --per-account 5

  # 并发数控制
  python codex_invitation_batch.py --auth-dir ./accounts --concurrency 3

  # dry-run
  python codex_invitation_batch.py --auth-dir ./accounts --dry-run
"""

from __future__ import annotations

import sys
import json
import time
import argparse
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from codex_invitation_types import InviteResult, PreparedInviteResult, public_result

# 导入邀请脚本的核心函数
from codex_invitation_helper import (
    load_auth_tokens, build_session, get_headers, check_eligibility,
    random_email, INVITE_URL, REFERRAL_KEY
)


def log(msg: str, symbol: str = "*") -> None:
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] [{symbol}] {msg}", flush=True)


def is_auth_json_file(path: Path) -> bool:
    """只接收包含 access_token 或 refresh_token 的账号凭证文件。"""
    if "metadata" in path.name or "system_bak" in path.name:
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return False
    tokens = data.get("tokens", {})
    return isinstance(tokens, dict) and bool(tokens.get("access_token") or tokens.get("refresh_token"))


def prepare_account(
    auth_path: Path,
    domain: str,
    per_account: int,
    proxy: str | None = None,
    dry_run: bool = False,
    save_back: bool = False,
) -> PreparedInviteResult:
    """读取母号凭证并生成待发送邀请清单。"""
    result: PreparedInviteResult = {
        "auth_file": str(auth_path),
        "success": False,
        "emails": [],
        "invites": [],
        "sent_count": 0,
        "partial": False,
        "error": "",
        "access_token": "",
        "account_id": "",
    }

    try:
        access_token, account_id = load_auth_tokens(auth_path, proxy, save_back)
    except SystemExit:
        result["error"] = "凭证加载失败"
        return result

    _, session = build_session(proxy)
    try:
        remaining = check_eligibility(session, access_token, account_id)
    finally:
        session.close()

    if remaining is not None:
        if remaining <= 0:
            result["error"] = f"额度已用完 (剩余: {remaining})"
            return result
        count = min(per_account, remaining)
    else:
        count = per_account

    result["access_token"] = access_token
    result["account_id"] = account_id
    emails = [random_email(domain) for _ in range(count)]
    result["emails"] = emails
    result["success"] = True
    if dry_run:
        result["error"] = "dry-run"
        result["sent_count"] = len(emails)
    return result


def send_account_invites(
    prepared: PreparedInviteResult,
    proxy: str | None = None,
    barrier: threading.Barrier | None = None,
) -> InviteResult:
    """在统一起点发送单个母号的邀请请求。"""
    if barrier is not None:
        print(f"[{Path(prepared['auth_file']).name}] 准备就绪，等待其他母号共同发送...", flush=True)
        barrier.wait(timeout=30)

    result: InviteResult = public_result(prepared)
    access_token = prepared["access_token"]
    account_id = prepared["account_id"]

    session = None
    try:
        _, session = build_session(proxy)
        resp = session.post(
            INVITE_URL,
            headers=get_headers(access_token, account_id, is_json=True),
            json={"referral_key": REFERRAL_KEY, "emails": prepared["emails"]},
            timeout=30,
            verify=False,
        )
        if resp.status_code != 200:
            result["error"] = f"HTTP {resp.status_code}: {resp.text[:200]}"
            result["success"] = False
            return result

        try:
            data = resp.json()
        except ValueError as e:
            result["error"] = f"HTTP 200 但响应不是 JSON: {e}"
            result["success"] = False
            return result

        invites = data.get("invites", [])
        if not isinstance(invites, list):
            result["error"] = f"HTTP 200 但响应缺少 invites 列表: {str(data)[:200]}"
            result["success"] = False
            return result

        result["invites"] = invites
        result["sent_count"] = len(invites)
        result["partial"] = len(invites) != len(prepared["emails"])
        result["success"] = bool(invites)
        if not invites:
            result["error"] = f"HTTP 200 但 invites 为空，请求邮箱数 {len(prepared['emails'])}"
        return result
    except requests.RequestException as e:
        result["error"] = str(e)
        result["success"] = False
        return result
    finally:
        if session is not None:
            session.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Codex 批量并行邀请调度器")
    parser.add_argument("--auth-dir", required=True, help="母号凭证目录（每个 .json 文件是一个母号）")
    parser.add_argument("--domain", default="dfhdg.store", help="随机邮箱域名 [默认: dfhdg.store]")
    parser.add_argument("--per-account", type=int, default=5, help="每个母号邀请邮箱数 [默认: 5]")
    parser.add_argument("--concurrency", type=int, default=5, help="并发母号数 [默认: 5]")
    parser.add_argument("--proxy", default="http://127.0.0.1:7890", help="HTTP 代理 URL [默認: http://127.0.0.1:7890]")
    parser.add_argument("--out", help="结果输出 JSON 文件路径")
    parser.add_argument("--dry-run", action="store_true", help="只预检，不实际发送")
    parser.add_argument("--save-back", action="store_true", help="刷新 token 或补齐 account_id 后写回原文件")
    args = parser.parse_args()

    if args.per_account <= 0:
        print(f"[!] --per-account 必须大于 0，当前: {args.per_account}")
        return 1
    if args.concurrency <= 0:
        print(f"[!] --concurrency 必须大于 0，当前: {args.concurrency}")
        return 1

    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except:
        pass

    auth_dir = Path(args.auth_dir)
    if not auth_dir.is_dir():
        print(f"[!] 目录不存在: {auth_dir}")
        return 1

    all_json_files = sorted(auth_dir.glob("*.json"))
    auth_files = [fp for fp in all_json_files if is_auth_json_file(fp)]
    if not auth_files:
        print(f"[!] 目录下无有效账号 JSON 文件: {auth_dir}")
        return 1

    skipped = len(all_json_files) - len(auth_files)
    if skipped:
        log(f"已跳过 {skipped} 个非账号 JSON 文件")
    log(f"扫描到 {len(auth_files)} 个母号，每个邀请 {args.per_account} 个邮箱，并发数 {args.concurrency}")
    if args.dry_run:
        log("dry-run 模式，不会实际发送邀请")

    prepare_results: list[PreparedInviteResult] = []
    prepare_failures: list[InviteResult] = []

    max_workers = min(args.concurrency, len(auth_files))
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(prepare_account, fp, args.domain, args.per_account, args.proxy, args.dry_run, args.save_back): fp
            for fp in auth_files
        }
        for future in as_completed(futures):
            fp = futures[future]
            try:
                prepared = future.result()
            except Exception as e:
                failure: InviteResult = {"auth_file": str(fp), "success": False, "emails": [], "invites": [], "sent_count": 0, "partial": False, "error": str(e)}
                prepare_failures.append(failure)
            else:
                if prepared["success"]:
                    prepare_results.append(prepared)
                else:
                    prepare_failures.append(public_result(prepared))

    results: list[InviteResult] = []
    if args.dry_run:
        results = [public_result(r) for r in prepare_results] + prepare_failures
    elif prepare_results:
        log(f"所有可用母号已准备完成，统一发起 {len(prepare_results)} 个邀请请求", "→")
        barrier = threading.Barrier(len(prepare_results))
        with ThreadPoolExecutor(max_workers=len(prepare_results)) as pool:
            futures = {
                pool.submit(send_account_invites, r, args.proxy, barrier): r
                for r in prepare_results
            }
            for future in as_completed(futures):
                prepared = futures[future]
                try:
                    r = future.result()
                except Exception as e:
                    r = public_result(prepared)
                    r["success"] = False
                    r["error"] = str(e)
                results.append(r)
    else:
        results = []

    results = prepare_failures + results

    total_emails = 0
    success_accounts = 0
    for r in results:
        account_id = Path(r["auth_file"]).stem
        if r["success"]:
            success_accounts += 1
            sent_count = int(r.get("sent_count", len(r["emails"])))
            total_emails += sent_count
            if args.dry_run:
                label = "dry-run"
            elif r.get("partial"):
                label = f"{sent_count}/{len(r['emails'])} 条邀请，部分成功"
            else:
                label = f"{sent_count} 条邀请"
            log(f"✓ {account_id}: {len(r['emails'])} 个邮箱 ({label})", "✓")
        else:
            log(f"✗ {account_id}: {r.get('error', '未知错误')}", "!")

    print("\n" + "=" * 60)
    print(f"邀请汇总: {success_accounts}/{len(auth_files)} 个母号成功，共 {total_emails} 个邮箱")
    print("=" * 60)

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
        log(f"结果已写入: {out_path}")

    return 0 if success_accounts > 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] 用户取消。")
        sys.exit(130)
