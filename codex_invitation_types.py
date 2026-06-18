#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shared result shapes for Codex invitation batching."""

from __future__ import annotations

from typing import TypedDict


class InviteResult(TypedDict):
    auth_file: str
    success: bool
    emails: list[str]
    invites: list[dict[str, str]]
    sent_count: int
    partial: bool
    error: str


class PreparedInviteResult(InviteResult):
    access_token: str
    account_id: str


def public_result(result: InviteResult) -> InviteResult:
    return {
        "auth_file": result["auth_file"],
        "success": result["success"],
        "emails": result["emails"],
        "invites": result["invites"],
        "sent_count": result["sent_count"],
        "partial": result["partial"],
        "error": result["error"],
    }
