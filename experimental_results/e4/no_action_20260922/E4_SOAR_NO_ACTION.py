#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SOAR Orchestrator v6.3 cho môi trường luận văn/lab.

Các điểm chính:
- Không chứa Telegram token mặc định.
- Rule Engine quyết định; LLM chỉ giải thích.
- HIGH phản ứng trước, LLM hậu kiểm sau.
- Elasticsearch dùng PIT + checkpoint + durable queue SQLite.
- Worker cố định, không tạo thread vô hạn.
- HITL theo incident_id, chống duyệt lặp.
- Watchlist có cửa sổ 24 giờ và escalation.
- Firewall chống rule trùng, có timeout và TTL.
- P1/P2/P3 được đo thật, không hard-code.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import hmac
import hashlib
import json
import os
import queue
import re
import sqlite3
import subprocess
import threading
import time
import traceback
import unicodedata
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional

from dotenv import load_dotenv
import ollama
import requests
from elasticsearch import Elasticsearch
from fpdf import FPDF, XPos, YPos
from pdf_report_pro import build_incident_pdf
from static_rag import StaticRAG, compact_context, validate_and_score

UTC = dt.timezone.utc
BASE_DIR = Path(__file__).resolve().parent

# Đọc .env trước khi khởi tạo mọi đường dẫn/cấu hình.
load_dotenv(BASE_DIR / ".env", override=True)

DB_PATH = Path(
    os.getenv("DB_PATH", str(BASE_DIR / "alert_history.db"))
).resolve()
FONT_DIR = BASE_DIR / "fonts"


class Config:
    ES_URL = os.getenv("ES_URL", "http://localhost:9200")
    INDEX_NAME = os.getenv("INDEX_NAME", "datatest")
    ES_BATCH_SIZE = int(os.getenv("ES_BATCH_SIZE", "200"))
    SCAN_INTERVAL = float(os.getenv("SCAN_INTERVAL", "3"))
    ES_LOOKBACK_SECONDS = int(os.getenv("ES_LOOKBACK_SECONDS", "60"))
    STRICT_CATEGORY = os.getenv("STRICT_CATEGORY", "1").lower() in {"1", "true", "yes"}

    TG_TOKEN = os.getenv("TG_TOKEN", "").strip()
    TG_CHAT_ID = os.getenv("TG_CHAT_ID", "").strip()

    API_BIND = os.getenv("API_BIND", "127.0.0.1")
    API_PORT = int(os.getenv("API_PORT", "5050"))
    API_KEY = os.getenv("API_KEY", "").strip()
    LAB_API_NO_AUTH = os.getenv("LAB_API_NO_AUTH", "1").lower() in {"1", "true", "yes"}
    AUTO_CREATE_INDEX = os.getenv("AUTO_CREATE_INDEX", "1").lower() in {"1", "true", "yes"}

    WORKER_COUNT = int(os.getenv("WORKER_COUNT", "4"))
    EVENT_QUEUE_SIZE = int(os.getenv("EVENT_QUEUE_SIZE", "500"))
    REPORT_QUEUE_SIZE = int(os.getenv("REPORT_QUEUE_SIZE", "200"))
    MAX_RETRY = int(os.getenv("MAX_RETRY", "3"))

    OLLAMA_URL = os.getenv(
        "OLLAMA_URL", "http://127.0.0.1:11434"
    ).rstrip("/")
    LLM_MODEL = os.getenv("LLM_MODEL", "llama3.2:3b")
    LLM_CONCURRENCY = int(os.getenv("LLM_CONCURRENCY", "1"))
    LLM_TIMEOUT_SECONDS = int(os.getenv("LLM_TIMEOUT_SECONDS", "120"))
    LLM_RETRIES = int(os.getenv("LLM_RETRIES", "2"))
    LLM_RETRY_DELAY = float(os.getenv("LLM_RETRY_DELAY", "2"))
    LLM_NUM_CTX = int(os.getenv("LLM_NUM_CTX", "1024"))
    LLM_NUM_PREDICT = int(os.getenv("LLM_NUM_PREDICT", "384"))
    LLM_KEEP_ALIVE = int(os.getenv("LLM_KEEP_ALIVE", "0"))
    KB_PATH = Path(os.getenv("KB_PATH", str(BASE_DIR / "knowledge_base.json"))).resolve()
    RAG_ENABLED = os.getenv("RAG_ENABLED", "1").lower() in {"1", "true", "yes"}
    WHITELIST_FAIL_CLOSED = os.getenv("WHITELIST_FAIL_CLOSED", "1").lower() in {"1", "true", "yes"}
    WHITELIST_ALLOW_CIDR = os.getenv("WHITELIST_ALLOW_CIDR", "1").lower() in {"1", "true", "yes"}
    WHITELIST_MIN_PREFIX_V4 = int(os.getenv("WHITELIST_MIN_PREFIX_V4", "24"))
    WHITELIST_MIN_PREFIX_V6 = int(os.getenv("WHITELIST_MIN_PREFIX_V6", "64"))

    # Mặc định dry-run để tránh chặn nhầm máy thật.
    ENABLE_NETWORK_ENFORCEMENT = os.getenv(
        "ENABLE_NETWORK_ENFORCEMENT", "0"
    ).lower() in {"1", "true", "yes"}
    AUTO_BLOCK_HIGH = os.getenv("AUTO_BLOCK_HIGH", "1").lower() in {
        "1", "true", "yes"
    }
    ALLOW_PRIVATE_BLOCK = os.getenv("ALLOW_PRIVATE_BLOCK", "0").lower() in {
        "1", "true", "yes"
    }
    LAB_ALLOWED_NETWORKS = [
        ipaddress.ip_network(value.strip())
        for value in os.getenv(
            "LAB_ALLOWED_NETWORKS",
            "192.0.2.0/24,198.51.100.0/24,203.0.113.0/24"
        ).split(",")
        if value.strip()
    ]
    ALLOW_HOST_FIREWALL = os.getenv("ALLOW_HOST_FIREWALL", "0").lower() in {
        "1", "true", "yes"
    }
    WATCHLIST_ESCALATE_AUTO = os.getenv(
        "WATCHLIST_ESCALATE_AUTO", "0"
    ).lower() in {"1", "true", "yes"}

    FIREWALL_CONTAINERS = [
        x.strip()
        for x in os.getenv(
            "FIREWALL_CONTAINERS",
            "network-firewall-gateway,network-firewall_network_firewall_1",
        ).split(",")
        if x.strip()
    ]
    IPTABLES_PARENT_CHAIN = os.getenv("IPTABLES_PARENT_CHAIN", "INPUT")
    IPTABLES_TIMEOUT = int(os.getenv("IPTABLES_TIMEOUT", "8"))
    BLOCK_TTL_SECONDS = int(os.getenv("BLOCK_TTL_SECONDS", "3600"))
    RATE_LIMIT_TTL_SECONDS = int(os.getenv("RATE_LIMIT_TTL_SECONDS", "900"))

    WATCH_WINDOW_HOURS = int(os.getenv("WATCH_WINDOW_HOURS", "24"))
    WATCH_STRIKE_THRESHOLD = int(os.getenv("WATCH_STRIKE_THRESHOLD", "3"))

    # Hậu phân tích mức Cao. Đây là ngữ cảnh alert-level sau phản ứng,
    # không phải packet capture hoặc telemetry NIDS.
    POST_ANALYSIS_WAIT_SECONDS = float(
        os.getenv("POST_ANALYSIS_WAIT_SECONDS", "6")
    )
    POST_ANALYSIS_BEFORE_SECONDS = int(
        os.getenv("POST_ANALYSIS_BEFORE_SECONDS", "600")
    )
    POST_ANALYSIS_RELATED_LIMIT = int(
        os.getenv("POST_ANALYSIS_RELATED_LIMIT", "20")
    )
    # HIGH_POST có prompt dài hơn và bảy trường đầu ra.
    LLM_HIGH_NUM_CTX = int(
        os.getenv("LLM_HIGH_NUM_CTX", "2048")
    )
    LLM_HIGH_NUM_PREDICT = int(
        os.getenv("LLM_HIGH_NUM_PREDICT", "640")
    )


def ensure_es_index() -> None:
    """Tạo index LAB nếu chưa tồn tại để tránh lặp lỗi index_not_found."""
    try:
        if ES.indices.exists(index=Config.INDEX_NAME):
            return
        if not Config.AUTO_CREATE_INDEX:
            print(
                f"[!] Index {Config.INDEX_NAME} chưa tồn tại và AUTO_CREATE_INDEX=0."
            )
            return

        mapping = {
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "event": {
                        "properties": {
                            "id": {"type": "keyword"},
                            "kind": {"type": "keyword"},
                            "sequence": {"type": "long"},
                        }
                    },
                    "source": {
                        "properties": {
                            "ip": {"type": "ip"},
                        }
                    },
                    "labels": {
                        "properties": {
                            "attack_category": {"type": "keyword"},
                        }
                    },
                    "event_count": {"type": "long"},
                    "Attack category": {
                        "type": "text",
                        "fields": {"keyword": {"type": "keyword"}},
                    },
                    "Source IP": {"type": "ip"},
                    "Frequency": {"type": "long"},
                    "message": {"type": "text"},
                }
            }
        }
        ES.indices.create(index=Config.INDEX_NAME, body=mapping)
        print(f"[+] Đã tự tạo Elasticsearch index: {Config.INDEX_NAME}")
    except Exception as exc:
        print(f"[-] Không thể tạo index {Config.INDEX_NAME}: {exc}")




class ValidationError(ValueError):
    """Lỗi dữ liệu đầu vào: đưa thẳng vào DEAD, không retry vô ích."""


class WhitelistLookupError(RuntimeError):
    """Không xác minh được Whitelist; Response Engine phải fail-closed."""


@dataclass(frozen=True)
class NormalizedEvent:
    es_id: str
    timestamp: str
    src_ip: str
    category: str
    frequency: int
    raw: dict[str, Any]


@dataclass(frozen=True)
class RuleDecision:
    severity: str
    playbook: str
    action_text: str
    use_llm: bool
    high_priority: bool


RULE_ENGINE = {
    "DOS": {
        "high_min": 150,
        "medium_min": 50,
        "high_playbook": "PLAYBOOK_1",
        "medium_playbook": "PLAYBOOK_2",
    },
    "BRUTE_FORCE": {
        "high_min": 50,
        "medium_min": 10,
        "high_playbook": "PLAYBOOK_3",
        "medium_playbook": "PLAYBOOK_2",
    },
    "EXPLOIT": {"always_high": True, "high_playbook": "PLAYBOOK_1"},
    "SUSPICIOUS_SCAN": {"always_low": True, "low_playbook": "PLAYBOOK_4"},
}

# Static RAG được tải từ knowledge_base.json. Không dùng vector database.
CATEGORY_ALIASES = {
    "DOS": "DOS",
    "DDOS": "DOS",
    "DENIAL OF SERVICE": "DOS",
    "BRUTE FORCE": "BRUTE_FORCE",
    "BRUTEFORCE": "BRUTE_FORCE",
    "EXPLOIT": "EXPLOIT",
    "EXPLOITS": "EXPLOIT",
    "SUSPICIOUS SCAN": "SUSPICIOUS_SCAN",
    "SCAN": "SUSPICIOUS_SCAN",
}

try:
    STATIC_RAG = StaticRAG(Config.KB_PATH)
    print(
        f"[+] Static RAG: {Config.KB_PATH.name} | "
        f"version={STATIC_RAG.version} | method={STATIC_RAG.method}"
    )
except Exception as exc:
    raise RuntimeError(f"Không khởi tạo được Static RAG: {exc}") from exc



def utc_now() -> dt.datetime:
    return dt.datetime.now(UTC)


def utc_now_iso() -> str:
    return utc_now().isoformat(timespec="milliseconds").replace("+00:00", "Z")


def normalize_category(value: Any) -> str:
    text = str(value or "").strip().upper()
    if text == "NORMAL":
        return "NORMAL"
    text = re.sub(r"[_\-]+", " ", text)
    text = re.sub(r"\s+", " ", text)
    for alias, canonical in CATEGORY_ALIASES.items():
        if alias in text:
            return canonical
    return "UNKNOWN"


def retrieve_knowledge(category: str) -> dict[str, Any]:
    """Exact-match retrieval from the auditable static knowledge base."""
    return STATIC_RAG.retrieve(normalize_category(category)).as_dict()


def decide_rule(category: str, frequency: int) -> RuleDecision:
    category = normalize_category(category)
    rule = RULE_ENGINE.get(category)
    if not rule:
        return RuleDecision("THAP", "PLAYBOOK_4", "Ghi audit và rà soát thủ công.", False, False)
    if rule.get("always_high"):
        return RuleDecision("CAO", rule["high_playbook"], "Chặn IP khẩn cấp theo Rule Engine.", True, True)
    if rule.get("always_low"):
        return RuleDecision("THAP", rule["low_playbook"], "Ghi audit và đưa IP vào Watchlist.", True, False)
    if frequency >= int(rule["high_min"]):
        return RuleDecision("CAO", rule["high_playbook"], "Phản ứng khẩn cấp theo Rule Engine.", True, True)
    if frequency >= int(rule["medium_min"]):
        return RuleDecision("TRUNG BINH", rule["medium_playbook"], "Phân tích và chuyển Human-in-the-loop.", True, False)
    return RuleDecision("THAP", "PLAYBOOK_4", "Ghi audit và đưa IP vào Watchlist.", True, False)


# ---------------------------------------------------------------------
# DATABASE
# ---------------------------------------------------------------------

def db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def ensure_column(conn: sqlite3.Connection, table: str, name: str, column_type: str) -> None:
    columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    if name not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {column_type}")


def init_db() -> None:
    with db_connect() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute(
            """CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT, ip TEXT, category TEXT, severity TEXT,
                action TEXT, execution_status TEXT, confidence_score INTEGER,
                latency REAL, pdf_file TEXT, llm_reasoning TEXT,
                audit_trace TEXT, raw_data TEXT, es_id TEXT UNIQUE
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS policy (
                id INTEGER PRIMARY KEY, mode TEXT, threshold TEXT,
                duration TEXT, confidence_threshold INTEGER,
                emergency_stop INTEGER DEFAULT 0, dos_action TEXT,
                brute_action TEXT, llm_provider TEXT, llm_model TEXT
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE, description TEXT,
                target_type TEXT NOT NULL DEFAULT 'IP',
                created_at TEXT, created_by TEXT,
                updated_at TEXT, disabled_at TEXT, disabled_by TEXT,
                last_match_at TEXT, match_count INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'ACTIVE'
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS watchlist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE, category TEXT,
                strike_count INTEGER NOT NULL DEFAULT 1,
                first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                expires_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'ACTIVE'
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE, category TEXT, blocked_at TEXT,
                expires_at TEXT, status TEXT, rule_target TEXT, rule_kind TEXT
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS system_checkpoint (
                checkpoint_name TEXT PRIMARY KEY,
                checkpoint_value TEXT NOT NULL, updated_at TEXT NOT NULL
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS event_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                es_id TEXT UNIQUE NOT NULL, payload TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'NEW',
                retry_count INTEGER NOT NULL DEFAULT 0,
                last_error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS control_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL, actor TEXT NOT NULL,
                action TEXT NOT NULL, ip TEXT, details TEXT
            )"""
        )
        migrations = {
            "llm_recommendation": "TEXT", "policy_decision": "TEXT",
            "playbook": "TEXT", "approval_status": "TEXT",
            "approved_by": "TEXT", "approved_at": "TEXT",
            "execution_started_at": "TEXT", "execution_finished_at": "TEXT",
            "firewall_rule_id": "TEXT", "execution_error": "TEXT",
            "response_latency": "REAL", "report_latency": "REAL",
            "grounding_score": "INTEGER", "kb_id": "TEXT",
            "mitre_id": "TEXT", "retrieval_status": "TEXT",
            "llm_status": "TEXT", "llm_model_used": "TEXT",
            "post_review_status": "TEXT",
            "post_review_action": "TEXT",
            "post_review_by": "TEXT",
            "post_review_at": "TEXT",
        }
        for name, typ in migrations.items():
            ensure_column(conn, "alerts", name, typ)

        # Migration cho database cũ của luận văn. CREATE TABLE IF NOT EXISTS
        # không tự thêm cột vào bảng watchlist/blocked_ips đã tồn tại.
        watchlist_migrations = {
            "added_at": "TEXT",
            "first_seen": "TEXT",
            "last_seen": "TEXT",
            "expires_at": "TEXT",
            "status": "TEXT",
        }
        for name, typ in watchlist_migrations.items():
            ensure_column(conn, "watchlist", name, typ)

        whitelist_migrations = {
            "created_at": "TEXT",
            "created_by": "TEXT",
            "updated_at": "TEXT",
            "disabled_at": "TEXT",
            "disabled_by": "TEXT",
            "last_match_at": "TEXT",
            "match_count": "INTEGER DEFAULT 0",
            "target_type": "TEXT DEFAULT 'IP'",
            "status": "TEXT",
        }
        for name, typ in whitelist_migrations.items():
            ensure_column(conn, "whitelist", name, typ)

        blocked_migrations = {
            "expires_at": "TEXT",
            "rule_target": "TEXT",
            "rule_kind": "TEXT",
        }
        for name, typ in blocked_migrations.items():
            ensure_column(conn, "blocked_ips", name, typ)

        now = utc_now_iso()
        watch_expiry = (
            utc_now() + dt.timedelta(hours=Config.WATCH_WINDOW_HOURS)
        ).isoformat(timespec="seconds").replace("+00:00", "Z")
        conn.execute(
            """UPDATE whitelist SET
                 created_at=COALESCE(created_at, ?),
                 created_by=COALESCE(created_by, 'legacy-import'),
                 updated_at=COALESCE(updated_at, created_at, ?),
                 match_count=COALESCE(match_count, 0),
                 target_type=CASE
                    WHEN instr(ip, '/') > 0 THEN 'CIDR'
                    ELSE COALESCE(target_type, 'IP')
                 END,
                 status=COALESCE(status, 'ACTIVE')""",
            (now, now),
        )
        conn.execute(
            """UPDATE watchlist SET
                 first_seen=COALESCE(first_seen, added_at, ?),
                 last_seen=COALESCE(last_seen, added_at, ?),
                 expires_at=COALESCE(expires_at, ?),
                 status=COALESCE(status, 'ACTIVE')""",
            (now, now, watch_expiry),
        )
        conn.execute(
            """UPDATE blocked_ips SET
                 expires_at=COALESCE(expires_at, ?),
                 status=COALESCE(status, 'ACTIVE'),
                 rule_kind=COALESCE(rule_kind, 'BLOCK')""",
            ((utc_now() + dt.timedelta(seconds=Config.BLOCK_TTL_SECONDS))
             .isoformat(timespec="seconds").replace("+00:00", "Z"),),
        )

        conn.execute(
            """INSERT OR IGNORE INTO policy
               (id, mode, threshold, confidence_threshold, emergency_stop,
                llm_provider, llm_model)
               VALUES (1, 'Human Approval', 'TRUNG BINH+', 82, 0,
                       'Local Ollama', ?)""",
            (Config.LLM_MODEL,),
        )
        conn.execute(
            "UPDATE policy SET llm_provider='Local Ollama', llm_model=? WHERE id=1",
            (Config.LLM_MODEL,),
        )
        conn.execute(
            "UPDATE event_queue SET status='NEW', updated_at=? "
            "WHERE status IN ('ENQUEUED','PROCESSING')",
            (utc_now_iso(),),
        )


def get_checkpoint(name: str, default: str) -> str:
    with db_connect() as conn:
        row = conn.execute(
            "SELECT checkpoint_value FROM system_checkpoint WHERE checkpoint_name=?",
            (name,),
        ).fetchone()
        return str(row["checkpoint_value"]) if row else default


def set_checkpoint(name: str, value: str) -> None:
    with db_connect() as conn:
        conn.execute(
            """INSERT INTO system_checkpoint
               (checkpoint_name, checkpoint_value, updated_at)
               VALUES (?, ?, ?)
               ON CONFLICT(checkpoint_name) DO UPDATE SET
                 checkpoint_value=excluded.checkpoint_value,
                 updated_at=excluded.updated_at""",
            (name, value, utc_now_iso()),
        )


def get_policy() -> dict[str, Any]:
    with db_connect() as conn:
        row = conn.execute("SELECT * FROM policy WHERE id=1").fetchone()
        return dict(row) if row else {
            "mode": "Human Approval", "emergency_stop": 0,
            "llm_model": Config.LLM_MODEL,
        }


def normalize_whitelist_target(value: str) -> tuple[str, str]:
    """Chuẩn hóa target Whitelist thành IP hoặc CIDR có thể kiểm toán."""
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("IP/CIDR Whitelist không được để trống")

    if "/" in raw:
        if not Config.WHITELIST_ALLOW_CIDR:
            raise ValueError("CIDR Whitelist đang bị tắt bởi cấu hình")
        network = ipaddress.ip_network(raw, strict=False)
        if network.network_address.is_multicast or network.network_address.is_unspecified:
            raise ValueError(f"CIDR không an toàn cho Whitelist: {network}")
        minimum_prefix = (
            Config.WHITELIST_MIN_PREFIX_V4
            if network.version == 4
            else Config.WHITELIST_MIN_PREFIX_V6
        )
        if network.prefixlen < minimum_prefix:
            raise ValueError(
                f"CIDR {network} quá rộng; yêu cầu prefix >= {minimum_prefix}."
            )
        return str(network), "CIDR"

    ip = ipaddress.ip_address(raw)
    if ip.is_multicast or ip.is_unspecified:
        raise ValueError(f"IP không an toàn cho Whitelist: {ip}")
    return str(ip), "IP"


def whitelist_target_matches(ip_text: str, target_text: str) -> bool:
    """Kiểm tra IP nguồn có nằm trong target IP/CIDR hay không."""
    ip = ipaddress.ip_address(ip_text)
    target = ipaddress.ip_network(str(target_text), strict=False)
    return ip.version == target.version and ip in target


def find_whitelist_match_in_rows(
    ip: str,
    rows: list[sqlite3.Row] | tuple[sqlite3.Row, ...],
) -> Optional[dict[str, Any]]:
    for row in rows:
        try:
            if whitelist_target_matches(ip, str(row["ip"])):
                result = dict(row)
                result["matched_target"] = str(row["ip"])
                result["target_type"] = (
                    str(row["target_type"])
                    if "target_type" in row.keys() and row["target_type"]
                    else ("CIDR" if "/" in str(row["ip"]) else "IP")
                )
                return result
        except ValueError:
            # Bỏ qua bản ghi legacy không hợp lệ, nhưng không cho phép nó
            # làm sập toàn bộ Response Engine.
            continue
    return None


def get_whitelist_entry(ip: str, *, touch: bool = True) -> Optional[dict[str, Any]]:
    """Trả về bản ghi Whitelist ACTIVE khớp IP hoặc CIDR.

    Mọi lỗi truy vấn được nâng thành WhitelistLookupError để tầng phản ứng
    có thể fail-closed thay vì chặn khi chưa xác minh được safe exclusion.
    """
    try:
        normalized_ip = str(ipaddress.ip_address(ip))
        with db_connect() as conn:
            rows = conn.execute(
                """SELECT * FROM whitelist
                   WHERE COALESCE(status, 'ACTIVE')='ACTIVE'
                   ORDER BY CASE WHEN target_type='IP' THEN 0 ELSE 1 END, id"""
            ).fetchall()
            match = find_whitelist_match_in_rows(normalized_ip, rows)
            if match and touch:
                conn.execute(
                    """UPDATE whitelist SET
                         match_count=COALESCE(match_count, 0)+1,
                         last_match_at=?, updated_at=?
                       WHERE id=?""",
                    (utc_now_iso(), utc_now_iso(), int(match["id"])),
                )
        return match
    except (sqlite3.Error, OSError, ValueError) as exc:
        raise WhitelistLookupError(
            f"Không xác minh được Whitelist cho {ip}: {exc}"
        ) from exc


def is_whitelisted(ip: str) -> bool:
    return get_whitelist_entry(ip) is not None


def audit_control_event(

    action: str,
    ip: str,
    actor: str,
    details: str,
) -> None:
    with db_connect() as conn:
        conn.execute(
            """INSERT INTO control_audit
               (timestamp, actor, action, ip, details)
               VALUES (?, ?, ?, ?, ?)""",
            (utc_now_iso(), actor, action, ip, details[:1000]),
        )


# ---------------------------------------------------------------------
# NORMALIZE INPUT
# ---------------------------------------------------------------------

def nested_get(data: dict[str, Any], path: str, default: Any = None) -> Any:
    cur: Any = data
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def parse_timestamp(value: Any) -> str:
    if not value:
        return utc_now_iso()
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except ValueError:
        return utc_now_iso()


def normalize_event(es_id: str, source: dict[str, Any]) -> NormalizedEvent:
    src_ip = nested_get(source, "source.ip") or source.get("Source IP") or source.get("Source ip") or source.get("src_ip")
    category = nested_get(source, "labels.attack_category") or source.get("Attack category") or source.get("Attack cat") or nested_get(source, "event.category") or "UNKNOWN"
    frequency_raw = source.get("event_count") or source.get("Frequency") or source.get("count") or 1
    try:
        parsed_ip = str(ipaddress.ip_address(str(src_ip)))
    except ValueError as exc:
        raise ValueError(f"IP không hợp lệ: {src_ip!r}") from exc
    try:
        frequency = int(frequency_raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Frequency không hợp lệ: {frequency_raw!r}") from exc
    if frequency < 0:
        raise ValueError("Frequency không được âm")
    canonical_category = normalize_category(category)
    if canonical_category == "UNKNOWN" and Config.STRICT_CATEGORY:
        raise ValidationError(
            f"Category không được hỗ trợ: {category!r}. "
            "Hãy sửa Simulator hoặc bổ sung CATEGORY_ALIASES."
        )
    return NormalizedEvent(
        es_id=es_id,
        timestamp=parse_timestamp(source.get("@timestamp")),
        src_ip=parsed_ip,
        category=canonical_category,
        frequency=frequency,
        raw=source,
    )


def calculate_p1(event_timestamp: str) -> Optional[float]:
    try:
        event_time = dt.datetime.fromisoformat(event_timestamp.replace("Z", "+00:00"))
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=UTC)
        return round(max((utc_now() - event_time.astimezone(UTC)).total_seconds(), 0.0), 3)
    except ValueError:
        return None


# ---------------------------------------------------------------------
# LLM: HIGH POST-ANALYSIS / MEDIUM PRE-HITL / LOW MONITOR ANALYSIS
# ---------------------------------------------------------------------

LLM_SEMAPHORE = threading.BoundedSemaphore(max(1, Config.LLM_CONCURRENCY))

# Telemetry tùy chọn cho kiểm thử LLM contention.
# Không đặt LLM_CONTENTION_TRACE_PATH thì không ghi file.
LLM_CONTENTION_LOCK = threading.Lock()
LLM_ACTIVE_CALLS = 0
LLM_MAX_ACTIVE_CALLS = 0


def _llm_trace_record(record: dict[str, Any]) -> None:
    trace_path = os.getenv(
        "LLM_CONTENTION_TRACE_PATH",
        "",
    ).strip()

    if not trace_path:
        return

    try:
        directory = os.path.dirname(trace_path)
        if directory:
            os.makedirs(directory, exist_ok=True)

        with open(
            trace_path,
            "a",
            encoding="utf-8",
        ) as handle:
            handle.write(
                json.dumps(
                    record,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            )
    except Exception as exc:
        print(
            "[LLM TRACE] Không ghi được telemetry: "
            f"{type(exc).__name__}: {exc}"
        )


def _llm_acquire_slot(
    *,
    analysis_mode: str,
    attempt: int,
    model: str,
) -> tuple[float, int]:
    global LLM_ACTIVE_CALLS
    global LLM_MAX_ACTIVE_CALLS

    wait_started = time.perf_counter()
    LLM_SEMAPHORE.acquire()
    wait_seconds = round(
        time.perf_counter() - wait_started,
        6,
    )

    with LLM_CONTENTION_LOCK:
        LLM_ACTIVE_CALLS += 1
        LLM_MAX_ACTIVE_CALLS = max(
            LLM_MAX_ACTIVE_CALLS,
            LLM_ACTIVE_CALLS,
        )

        active_snapshot = LLM_ACTIVE_CALLS

        _llm_trace_record(
            {
                "timestamp_epoch": time.time(),
                "event": "ACQUIRED",
                "analysis_mode": analysis_mode,
                "attempt": attempt,
                "model": model,
                "thread": threading.current_thread().name,
                "wait_seconds": wait_seconds,
                "active_calls": active_snapshot,
                "max_active_calls": LLM_MAX_ACTIVE_CALLS,
                "configured_concurrency": max(
                    1,
                    Config.LLM_CONCURRENCY,
                ),
            }
        )

    return wait_seconds, active_snapshot


def _llm_release_slot(
    *,
    analysis_mode: str,
    attempt: int,
    model: str,
) -> None:
    global LLM_ACTIVE_CALLS

    with LLM_CONTENTION_LOCK:
        LLM_ACTIVE_CALLS = max(
            0,
            LLM_ACTIVE_CALLS - 1,
        )

        _llm_trace_record(
            {
                "timestamp_epoch": time.time(),
                "event": "RELEASED",
                "analysis_mode": analysis_mode,
                "attempt": attempt,
                "model": model,
                "thread": threading.current_thread().name,
                "active_calls": LLM_ACTIVE_CALLS,
                "max_active_calls": LLM_MAX_ACTIVE_CALLS,
                "configured_concurrency": max(
                    1,
                    Config.LLM_CONCURRENCY,
                ),
            }
        )

    LLM_SEMAPHORE.release()

HIGH_POST_PROMPT = """
Bạn là SOC Tier-2 đóng vai trò CỐ VẤN SAU KHI CHẶN.

Rule Engine đã chặn IP trước để containment khẩn cấp. Bạn không được thay đổi
severity, Playbook, Firewall, TTL hoặc tự thực thi rollback. Nhiệm vụ của bạn
là tham mưu cho Admin xem quyết định chặn có đủ căn cứ hay không, giải thích
ngữ cảnh dễ hiểu và đề xuất một phương án hậu kiểm.

STATIC_RAG cung cấp ngữ nghĩa chuẩn, MITRE ATT&CK, SOP, nguy cơ và điều kiện
rollback. POST_RESPONSE_CONTEXT chứa bằng chứng cảnh báo trước/sau phản ứng.

Chỉ trả năm trường:

1. containment_assessment:
   - SUPPORTED_BY_EVIDENCE: chặn có căn cứ từ cảnh báo và ngữ cảnh.
   - INCONCLUSIVE: chưa đủ bằng chứng để khẳng định chắc chắn.
   - POSSIBLE_FALSE_POSITIVE: có dấu hiệu nguồn/lưu lượng hợp lệ.
   Đây là đánh giá tư vấn, không phải quyền quyết định cuối.

2. context_explanation:
   Giải thích bằng tiếng Việt cho Admin: IP nguồn, dịch vụ đích, Rule/MITRE,
   diễn biến trước/sau và ý nghĩa an toàn thông tin.

3. recommended_admin_action:
   - KEEP_BLOCK_UNTIL_TTL
   - KEEP_BLOCK_AND_WATCHLIST
   - ROLLBACK_UNBLOCK

4. recommendation_reason:
   Nêu rõ tại sao chọn phương án trên dựa trên bằng chứng và Static RAG.

5. evidence_gaps:
   Nêu dữ liệu còn thiếu như CPU, tỷ lệ lỗi, access log, application log,
   xác minh chủ sở hữu IP hoặc bằng chứng lưu lượng hợp lệ.

Quy tắc:
- LLM chỉ tham mưu; Admin là người quyết định cuối.
- Viết hoàn toàn bằng tiếng Việt, trừ các enum bắt buộc.
- Không tự tạo CVE, log, tài khoản, downtime hoặc kết luận đã khắc phục.
- Không khuyên ROLLBACK_UNBLOCK nếu không có bằng chứng nguồn hợp lệ hoặc
  dương tính giả.
- Mỗi chuỗi tối đa 80 từ.
- Không Markdown, không khóa thừa.

EVENT={event_json}
STATIC_RAG={rag_context}
POST_RESPONSE_CONTEXT={post_context_json}

Trả đúng JSON:
{{"containment_assessment":"SUPPORTED_BY_EVIDENCE",
"context_explanation":"...",
"recommended_admin_action":"KEEP_BLOCK_AND_WATCHLIST",
"recommendation_reason":"...",
"evidence_gaps":"..."}}
""".strip()


HIGH_POST_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "containment_assessment": {
            "type": "string",
            "enum": [
                "SUPPORTED_BY_EVIDENCE",
                "INCONCLUSIVE",
                "POSSIBLE_FALSE_POSITIVE",
            ],
        },
        "context_explanation": {"type": "string"},
        "recommended_admin_action": {
            "type": "string",
            "enum": [
                "KEEP_BLOCK_UNTIL_TTL",
                "KEEP_BLOCK_AND_WATCHLIST",
                "ROLLBACK_UNBLOCK",
            ],
        },
        "recommendation_reason": {"type": "string"},
        "evidence_gaps": {"type": "string"},
    },
    "required": [
        "containment_assessment",
        "context_explanation",
        "recommended_admin_action",
        "recommendation_reason",
        "evidence_gaps",
    ],
    "additionalProperties": False,
}



def compact_post_context_for_llm(
    context: Optional[dict[str, Any]],
) -> dict[str, Any]:
    """Facts tối thiểu cho LLM tham mưu sau khi chặn."""
    source = context or {}
    before = source.get("before") or {}
    after = source.get("after") or {}
    before_freqs = list(
        source.get("before_frequencies")
        or before.get("frequencies")
        or []
    )
    after_freqs = list(
        source.get("after_frequencies")
        or after.get("frequencies")
        or []
    )
    return {
        "affected_service": source.get("affected_service"),
        "before_event_count": before.get("event_count", 0),
        "before_frequency_sum": before.get("frequency_sum", 0),
        "before_frequencies": before_freqs,
        "after_event_count": after.get("event_count", 0),
        "after_frequency_sum": after.get("frequency_sum", 0),
        "after_frequencies": after_freqs,
        "comparison_status": source.get("comparison_status"),
        "current_alert_count": source.get("current_alert_count", 1),
        "related_event_count": source.get("related_event_count", 0),
        "context_query_scope": source.get("context_query_scope"),
        "rule_ttl_seconds": source.get("rule_ttl_seconds"),
        "rollback_conditions": list(
            source.get("rollback_conditions") or []
        )[:3],
        "service_telemetry_available": bool(
            source.get("service_telemetry_available")
        ),
        "evidence_scope": source.get("evidence_scope"),
        "query_error": source.get("query_error"),
        "admin_allowed_actions": [
            "KEEP_BLOCK_UNTIL_TTL",
            "KEEP_BLOCK_AND_WATCHLIST",
            "ROLLBACK_UNBLOCK",
        ],
    }



MEDIUM_PRE_PROMPT = """
Bạn là SOC Tier-2 hỗ trợ Admin. Rule Engine mới phân loại TRUNG BÌNH;
Playbook chưa được thực thi. Chỉ dùng EVENT và STATIC_RAG.
Không tự tạo CVE, tài sản, tài khoản, log hoặc bằng chứng mới.
Phải dùng đúng IP nguồn, category, MITRE ID và Playbook ứng viên.
Mỗi trường phải là một câu cụ thể, tối đa 35 từ.
Cấm trả dấu chấm lửng, chuỗi rỗng, N/A, null hoặc câu mẫu chung chung.
Cấm kết luận "đã ổn định", "đã xác nhận hợp lệ", "không còn dấu hiệu"
nếu EVENT không có bằng chứng hậu kiểm. next_steps phải bắt đầu bằng hành động
điều tra như Kiểm tra, Đối chiếu, Truy vấn, Xác minh hoặc Rà soát.

EVENT={event_json}
STATIC_RAG={rag_context}

Trả đúng một JSON object, không Markdown, với đúng các khóa:
nhan_dinh, nguy_co, co_so_suy_luan, khuyen_nghi,
de_xuat_admin, ly_do_de_xuat, next_steps.
de_xuat_admin chỉ được là APPROVE_RATE_LIMIT, APPROVE_BLOCK,
MONITOR hoặc REJECT.
""".strip()

LOW_MONITOR_PROMPT = """
Bạn là SOC Tier-2 hỗ trợ giám sát. Rule Engine chọn Watchlist, chưa chặn.
Chỉ dùng EVENT và STATIC_RAG. Không tự tạo dữ kiện mới.
Phải dùng đúng IP nguồn, category và MITRE ID từ ngữ cảnh.
Mỗi trường phải là một câu cụ thể, tối đa 35 từ.
Cấm trả dấu chấm lửng, chuỗi rỗng, N/A, null hoặc câu mẫu chung chung.
Cấm kết luận "đã ổn định", "đã xác nhận hợp lệ", "không còn dấu hiệu"
nếu EVENT không có bằng chứng hậu kiểm. next_steps phải bắt đầu bằng hành động
điều tra như Kiểm tra, Đối chiếu, Truy vấn, Xác minh hoặc Rà soát.

EVENT={event_json}
STATIC_RAG={rag_context}

Trả đúng một JSON object, không Markdown, với đúng các khóa:
nhan_dinh, nguy_co, co_so_suy_luan, khuyen_nghi,
de_xuat_admin, next_steps.
de_xuat_admin phải là MONITOR.
""".strip()

def _event_message(event: NormalizedEvent) -> str:
    return str(
        event.raw.get("message")
        or event.raw.get("Message")
        or "Không có message bổ sung."
    )


def _event_destination(event: NormalizedEvent) -> str:
    dst_ip = nested_get(event.raw, "destination.ip")
    dst_port = nested_get(event.raw, "destination.port")
    protocol = nested_get(event.raw, "network.transport")
    parts = []
    if dst_ip:
        parts.append(str(dst_ip))
    if dst_port:
        parts.append(f"port {dst_port}")
    if protocol:
        parts.append(str(protocol).upper())
    return " / ".join(parts) if parts else "Không có dữ liệu đích."




def _event_time(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def collect_post_response_context(
    event: NormalizedEvent,
    decision: RuleDecision,
    kb_result: Any,
) -> dict[str, Any]:
    """Thu thập bằng chứng alert-level để LLM hậu phân tích.

    Hàm chỉ truy vấn các cảnh báo đã có trong Elasticsearch. Nó không tuyên bố
    đã thu thập packet, CPU, memory, application health hoặc NIDS telemetry.
    """
    alert_time = _event_time(event.timestamp)
    now = utc_now()
    before_start = alert_time - dt.timedelta(
        seconds=Config.POST_ANALYSIS_BEFORE_SECONDS
    )

    query = {
        "bool": {
            "filter": [
                {
                    "range": {
                        "@timestamp": {
                            "gte": before_start.isoformat(),
                            "lte": now.isoformat(),
                        }
                    }
                }
            ],
            "should": [
                {"term": {"source.ip": event.src_ip}},
                {"term": {"Source IP": event.src_ip}},
            ],
            "minimum_should_match": 1,
        }
    }

    hits: list[dict[str, Any]] = []
    query_error: Optional[str] = None
    try:
        response = ES.search(
            index=Config.INDEX_NAME,
            query=query,
            sort=[{"@timestamp": {"order": "asc"}}],
            size=max(1, Config.POST_ANALYSIS_RELATED_LIMIT),
        )
        hits = list((response.get("hits") or {}).get("hits") or [])
    except Exception as exc:
        query_error = f"{type(exc).__name__}: {exc}"

    before_docs: list[dict[str, Any]] = []
    after_docs: list[dict[str, Any]] = []
    related: list[dict[str, Any]] = []
    current_alert_count = 0
    scenario_id = str(
        nested_get(event.raw, "labels.scenario_id") or ""
    ).strip()

    for hit in hits:
        source = dict(hit.get("_source") or {})

        # Khi Simulator gắn scenario_id, chỉ lấy bằng chứng cùng kịch bản.
        hit_scenario_id = str(
            nested_get(source, "labels.scenario_id") or ""
        ).strip()
        if scenario_id and hit_scenario_id != scenario_id:
            continue
        timestamp = str(source.get("@timestamp") or "")
        try:
            seen_at = _event_time(timestamp)
        except Exception:
            continue

        frequency_raw = (
            source.get("event_count")
            or source.get("Frequency")
            or source.get("frequency")
            or 0
        )
        try:
            frequency = int(frequency_raw)
        except (TypeError, ValueError):
            frequency = 0

        category = normalize_category(
            nested_get(source, "labels.attack_category")
            or source.get("Attack category")
            or nested_get(source, "event.category")
            or "UNKNOWN"
        )
        item = {
            "es_id": str(
                nested_get(source, "event.id")
                or hit.get("_id")
                or "N/A"
            ),
            "timestamp": timestamp,
            "category": category,
            "frequency": frequency,
            "scenario_stage": str(
                nested_get(source, "labels.scenario_stage") or "N/A"
            ),
            "destination": " / ".join(
                [
                    str(value)
                    for value in (
                        nested_get(source, "destination.ip"),
                        (
                            f"port {nested_get(source, 'destination.port')}"
                            if nested_get(source, "destination.port")
                            else None
                        ),
                        nested_get(source, "network.protocol")
                        or nested_get(source, "network.transport"),
                    )
                    if value
                ]
            )
            or "N/A",
        }
        # Alert đang xử lý không phải là "sự kiện liên quan bổ sung".
        item_id = str(item["es_id"])
        if item_id == event.es_id:
            current_alert_count += 1
            continue

        related.append(item)
        if seen_at < alert_time:
            before_docs.append(item)
        else:
            after_docs.append(item)

    def summarize(items: list[dict[str, Any]]) -> dict[str, Any]:
        frequencies = [int(item.get("frequency") or 0) for item in items]
        return {
            "event_count": len(items),
            "frequency_sum": sum(frequencies),
            "frequencies": frequencies,
            "stages": [
                str(item.get("scenario_stage") or "N/A")
                for item in items
            ],
            "categories": sorted(
                {
                    str(item.get("category") or "UNKNOWN")
                    for item in items
                }
            ),
        }

    before = summarize(before_docs)
    after = summarize(after_docs)
    comparison_status = (
        "SUFFICIENT"
        if before["event_count"] > 0 and after["event_count"] > 0
        else "LIMITED_ALERT_LEVEL_EVIDENCE"
    )

    destination = _event_destination(event)
    rollback_conditions = list(
        getattr(kb_result, "rollback_conditions", ()) or ()
    )
    ttl_seconds = (
        Config.BLOCK_TTL_SECONDS
        if decision.playbook in {"PLAYBOOK_1", "PLAYBOOK_3"}
        else Config.RATE_LIMIT_TTL_SECONDS
    )

    return {
        "evidence_scope": (
            "Elasticsearch alert-level evidence; không phải packet/flow hoặc "
            "telemetry hiệu năng dịch vụ."
        ),
        "affected_service": destination,
        "alert_timestamp": event.timestamp,
        "observation_end": now.isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        ),
        "observation_after_seconds": round(
            max((now - alert_time).total_seconds(), 0.0),
            3,
        ),
        "before_window_seconds": Config.POST_ANALYSIS_BEFORE_SECONDS,
        "before": before,
        "after": after,
        "before_frequencies": before.get("frequencies", []),
        "after_frequencies": after.get("frequencies", []),
        "comparison_status": comparison_status,
        "current_alert_count": current_alert_count,
        "related_event_count": len(related),
        "related_events": related[:10],
        "context_query_scope": (
            f"scenario_id={scenario_id}"
            if scenario_id
            else f"source.ip={event.src_ip}"
        ),
        "rule_ttl_seconds": ttl_seconds,
        "rollback_conditions": rollback_conditions,
        "service_telemetry_available": False,
        "query_error": query_error,
    }


def _event_evidence(event: NormalizedEvent, decision: RuleDecision) -> dict[str, Any]:
    return {
        "source_ip": event.src_ip,
        "category": event.category,
        "frequency": event.frequency,
        "destination": _event_destination(event),
        "destination_ip": nested_get(event.raw, "destination.ip"),
        "destination_port": nested_get(event.raw, "destination.port"),
        "transport": nested_get(event.raw, "network.transport"),
        "protocol": nested_get(event.raw, "network.protocol"),
        "rule_id": nested_get(event.raw, "rule.id"),
        "rule_name": nested_get(event.raw, "rule.name"),
        "message": _event_message(event),
        "severity": decision.severity,
        "playbook": decision.playbook,
    }


def static_analysis(
    event: NormalizedEvent,
    decision: RuleDecision,
    *,
    source: str = "STATIC_RAG_PENDING_LLM",
    llm_error: Optional[str] = None,
    analysis_mode: str = "MEDIUM_PRE",
    post_context: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    kb = retrieve_knowledge(event.category)
    recommendation = (
        "Chờ LLM phân tích trước khi Admin quyết định."
        if decision.severity == "TRUNG BINH"
        else "Duy trì kiểm soát theo TTL và hậu kiểm bằng chứng liên quan."
    )
    result: dict[str, Any] = {
        "nhan_dinh": (
            f"Static RAG truy xuất {kb['kb_id']} và ánh xạ "
            f"{event.category} với MITRE ATT&CK {kb['mitre']}."
        ),
        "nguy_co": kb["description"],
        "co_so_suy_luan": (
            f"Frequency={event.frequency}/10 giây. SOP: {kb['sop']}"
        ),
        "khuyen_nghi": " ".join(kb.get("mitigation", [])[:2]) or decision.action_text,
        "de_xuat_admin": recommendation,
        "next_steps": " ".join(kb.get("investigation_steps", [])[:2]),
        "muc_do": decision.severity,
        "playbook_code": decision.playbook,
        "do_tin_cay": None,
        "grounding_score": None,
        "grounding_label": "N/A - chưa có đầu ra LLM hợp lệ",
        "analysis_source": source,
        "llm_status": "PENDING" if llm_error is None else "ERROR",
        "llm_model": Config.LLM_MODEL,
        "kb_id": kb["kb_id"],
        "kb_version": kb["kb_version"],
        "retrieval_method": kb["retrieval_method"],
        "retrieval_status": kb["retrieval_status"],
        "mitre_id": kb["mitre_id"],
        "mitre_name": kb["mitre_name"],
        "mitre_mapping_scope": kb["mapping_scope"],
        "rag_source_refs": kb.get("source_refs", []),
        "grounding_summary": (
            f"Static RAG: {kb['kb_id']} / {kb['retrieval_method']} / "
            f"{kb['mitre']}; Rule Engine giữ {decision.severity}/{decision.playbook}."
        ),
        "evidence_used": [
            f"source.ip={event.src_ip}",
            f"category={event.category}",
            f"frequency={event.frequency}/10s",
            f"destination={_event_destination(event)}",
            kb["kb_id"],
            kb["mitre"],
            f"playbook={decision.playbook}",
        ],
        "llm_self_confidence_used": False,
        "prompt_id": "NOT_CALLED",
        "validator_id": "STATIC-RAG-VALIDATOR-v1.3",
    }
    result["analysis_mode"] = analysis_mode

    if analysis_mode == "HIGH_POST":
        context = post_context or {}
        service = context.get("affected_service") or _event_destination(event)
        before = context.get("before") or {}
        after = context.get("after") or {}
        before_freqs = list(
            context.get("before_frequencies")
            or before.get("frequencies")
            or []
        )
        after_freqs = list(
            context.get("after_frequencies")
            or after.get("frequencies")
            or []
        )
        related_count = int(context.get("related_event_count") or 0)
        ttl_seconds = int(
            context.get("rule_ttl_seconds") or Config.BLOCK_TTL_SECONDS
        )
        rollback = list(
            context.get("rollback_conditions")
            or kb.get("rollback_conditions", [])
        )

        supported = (
            event.frequency >= 150
            and (
                related_count > 0
                or int(after.get("event_count") or 0) > 0
                or int(before.get("event_count") or 0) > 0
            )
        )
        assessment = (
            "SUPPORTED_BY_EVIDENCE"
            if supported
            else "INCONCLUSIVE"
        )
        recommended_action = (
            "KEEP_BLOCK_AND_WATCHLIST"
            if related_count > 0
            else "KEEP_BLOCK_UNTIL_TTL"
        )

        result.update({
            "containment_assessment": assessment,
            "context_explanation": (
                f"Rule Engine đã containment {event.src_ip} sau cảnh báo "
                f"{event.category} tần suất {event.frequency}/10 giây tới "
                f"{service}. Trước={before_freqs or [0]}, "
                f"sau={after_freqs or [0]}, MITRE={kb['mitre_id']}."
            ),
            "recommended_admin_action": recommended_action,
            "recommendation_reason": (
                f"Ngưỡng Rule Engine đã bị vượt và Elasticsearch ghi nhận "
                f"{related_count} cảnh báo liên quan bổ sung. Giữ rule theo "
                f"TTL {ttl_seconds} giây; Admin hậu kiểm trước khi thay đổi."
            ),
            "evidence_gaps": (
                "Chưa có telemetry CPU, tỷ lệ lỗi, availability, access log "
                "và xác minh nguồn IP hợp lệ để kết luận tác động thực tế."
            ),
            "admin_allowed_actions": [
                "KEEP_BLOCK_UNTIL_TTL",
                "KEEP_BLOCK_AND_WATCHLIST",
                "ROLLBACK_UNBLOCK",
            ],
            "admin_review_status": "PENDING_ADMIN_REVIEW",
            "admin_final_action": None,
            "advisory_only": True,
            "rollback_conditions": "; ".join(rollback[:3]),
            "control_integrity_score": 65,
            "control_integrity_max": 65,
            "llm_contribution_score": 0,
            "llm_contribution_max": 35,
            "llm_contribution_label": "SAFE_FALLBACK",
            "llm_accepted_count": 0,
            "llm_required_count": 5,
            "grounding_score": 65,
            "grounding_label": "AN TOÀN DỰ PHÒNG",
            "field_provenance": {
                "containment_assessment": "RULE_RAG_GUARDRAIL",
                "context_explanation": "EVIDENCE_RAG_GUARDRAIL",
                "recommended_admin_action": "POLICY_RAG_GUARDRAIL",
                "recommendation_reason": "EVIDENCE_RAG_GUARDRAIL",
                "evidence_gaps": "SYSTEM_EVIDENCE_GAP",
                "rollback_conditions": "STATIC_RAG",
            },
            "guardrail_overrides": [
                "containment_assessment",
                "context_explanation",
                "recommended_admin_action",
                "recommendation_reason",
                "evidence_gaps",
            ],
            "analysis_stage": "POST_BLOCK_ADMIN_ADVISORY",
            "analysis_role_contract": (
                "Rule Engine containment trước; Static RAG grounding; "
                "LLM tham mưu; Validator kiểm soát; Admin quyết định cuối."
            ),
            "de_xuat_admin": recommended_action,
            "nhan_dinh": (
                f"{assessment}: {recommended_action}"
            ),
            "co_so_suy_luan": (
                f"before={before_freqs}; after={after_freqs}; "
                f"related={related_count}; TTL={ttl_seconds}."
            ),
            "next_steps": (
                "Admin chọn giữ chặn, giữ chặn và đưa Watchlist, "
                "hoặc rollback/unblock."
            ),
            "final_analysis_source": "STATIC_RAG_SAFE_FALLBACK",
            "llm_output_quality": "SAFE_FALLBACK",
            "llm_status_detail": (
                "NOT_CALLED" if llm_error is None else "LLM_ERROR"
            ),
        })


    if llm_error:
        result["llm_error"] = llm_error
        result["de_xuat_admin"] = (
            "LLM không khả dụng; quản trị viên hậu kiểm bằng Static RAG, "
            "Rule Engine và log liên quan."
        )
    return result


# ---------------------------------------------------------------------
# OUTPUT SANITIZER — POST VALIDATOR / PRE OUTPUT SINK
# ---------------------------------------------------------------------

OUTPUT_SANITIZER_ID = "OUTPUT-SANITIZER-v1.0"
OUTPUT_SANITIZER_MAX_DEPTH = 6
OUTPUT_SANITIZER_MAX_STRING_LENGTH = 2000
OUTPUT_SANITIZER_MAX_LIST_ITEMS = 50
OUTPUT_SANITIZER_MAX_DICT_FIELDS = 80
OUTPUT_SANITIZER_MAX_KEY_LENGTH = 120
OUTPUT_SANITIZER_MAX_REPORT_ITEMS = 50

_ANSI_ESCAPE_RE = re.compile(
    r"\x1B(?:"
    r"\[[0-?]*[ -/]*[@-~]"
    r"|"
    r"[@-_]"
    r")"
)

_CONTROL_CHARACTER_RE = re.compile(
    r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]"
)

_SCRIPT_STYLE_BLOCK_RE = re.compile(
    r"<\s*(script|style)\b[^>]*>.*?<\s*/\s*\1\s*>",
    flags=re.I | re.S,
)

_HTML_TAG_RE = re.compile(
    r"<\s*/?\s*[A-Za-z][^>]{0,500}>",
    flags=re.I | re.S,
)

_DANGEROUS_SCHEME_RE = re.compile(
    r"\b(?:javascript|vbscript|data)\s*:",
    flags=re.I,
)

_MARKDOWN_FENCE_RE = re.compile(
    r"```(?:[A-Za-z0-9_+.\-]+)?",
    flags=re.I,
)

_SAFE_KEY_RE = re.compile(r"[^\w.\-]+", flags=re.UNICODE)


def _sanitizer_record(
    report: dict[str, Any],
    category: str,
    path: str,
) -> None:
    """Ghi nhận thay đổi nhưng giới hạn kích thước báo cáo."""
    report["change_count"] = int(report.get("change_count") or 0) + 1

    items = report.setdefault(category, [])
    if (
        isinstance(items, list)
        and len(items) < OUTPUT_SANITIZER_MAX_REPORT_ITEMS
        and path not in items
    ):
        items.append(path)


def _sanitize_llm_text(
    value: Any,
    path: str,
    report: dict[str, Any],
) -> str:
    """Làm sạch chuỗi trước DB, PDF, Dashboard và Telegram."""
    text = unicodedata.normalize("NFKC", str(value or ""))

    updated, count = _ANSI_ESCAPE_RE.subn("", text)
    if count:
        _sanitizer_record(report, "ansi_removed", path)
    text = updated

    text = text.replace("\r\n", "\n").replace("\r", "\n")

    updated, count = _CONTROL_CHARACTER_RE.subn("", text)
    if count:
        _sanitizer_record(report, "control_characters_removed", path)
    text = updated

    updated, count = _MARKDOWN_FENCE_RE.subn("", text)
    if count or "`" in updated:
        _sanitizer_record(report, "markdown_removed", path)
    text = updated.replace("`", "")

    updated, count = _DANGEROUS_SCHEME_RE.subn(
        "[BLOCKED_SCHEME]:",
        text,
    )
    if count:
        _sanitizer_record(report, "dangerous_schemes_blocked", path)
    text = updated

    updated, block_count = _SCRIPT_STYLE_BLOCK_RE.subn("", text)
    if block_count:
        _sanitizer_record(report, "script_style_blocks_removed", path)
    text = updated

    updated, count = _HTML_TAG_RE.subn("", text)
    if count:
        _sanitizer_record(report, "html_removed", path)
    text = updated

    # Không cho phần còn lại được Telegram/browser hiểu là HTML.
    translated = (
        text.replace("&", "＆")
        .replace("<", "＜")
        .replace(">", "＞")
    )
    if translated != text:
        _sanitizer_record(report, "html_metacharacters_neutralized", path)
    text = translated

    # Giới hạn chuỗi để tránh output bất thường làm phình DB/PDF/Telegram.
    if len(text) > OUTPUT_SANITIZER_MAX_STRING_LENGTH:
        text = text[:OUTPUT_SANITIZER_MAX_STRING_LENGTH]
        _sanitizer_record(report, "strings_truncated", path)

    return text.strip()


def _sanitize_llm_key(
    key: Any,
    path: str,
    report: dict[str, Any],
) -> str:
    """Chuẩn hóa key để không chứa markup hoặc cấu trúc bất thường."""
    raw_key = _sanitize_llm_text(
        key,
        f"{path}.__key__",
        report,
    )

    safe_key = _SAFE_KEY_RE.sub("_", raw_key).strip("._")
    if not safe_key:
        safe_key = "field"

    if safe_key != raw_key:
        _sanitizer_record(report, "keys_normalized", path)

    if len(safe_key) > OUTPUT_SANITIZER_MAX_KEY_LENGTH:
        safe_key = safe_key[:OUTPUT_SANITIZER_MAX_KEY_LENGTH]
        _sanitizer_record(report, "keys_truncated", path)

    return safe_key


def sanitize_llm_output(
    value: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Làm sạch output đã qua Validator trước khi tới output sink.

    Hàm không quyết định severity hoặc Playbook. Các giá trị đó tiếp tục
    được Core gắn lại từ RuleDecision sau bước Sanitizer.
    """
    report: dict[str, Any] = {
        "sanitizer_id": OUTPUT_SANITIZER_ID,
        "changed": False,
        "change_count": 0,
        "html_removed": [],
        "script_style_blocks_removed": [],
        "html_metacharacters_neutralized": [],
        "ansi_removed": [],
        "control_characters_removed": [],
        "markdown_removed": [],
        "dangerous_schemes_blocked": [],
        "strings_truncated": [],
        "lists_truncated": [],
        "dicts_truncated": [],
        "max_depth_reached": [],
        "keys_normalized": [],
        "keys_truncated": [],
        "duplicate_keys_dropped": [],
        "types_coerced": [],
    }

    def walk(current: Any, path: str, depth: int) -> Any:
        if depth > OUTPUT_SANITIZER_MAX_DEPTH:
            _sanitizer_record(report, "max_depth_reached", path)
            return "[MAX_DEPTH_REACHED]"

        if current is None or isinstance(current, (bool, int, float)):
            return current

        if isinstance(current, str):
            return _sanitize_llm_text(current, path, report)

        if isinstance(current, bytes):
            _sanitizer_record(report, "types_coerced", path)
            decoded = current.decode("utf-8", errors="replace")
            return _sanitize_llm_text(decoded, path, report)

        if isinstance(current, dict):
            cleaned_dict: dict[str, Any] = {}

            entries = list(current.items())
            if len(entries) > OUTPUT_SANITIZER_MAX_DICT_FIELDS:
                entries = entries[:OUTPUT_SANITIZER_MAX_DICT_FIELDS]
                _sanitizer_record(report, "dicts_truncated", path)

            for raw_key, raw_value in entries:
                safe_key = _sanitize_llm_key(raw_key, path, report)

                if safe_key in cleaned_dict:
                    _sanitizer_record(
                        report,
                        "duplicate_keys_dropped",
                        f"{path}.{safe_key}",
                    )
                    continue

                child_path = (
                    f"{path}.{safe_key}"
                    if path
                    else safe_key
                )
                cleaned_dict[safe_key] = walk(
                    raw_value,
                    child_path,
                    depth + 1,
                )

            return cleaned_dict

        if isinstance(current, (list, tuple, set)):
            if not isinstance(current, list):
                _sanitizer_record(report, "types_coerced", path)

            items = list(current)
            if len(items) > OUTPUT_SANITIZER_MAX_LIST_ITEMS:
                items = items[:OUTPUT_SANITIZER_MAX_LIST_ITEMS]
                _sanitizer_record(report, "lists_truncated", path)

            return [
                walk(item, f"{path}[{index}]", depth + 1)
                for index, item in enumerate(items)
            ]

        _sanitizer_record(report, "types_coerced", path)
        return _sanitize_llm_text(current, path, report)

    cleaned = walk(value, "$", 0)

    if not isinstance(cleaned, dict):
        _sanitizer_record(report, "types_coerced", "$")
        cleaned = {"value": cleaned}

    report["changed"] = bool(report["change_count"])

    # Loại các danh sách rỗng để báo cáo gọn hơn.
    compact_report = {
        key: item
        for key, item in report.items()
        if item not in ([], None)
    }

    return cleaned, compact_report


def _extract_json_object(raw: str) -> dict[str, Any]:
    cleaned = re.sub(
        r"^```(?:json)?\s*|\s*```$",
        "",
        str(raw or "").strip(),
        flags=re.I,
    )
    if not cleaned:
        raise ValueError("LLM trả nội dung rỗng")

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        if start < 0:
            raise ValueError("Không tìm thấy JSON object trong phản hồi LLM")
        depth = 0
        end: Optional[int] = None
        for index, char in enumerate(cleaned[start:], start=start):
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    end = index + 1
                    break
        if end is None:
            raise ValueError("JSON object chưa đóng ngoặc")
        parsed = json.loads(cleaned[start:end])

    if not isinstance(parsed, dict):
        raise ValueError("Phản hồi LLM không phải JSON object")
    return parsed


def parse_llm(
    raw: str,
    event: NormalizedEvent,
    decision: RuleDecision,
    analysis_mode: str,
    kb_result: Any,
    post_context: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    data = _extract_json_object(raw)
    evidence = _event_evidence(event, decision)
    validated = validate_and_score(
        data,
        event=evidence,
        severity=decision.severity,
        playbook=decision.playbook,
        analysis_mode=analysis_mode,
        kb=kb_result,
        post_context=post_context,
    )

    # Validator/Guardrail quyết định nội dung nào được giữ lại.
    # Sanitizer tiếp tục làm sạch trước DB/PDF/Dashboard/Telegram.
    validated, sanitizer_report = sanitize_llm_output(validated)

    source_map = {
        "HIGH_POST": "LLM_POST_BLOCK_ADVISORY",
        "MEDIUM_PRE": "LLM_PRE_HITL_ANALYSIS",
        "LOW_MONITOR": "LLM_MONITOR_ANALYSIS",
    }
    guarded = bool(validated.get("guardrail_overrides"))
    accepted = int(validated.get("llm_accepted_count") or 0)
    required = int(validated.get("llm_required_count") or 0)
    base_source = source_map.get(analysis_mode, "LLM_ANALYSIS")

    if accepted <= 0:
        llm_status = "REJECTED_BY_VALIDATOR"
        analysis_source = "STATIC_RAG_SAFE_FALLBACK"
        final_source = "STATIC_RAG_SAFE_FALLBACK"
    elif accepted < required:
        llm_status = "PARTIAL_ACCEPTED"
        analysis_source = f"{base_source}_WITH_GUARDRAIL"
        final_source = (
            "HYBRID_LLM_RAG_ADMIN_ADVISORY"
            if analysis_mode == "HIGH_POST"
            else "HYBRID_LLM_STATIC_RAG"
        )
    else:
        llm_status = "SUCCESS"
        analysis_source = base_source
        final_source = base_source

    validated.update(
        {
            "muc_do": decision.severity,
            "playbook_code": decision.playbook,
            "do_tin_cay": None,
            "analysis_source": analysis_source,
            "final_analysis_source": final_source,
            "llm_status": llm_status,
            "llm_model": Config.LLM_MODEL,
            "prompt_id": PROMPT_IDS.get(
                analysis_mode, "PROMPT-STATIC-RAG-v1.2"
            ),
            "validator_id": VALIDATOR_ID,
            "sanitizer_id": OUTPUT_SANITIZER_ID,
            "sanitizer_report": sanitizer_report,
        }
    )
    return validated

PROMPT_IDS = {
    "HIGH_POST": "PROMPT-HIGH-POST-BLOCK-ADVISORY-v3.0-FINAL",
    "MEDIUM_PRE": "PROMPT-MEDIUM-STATIC-RAG-v1.5",
    "LOW_MONITOR": "PROMPT-LOW-STATIC-RAG-v1.5",
}
VALIDATOR_ID = "STATIC-RAG-VALIDATOR-v3.0-ADVISORY-GROUNDED"


def _select_prompt(analysis_mode: str) -> str:
    if analysis_mode == "HIGH_POST":
        return HIGH_POST_PROMPT
    if analysis_mode == "MEDIUM_PRE":
        return MEDIUM_PRE_PROMPT
    return LOW_MONITOR_PROMPT


def call_llm(
    event: NormalizedEvent,
    decision: RuleDecision,
    policy: dict[str, Any],
    analysis_mode: str,
    *,
    post_context: Optional[dict[str, Any]] = None,
) -> tuple[dict[str, Any], float, Optional[str]]:
    """Call local Ollama with Static RAG context and deterministic validation."""
    kb_result = STATIC_RAG.retrieve(event.category)
    evidence = _event_evidence(event, decision)
    event_json = json.dumps(evidence, ensure_ascii=False, separators=(",", ":"))
    prompt = _select_prompt(analysis_mode).format(
        event_json=event_json,
        rag_context=compact_context(kb_result),
        post_context_json=json.dumps(
            compact_post_context_for_llm(post_context),
            ensure_ascii=False,
            separators=(",", ":"),
        ),
    )

    model = str(policy.get("llm_model") or Config.LLM_MODEL)
    endpoint = f"{Config.OLLAMA_URL}/api/chat"
    started = time.perf_counter()
    errors: list[str] = []

    for attempt in range(1, max(1, Config.LLM_RETRIES) + 1):
        try:
            wait_seconds, active_at_start = _llm_acquire_slot(
                analysis_mode=analysis_mode,
                attempt=attempt,
                model=model,
            )
            try:
                response = requests.post(
                    endpoint,
                    json={
                        "model": model,
                        "messages": [{"role": "user", "content": prompt}],
                        "format": (
                            HIGH_POST_RESPONSE_SCHEMA
                            if analysis_mode == "HIGH_POST"
                            else "json"
                        ),
                        "stream": False,
                        "keep_alive": Config.LLM_KEEP_ALIVE,
                        "options": {
                            "temperature": 0.0,
                            "num_ctx": (
                                Config.LLM_HIGH_NUM_CTX
                                if analysis_mode == "HIGH_POST"
                                else Config.LLM_NUM_CTX
                            ),
                            "num_predict": (
                                Config.LLM_HIGH_NUM_PREDICT
                                if analysis_mode == "HIGH_POST"
                                else Config.LLM_NUM_PREDICT
                            ),
                        },
                    },
                    timeout=Config.LLM_TIMEOUT_SECONDS,
                )
            finally:
                _llm_release_slot(
                    analysis_mode=analysis_mode,
                    attempt=attempt,
                    model=model,
                )

            if not response.ok:
                raise RuntimeError(
                    f"Ollama HTTP {response.status_code}: {response.text[:1500]}"
                )
            payload = response.json()
            content = str(nested_get(payload, "message.content") or "")
            done_reason = str(payload.get("done_reason") or "")
            if done_reason == "length":
                raise ValueError(
                    "Ollama cắt đầu ra vì hết token/context: "
                    f"prompt_eval_count={payload.get('prompt_eval_count')}, "
                    f"eval_count={payload.get('eval_count')}. "
                    "Tăng LLM_HIGH_NUM_CTX/LLM_HIGH_NUM_PREDICT hoặc "
                    "rút gọn context."
                )
            try:
                parsed = parse_llm(
                    content,
                    event,
                    decision,
                    analysis_mode,
                    kb_result,
                    post_context,
                )
            except Exception:
                print(f"[LLM RAW {analysis_mode}] {content[:2000]!r}")
                raise

            ns_to_s = lambda value: round(float(value or 0) / 1_000_000_000, 3)
            parsed["llm_model"] = model
            parsed["llm_runtime"] = {
                "load_duration": ns_to_s(payload.get("load_duration")),
                "prompt_eval_duration": ns_to_s(payload.get("prompt_eval_duration")),
                "eval_duration": ns_to_s(payload.get("eval_duration")),
                "prompt_eval_count": payload.get("prompt_eval_count"),
                "eval_count": payload.get("eval_count"),
            }
            parsed["prompt_hash"] = hashlib.sha256(
                prompt.encode("utf-8")
            ).hexdigest()[:16]
            parsed["response_hash"] = hashlib.sha256(
                content.encode("utf-8")
            ).hexdigest()[:16]
            latency = round(time.perf_counter() - started, 3)
            output_quality = parsed.get("llm_output_quality", "ACCEPTED")
            overrides = parsed.get("guardrail_overrides") or []
            override_note = f" | overrides={','.join(overrides)}" if overrides else ""
            print(
                f"[+] LLM {analysis_mode} {output_quality} | model={model} | "
                f"grounding={parsed.get('grounding_score')}/100 | {latency}s"
                f"{override_note}"
            )
            return parsed, latency, None
        except Exception as exc:
            error = (
                f"attempt={attempt}/{Config.LLM_RETRIES}: "
                f"{type(exc).__name__}: {exc}"
            )
            errors.append(error)
            print(f"[-] LLM {analysis_mode}: {error}")
            if attempt < Config.LLM_RETRIES:
                time.sleep(Config.LLM_RETRY_DELAY)

    latency = round(time.perf_counter() - started, 3)
    combined_error = " | ".join(errors)
    fallback = static_analysis(
        event,
        decision,
        source="STATIC_RAG_RULE_ENGINE_FALLBACK",
        llm_error=combined_error,
        analysis_mode=analysis_mode,
        post_context=post_context,
    )
    fallback["llm_model"] = model
    return fallback, latency, combined_error


# ---------------------------------------------------------------------
# PDF + TELEGRAM
# ---------------------------------------------------------------------

ROBOTO_REG = FONT_DIR / "Roboto-Regular.ttf"
ROBOTO_BOLD = FONT_DIR / "Roboto-Bold.ttf"
FONT_FAMILY = "Roboto" if ROBOTO_REG.exists() and ROBOTO_BOLD.exists() else "Helvetica"


def remove_accents(text: Any) -> str:
    normalized = unicodedata.normalize("NFKD", str(text))
    return "".join(ch for ch in normalized if not unicodedata.combining(ch))


def safe_text(value: Any) -> str:
    text = str(value or "Không có dữ liệu").replace("**", "").replace("`", "")
    text = re.sub(r"[^\w\s\.,;:\-\'\"()?!/%\[\]À-ỹđĐ]", "", text)
    return text if FONT_FAMILY == "Roboto" else remove_accents(text)


class PDFReport(FPDF):
    def header(self) -> None:
        self.set_font(FONT_FAMILY, "B", 17)
        self.cell(0, 10, safe_text("BÁO CÁO PHÂN TÍCH SỰ CỐ"), new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
        self.ln(4)

    def footer(self) -> None:
        self.set_y(-15)
        self.set_font(FONT_FAMILY, "", 9)
        self.cell(0, 10, safe_text(f"Trang {self.page_no()}"), align="C")


def export_pdf(
    incident_id: int,
    ai_data: dict[str, Any],
    status: str,
    audit: str,
    event: NormalizedEvent,
    playbook: str,
) -> str:
    """Xuất PDF audit đẹp từ dữ liệu incident thực tế."""
    try:
        metrics: dict[str, Any] = {}
        approved_by = "N/A"
        approved_at = "N/A"
        finished_at = "N/A"
        firewall_rule_id = "N/A"
        action = playbook
        post_review_status = ai_data.get(
            "admin_review_status",
            "PENDING_ADMIN_REVIEW",
        )
        post_review_action = ai_data.get("admin_final_action")
        post_review_by = "N/A"
        post_review_at = "N/A"
        db_llm_recommendation = None
        db_policy_decision = None

        with db_connect() as conn:
            row = conn.execute(
                "SELECT * FROM alerts WHERE id=?",
                (incident_id,),
            ).fetchone()

        provenance: dict[str, Any] = {}
        if row:
            payload = json.loads(row["raw_data"] or "{}")
            metrics = payload.get("metrics") or {}
            provenance = payload.get("decision_provenance") or {}
            approved_by = row["approved_by"] if "approved_by" in row.keys() else "N/A"
            approved_at = row["approved_at"] if "approved_at" in row.keys() else "N/A"
            finished_at = (
                row["execution_finished_at"]
                if "execution_finished_at" in row.keys()
                else "N/A"
            )
            firewall_rule_id = (
                row["firewall_rule_id"]
                if "firewall_rule_id" in row.keys()
                else "N/A"
            )
            action = row["action"] if "action" in row.keys() else playbook
            if "post_review_status" in row.keys() and row["post_review_status"]:
                post_review_status = row["post_review_status"]
            if "post_review_action" in row.keys() and row["post_review_action"]:
                post_review_action = row["post_review_action"]
            if "post_review_by" in row.keys() and row["post_review_by"]:
                post_review_by = row["post_review_by"]
            if "post_review_at" in row.keys() and row["post_review_at"]:
                post_review_at = row["post_review_at"]
            if "llm_recommendation" in row.keys() and row["llm_recommendation"]:
                db_llm_recommendation = row["llm_recommendation"]
            if "policy_decision" in row.keys() and row["policy_decision"]:
                db_policy_decision = row["policy_decision"]

        execution = {
            "severity": ai_data.get("muc_do", "N/A"),
            "playbook": playbook,
            "status": status,
            "action": action,
            "audit_trace": audit,
            "decision_source": provenance.get(
                "authorization_source", "RULE_ENGINE"
            ),
            "classification_source": provenance.get(
                "classification_source", "RULE_ENGINE"
            ),
            "knowledge_source": provenance.get(
                "knowledge_source", "STATIC_RAG"
            ),
            "analysis_source": (
                ai_data.get("analysis_source")
                or provenance.get("analysis_source")
                or "N/A"
            ),
            "authorization_source": provenance.get(
                "authorization_source", "RULE_ENGINE"
            ),
            "execution_source": provenance.get(
                "execution_source", "RESPONSE_ENGINE"
            ),
            "firewall_rule_id": firewall_rule_id or "N/A",
            "approved_by": approved_by or "N/A",
            "approved_at": approved_at or "N/A",
            "execution_finished_at": finished_at or "N/A",
            "whitelist_precheck": ai_data.get(
                "whitelist_precheck", "NOT_RECORDED"
            ),
            "whitelist_execution_recheck": ai_data.get(
                "whitelist_execution_recheck",
                "MATCHED" if status == "SKIPPED_WHITELIST" else "NOT_RECORDED",
            ),
            "whitelist_reason": ai_data.get("whitelist_reason", "N/A"),
            "whitelist_matched_target": ai_data.get(
                "whitelist_matched_target", "N/A"
            ),
            "whitelist_target_type": ai_data.get(
                "whitelist_target_type", "N/A"
            ),
            "post_review_status": post_review_status,
            "post_review_action": post_review_action or "CHƯA CÓ",
            "post_review_by": post_review_by,
            "post_review_at": post_review_at,
            "llm_recommendation": db_llm_recommendation,
            "policy_decision": db_policy_decision,
        }

        event_data = {
            "es_id": event.es_id,
            "timestamp": event.timestamp,
            "ip": event.src_ip,
            "category": event.category,
            "frequency": event.frequency,
            "destination": _event_destination(event),
            "destination_ip": nested_get(event.raw, "destination.ip"),
            "destination_port": nested_get(event.raw, "destination.port"),
            "transport": nested_get(event.raw, "network.transport"),
            "protocol": nested_get(event.raw, "network.protocol"),
            "rule_id": nested_get(event.raw, "rule.id"),
            "rule_name": nested_get(event.raw, "rule.name"),
            "message": _event_message(event),
        }

        metadata = {
            "classification": "NỘI BỘ",
            "data_type": "Cảnh báo tổng hợp từ Attack Simulator",
            "measurement_scope": "Post-alert từ Elasticsearch",
            "llm_role": (
                "Rule Engine chặn trước; Static RAG grounding; LLM tham mưu; Admin quyết định cuối"
            ),
            "rag_architecture": "Lightweight Static RAG - exact category match - no vector DB",
            "enforcement_mode": (
                "REAL IPTABLES"
                if Config.ENABLE_NETWORK_ENFORCEMENT
                else "DRY-RUN"
            ),
        }

        return build_incident_pdf(
            BASE_DIR,
            incident_id,
            event_data,
            ai_data,
            execution,
            metrics,
            metadata,
        )
    except Exception as exc:
        print(f"[-] PDF error: {exc}")
        traceback.print_exc()
        return ""


def telegram_enabled() -> bool:
    return bool(Config.TG_TOKEN and Config.TG_CHAT_ID)


def tg_call(method: str, payload: Optional[dict[str, Any]] = None, files: Optional[dict[str, Any]] = None, data: Optional[dict[str, Any]] = None, timeout: int = 20) -> Optional[dict[str, Any]]:
    if not telegram_enabled():
        return None
    url = f"https://api.telegram.org/bot{Config.TG_TOKEN}/{method}"
    for attempt in range(3):
        try:
            response = requests.post(url, json=payload, files=files, data=data, timeout=timeout)
            response.raise_for_status()
            result = response.json()
            if not result.get("ok"):
                raise RuntimeError(result)
            return result
        except Exception as exc:
            if attempt == 2:
                print(f"[-] Telegram {method}: {exc}")
                return None
            time.sleep(2)
    return None


def notify_telegram(message: str, markup: Optional[dict[str, Any]] = None) -> None:
    payload: dict[str, Any] = {"chat_id": Config.TG_CHAT_ID, "text": message, "parse_mode": "HTML"}
    if markup:
        payload["reply_markup"] = markup
    tg_call("sendMessage", payload=payload)


def send_pdf(filename: str, caption: str) -> None:
    path = BASE_DIR / filename
    if not telegram_enabled() or not filename or not path.is_file():
        return
    with path.open("rb") as fh:
        tg_call("sendDocument", files={"document": fh}, data={"chat_id": Config.TG_CHAT_ID, "caption": caption, "parse_mode": "HTML"}, timeout=30)


# ---------------------------------------------------------------------
# FIREWALL + WATCHLIST
# ---------------------------------------------------------------------

def validate_target(ip_text: str) -> str:
    ip = ipaddress.ip_address(ip_text)

    if ip.is_loopback or ip.is_multicast or ip.is_unspecified:
        raise ValueError(f"IP không an toàn để chặn: {ip}")

    # Whitelist là cổng an toàn ưu tiên cao nhất. Phải kiểm tra trước
    # cả LAB allowlist để tránh bypass với các IP TEST-NET dùng khi demo.
    try:
        whitelist = get_whitelist_entry(str(ip))
    except WhitelistLookupError as exc:
        if Config.WHITELIST_FAIL_CLOSED:
            raise ValueError(f"WHITELIST_CHECK_FAILED: {exc}") from exc
        whitelist = None
    if whitelist:
        raise ValueError(
            "WHITELIST_GATE_MATCHED: "
            f"IP {ip} khớp {whitelist.get('matched_target', whitelist.get('ip'))}; "
            "không được phép phản ứng."
        )

    # Các dải TEST-NET chỉ dùng cho LAB và không định tuyến Internet.
    if any(ip in network for network in Config.LAB_ALLOWED_NETWORKS):
        return str(ip)

    if ip.is_private and not Config.ALLOW_PRIVATE_BLOCK:
        raise ValueError(
            f"IP private {ip} chưa được cho phép. "
            "Chỉ bật ALLOW_PRIVATE_BLOCK=1 trong LAB kiểm soát."
        )

    if ip.is_reserved:
        raise ValueError(f"IP reserved không nằm trong LAB allowlist: {ip}")

    return str(ip)


def run_cmd(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, shell=False, check=check, capture_output=True, text=True, timeout=Config.IPTABLES_TIMEOUT)


def firewall_targets() -> list[str]:
    targets = [f"docker:{name}" for name in Config.FIREWALL_CONTAINERS]
    if Config.ALLOW_HOST_FIREWALL:
        targets.append("host")
    return targets


def prefix(target: str) -> list[str]:
    if target.startswith("docker:"):
        return ["docker", "exec", target.split(":", 1)[1], "iptables"]
    if target == "host":
        return ["sudo", "-n", "iptables"]
    raise ValueError(target)


def ensure_chain(target: str, chain: str) -> None:
    pre = prefix(target)
    run_cmd(pre + ["-N", chain], check=False)
    result = run_cmd(pre + ["-C", Config.IPTABLES_PARENT_CHAIN, "-j", chain], check=False)
    if result.returncode != 0:
        run_cmd(pre + ["-I", Config.IPTABLES_PARENT_CHAIN, "1", "-j", chain])


def add_rule(target: str, chain: str, args: list[str]) -> bool:
    ensure_chain(target, chain)
    pre = prefix(target)
    if run_cmd(pre + ["-C", chain] + args, check=False).returncode == 0:
        return False
    run_cmd(pre + ["-A", chain] + args)
    return True


def save_rule(ip: str, category: str, target: str, kind: str, ttl: int) -> None:
    expires = (utc_now() + dt.timedelta(seconds=ttl)).isoformat(timespec="seconds").replace("+00:00", "Z")
    with db_connect() as conn:
        conn.execute(
            """INSERT INTO blocked_ips
               (ip, category, blocked_at, expires_at, status, rule_target, rule_kind)
               VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?)
               ON CONFLICT(ip) DO UPDATE SET
                 category=excluded.category, blocked_at=excluded.blocked_at,
                 expires_at=excluded.expires_at, status='ACTIVE',
                 rule_target=excluded.rule_target, rule_kind=excluded.rule_kind""",
            (ip, category, utc_now_iso(), expires, target, kind),
        )


def execute_block(ip_text: str, category: str) -> tuple[str, str, Optional[str]]:
    try:
        ip = validate_target(ip_text)
    except ValueError as exc:
        return "FAILED", str(exc), None
    if not Config.ENABLE_NETWORK_ENFORCEMENT:
        return "DRY_RUN_SUCCESS", "DRY-RUN: chưa thay đổi iptables.", f"DRYRUN-BLOCK-{ip}"
    errors: list[str] = []
    for target in firewall_targets():
        try:
            created = add_rule(target, "SOAR_BLOCK", ["-s", ip, "-j", "DROP"])
            save_rule(ip, category, target, "BLOCK", Config.BLOCK_TTL_SECONDS)
            return "SUCCESS", f"Rule DROP {'đã thêm' if created else 'đã tồn tại'} trên {target}; có TTL.", f"{target}:SOAR_BLOCK:{ip}"
        except Exception as exc:
            errors.append(f"{target}: {exc}")
    return "FAILED", " | ".join(errors), None


def execute_rate_limit(ip_text: str, category: str) -> tuple[str, str, Optional[str]]:
    try:
        ip = validate_target(ip_text)
    except ValueError as exc:
        return "FAILED", str(exc), None
    if not Config.ENABLE_NETWORK_ENFORCEMENT:
        return "DRY_RUN_SUCCESS", "DRY-RUN: chưa thêm rate-limit.", f"DRYRUN-RATE-{ip}"
    args = ["-p", "tcp", "--syn", "-s", ip, "-m", "connlimit", "--connlimit-above", "5", "-j", "REJECT", "--reject-with", "tcp-reset"]
    errors: list[str] = []
    for target in firewall_targets():
        try:
            created = add_rule(target, "SOAR_RATE", args)
            save_rule(ip, category, target, "RATE_LIMIT", Config.RATE_LIMIT_TTL_SECONDS)
            return "SUCCESS", f"Rate-limit {'đã thêm' if created else 'đã tồn tại'} trên {target}; có TTL.", f"{target}:SOAR_RATE:{ip}"
        except Exception as exc:
            errors.append(f"{target}: {exc}")
    return "FAILED", " | ".join(errors), None


def execute_playbook(playbook: str, ip: str, category: str) -> tuple[str, str, Optional[str]]:
    # Gate #2: kiểm tra lại ngay trước khi thay đổi Firewall để chống
    # tình huống IP được thêm vào Whitelist sau lúc phân loại/HITL.
    try:
        whitelist = get_whitelist_entry(ip)
    except WhitelistLookupError as exc:
        audit_control_event(
            "WHITELIST_GATE_LOOKUP_FAILED",
            ip,
            "response-engine",
            f"playbook={playbook}; error={exc}",
        )
        return (
            "SAFETY_HOLD",
            "Whitelist Gate #2 không xác minh được; fail-closed, "
            f"không thực thi {playbook}. Chi tiết: {exc}",
            None,
        )
    if whitelist:
        reason = str(whitelist.get("description") or "Không có mô tả")
        actor = str(whitelist.get("created_by") or "unknown")
        matched_target = str(
            whitelist.get("matched_target") or whitelist.get("ip")
        )
        audit_control_event(
            "WHITELIST_GATE_BLOCKED_PLAYBOOK",
            ip,
            "response-engine",
            f"playbook={playbook}; matched_target={matched_target}; "
            f"created_by={actor}; reason={reason}",
        )
        return (
            "SKIPPED_WHITELIST",
            f"Whitelist Gate #2 MATCHED ({matched_target}); "
            f"không thực thi {playbook}. Lý do: {reason}",
            None,
        )

    if playbook in {"PLAYBOOK_1", "PLAYBOOK_3"}:
        return execute_block(ip, category)
    if playbook == "PLAYBOOK_2":
        return execute_rate_limit(ip, category)
    if playbook == "PLAYBOOK_4":
        return "SUCCESS", "Watchlist/audit; không thay đổi Firewall.", None
    return "FAILED", f"Playbook không hỗ trợ: {playbook}", None


def update_watchlist(ip: str, category: str) -> tuple[int, bool, str]:
    now, expiry = utc_now(), utc_now() + dt.timedelta(hours=Config.WATCH_WINDOW_HOURS)
    with db_connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM watchlist WHERE ip=?", (ip,)).fetchone()
        if row:
            old_expiry = dt.datetime.fromisoformat(str(row["expires_at"]).replace("Z", "+00:00"))
            strikes = 1 if old_expiry <= now else int(row["strike_count"]) + 1
            first_seen = utc_now_iso() if old_expiry <= now else str(row["first_seen"])
            conn.execute(
                """UPDATE watchlist SET category=?, strike_count=?, first_seen=?,
                   last_seen=?, expires_at=?, status='ACTIVE' WHERE ip=?""",
                (category, strikes, first_seen, utc_now_iso(), expiry.isoformat(timespec="seconds").replace("+00:00", "Z"), ip),
            )
        else:
            strikes = 1
            conn.execute(
                """INSERT INTO watchlist
                   (ip, category, strike_count, first_seen, last_seen, expires_at, status)
                   VALUES (?, ?, 1, ?, ?, ?, 'ACTIVE')""",
                (ip, category, utc_now_iso(), utc_now_iso(), expiry.isoformat(timespec="seconds").replace("+00:00", "Z")),
            )
    return strikes, strikes >= Config.WATCH_STRIKE_THRESHOLD, f"Watchlist strike={strikes}; cửa sổ {Config.WATCH_WINDOW_HOURS} giờ."


def cleanup_expired_firewall_rules() -> None:
    """Xóa rule hết TTL và đồng bộ trạng thái SQLite."""
    while True:
        try:
            with db_connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM blocked_ips WHERE status='ACTIVE' AND expires_at<=?",
                    (utc_now_iso(),),
                ).fetchall()
            for row in rows:
                ip = str(row["ip"])
                target = str(row["rule_target"])
                kind = str(row["rule_kind"])
                if kind == "BLOCK":
                    chain = "SOAR_BLOCK"
                    args = ["-s", ip, "-j", "DROP"]
                else:
                    chain = "SOAR_RATE"
                    args = ["-p", "tcp", "--syn", "-s", ip, "-m", "connlimit", "--connlimit-above", "5", "-j", "REJECT", "--reject-with", "tcp-reset"]
                try:
                    if Config.ENABLE_NETWORK_ENFORCEMENT:
                        pre = prefix(target)
                        if run_cmd(pre + ["-C", chain] + args, check=False).returncode == 0:
                            run_cmd(pre + ["-D", chain] + args)
                    with db_connect() as conn:
                        conn.execute("UPDATE blocked_ips SET status='EXPIRED' WHERE ip=?", (ip,))
                    print(f"[+] Đã rollback rule hết TTL cho {ip}")
                except Exception as exc:
                    print(f"[-] Rollback TTL {ip}: {exc}")
        except Exception as exc:
            print(f"[-] TTL cleanup: {exc}")
        time.sleep(60)


def rollback_firewall_rule(
    ip_text: str,
    actor: str = "api-user",
) -> tuple[bool, str]:
    """Rollback rule theo IP và đồng bộ SQLite.

    Hỗ trợ cả record mới có rule_target/rule_kind và record legacy.
    Trong DRY-RUN chỉ cập nhật trạng thái, không gọi iptables.
    """
    try:
        ip = str(ipaddress.ip_address(ip_text))
    except ValueError:
        return False, "IP không hợp lệ."

    with db_connect() as conn:
        row = conn.execute(
            """SELECT * FROM blocked_ips
               WHERE ip=? AND COALESCE(status,'ACTIVE')
                     IN ('ACTIVE','BLOCKED')
               LIMIT 1""",
            (ip,),
        ).fetchone()

    if not row:
        return False, f"Không tìm thấy active rule cho {ip}."

    keys = set(row.keys())
    kind = str(row["rule_kind"] if "rule_kind" in keys and row["rule_kind"] else "BLOCK")
    target = str(row["rule_target"] if "rule_target" in keys and row["rule_target"] else "")

    if kind == "RATE_LIMIT":
        chain = "SOAR_RATE"
        args = [
            "-p", "tcp", "--syn", "-s", ip,
            "-m", "connlimit", "--connlimit-above", "5",
            "-j", "REJECT", "--reject-with", "tcp-reset",
        ]
    else:
        chain = "SOAR_BLOCK"
        args = ["-s", ip, "-j", "DROP"]

    try:
        removed = False
        if Config.ENABLE_NETWORK_ENFORCEMENT:
            targets = [target] if target in firewall_targets() else firewall_targets()
            errors: list[str] = []
            for current_target in targets:
                try:
                    pre = prefix(current_target)
                    check = run_cmd(
                        pre + ["-C", chain] + args,
                        check=False,
                    )
                    if check.returncode == 0:
                        run_cmd(pre + ["-D", chain] + args)
                        removed = True
                        target = current_target
                        break
                except Exception as exc:
                    errors.append(f"{current_target}: {exc}")

            if not removed and errors:
                return False, " | ".join(errors)

        with db_connect() as conn:
            conn.execute(
                """UPDATE blocked_ips
                   SET status='ROLLBACKED'
                   WHERE ip=?""",
                (ip,),
            )
            alert_columns = {
                item["name"]
                for item in conn.execute(
                    "PRAGMA table_info(alerts)"
                ).fetchall()
            }
            updates = {
                "execution_status": "ROLLBACKED",
                "action": "FIREWALL_RULE_ROLLBACK",
                "audit_trace": (
                    f"{actor} rollback rule của {ip}"
                    + (f" tại {target}" if target else "")
                    + "."
                ),
            }
            usable = {
                key: value
                for key, value in updates.items()
                if key in alert_columns
            }
            if usable:
                assignments = ", ".join(
                    f"{key}=?" for key in usable
                )
                conn.execute(
                    f"""UPDATE alerts SET {assignments}
                        WHERE ip=? AND execution_status='SUCCESS'""",
                    (*usable.values(), ip),
                )

        mode = "iptables" if Config.ENABLE_NETWORK_ENFORCEMENT else "DRY-RUN"
        return True, f"Đã rollback {ip} ({mode})."
    except Exception as exc:
        return False, f"Rollback thất bại: {exc}"




# ---------------------------------------------------------------------
# INCIDENT + HITL
# ---------------------------------------------------------------------

REPORT_QUEUE: queue.Queue[int] = queue.Queue(maxsize=Config.REPORT_QUEUE_SIZE)


def insert_alert(
    event: NormalizedEvent,
    decision: RuleDecision,
    status: str,
    action: str,
    audit: str,
    ai_data: dict[str, Any],
    p1: Optional[float],
    p2: float,
    p3: float,
    response_latency: Optional[float],
    report_latency: Optional[float],
    rule_id: Optional[str],
    approval_status: Optional[str],
    authorization_source: str = "RULE_ENGINE",
    execution_source: str = "RESPONSE_ENGINE",
) -> int:
    payload = {
        "event": {
            "es_id": event.es_id,
            "timestamp": event.timestamp,
            "ip": event.src_ip,
            "category": event.category,
            "frequency": event.frequency,
        },
        "raw_event": event.raw,
        "ai_data": ai_data,
        "metrics": {
            "p1": p1,
            "p2": p2,
            "p3": p3,
            "technical_execution_latency": p3,
            "response_latency": response_latency,
            "report_latency": report_latency,
            "pre_hitl_report_latency": (
                report_latency
                if status == "PENDING" and approval_status == "PENDING"
                else None
            ),
            "final_report_latency": (
                report_latency
                if status not in {"PENDING", "EXECUTING"}
                else None
            ),
        },
        "lifecycle": {
            "state": status,
            "approval_status": approval_status,
            "transitioned_at": utc_now_iso(),
        },
        "decision_provenance": {
            "classification_source": "RULE_ENGINE",
            "knowledge_source": "STATIC_RAG",
            "analysis_source": ai_data.get("analysis_source", "N/A"),
            "authorization_source": authorization_source,
            "execution_source": execution_source,
        },
    }
    with db_connect() as conn:
        cur = conn.execute(
            """INSERT INTO alerts
               (timestamp, ip, category, llm_recommendation, policy_decision,
                severity, playbook, action, execution_status, approval_status,
                confidence_score, grounding_score, kb_id, mitre_id,
                retrieval_status, llm_status, llm_model_used,
                latency, response_latency, report_latency,
                pdf_file, llm_reasoning, audit_trace, raw_data, es_id,
                firewall_rule_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                       ?, ?, ?, '', ?, ?, ?, ?, ?)""",
            (
                utc_now_iso(), event.src_ip, event.category,
                ai_data.get("de_xuat_admin"), decision.severity,
                decision.severity, decision.playbook, action, status,
                approval_status, None, ai_data.get("grounding_score"),
                ai_data.get("kb_id"), ai_data.get("mitre_id"),
                ai_data.get("retrieval_status"), ai_data.get("llm_status"),
                ai_data.get("llm_model"),
                report_latency if report_latency is not None else p3,
                response_latency, report_latency,
                ai_data.get("nhan_dinh", ""), audit,
                json.dumps(payload, ensure_ascii=False), event.es_id, rule_id,
            ),
        )
        return int(cur.lastrowid)

def row_to_event(row: sqlite3.Row) -> NormalizedEvent:
    payload = json.loads(row["raw_data"] or "{}")
    data = payload.get("event", {})
    raw_event = payload.get("raw_event")
    if not isinstance(raw_event, dict):
        raw_event = data.get("raw") if isinstance(data.get("raw"), dict) else {}
    return NormalizedEvent(
        es_id=str(data.get("es_id") or row["es_id"]),
        timestamp=str(data.get("timestamp") or utc_now_iso()),
        src_ip=str(data.get("ip") or row["ip"]),
        category=str(data.get("category") or row["category"]),
        frequency=int(data.get("frequency") or 0),
        raw=raw_event,
    )

def send_approval_request(incident_id: int, event: NormalizedEvent, decision: RuleDecision) -> None:
    markup = {"inline_keyboard": [[
        {"text": "✅ DUYỆT", "callback_data": f"approve:{incident_id}"},
        {"text": "❌ TỪ CHỐI", "callback_data": f"reject:{incident_id}"},
    ]]}
    notify_telegram(
        f"🛡 <b>YÊU CẦU PHÊ DUYỆT</b>\n🆔 INC-{incident_id}\n"
        f"📍 IP: <code>{event.src_ip}</code>\n🚨 {event.category}\n"
        f"📊 {decision.severity}\n🛠 <b>{decision.playbook}</b>", markup,
    )


def process_event(event: NormalizedEvent) -> None:
    p1 = calculate_p1(event.timestamp)

    # Gate #1: kiểm tra Whitelist trước Rule Engine, LLM và Playbook.
    try:
        whitelist = get_whitelist_entry(event.src_ip)
    except WhitelistLookupError as exc:
        # Không phản ứng khi chưa xác minh được safe exclusion.
        decision = RuleDecision(
            "N/A", "NONE", "Safety hold do Whitelist lookup lỗi.",
            False, False,
        )
        data = static_analysis(event, decision, source="SAFETY_GUARD")
        data.update({
            "nhan_dinh": "Không xác minh được Whitelist; hệ thống dừng phản ứng theo nguyên tắc fail-closed.",
            "khuyen_nghi": "Khắc phục SQLite/Whitelist rồi xử lý lại incident.",
            "de_xuat_admin": "REVIEW_SYSTEM_HEALTH",
            "whitelist_precheck": "ERROR_FAIL_CLOSED",
            "whitelist_execution_recheck": "NOT_REACHED",
            "whitelist_reason": str(exc),
        })
        audit = f"Whitelist Gate #1 lookup failed; SAFETY_HOLD: {exc}"
        audit_control_event(
            "WHITELIST_GATE_LOOKUP_FAILED",
            event.src_ip,
            "orchestrator",
            audit,
        )
        incident_id = insert_alert(
            event, decision, "SAFETY_HOLD",
            "KHÔNG PHẢN ỨNG - FAIL-CLOSED", audit, data,
            p1, 0.0, 0.0, None, p1, None, "SAFETY_HOLD",
            authorization_source="SAFETY_POLICY",
            execution_source="NOT_EXECUTED",
        )
        pdf = export_pdf(
            incident_id, data, "SAFETY_HOLD", audit,
            event, decision.playbook,
        )
        with db_connect() as conn:
            conn.execute(
                "UPDATE alerts SET pdf_file=? WHERE id=?",
                (pdf, incident_id),
            )
        return

    if whitelist:
        decision = RuleDecision(
            "THAP",
            "PLAYBOOK_4",
            "Safe exclusion theo Whitelist Policy.",
            False,
            False,
        )
        data = static_analysis(
            event,
            decision,
            source="WHITELIST_POLICY",
        )
        reason = str(whitelist.get("description") or "Không có mô tả")
        data.update({
            "nhan_dinh": (
                f"Whitelist Gate #1 MATCHED cho {event.src_ip}; "
                "Rule Engine và Response Engine không được kích hoạt."
            ),
            "khuyen_nghi": "Duy trì safe exclusion và hậu kiểm định kỳ.",
            "de_xuat_admin": "REVIEW_WHITELIST_ENTRY",
            "whitelist_precheck": "MATCHED",
            "whitelist_execution_recheck": "NOT_REQUIRED",
            "whitelist_reason": reason,
            "whitelist_matched_target": whitelist.get("matched_target") or whitelist.get("ip"),
            "whitelist_target_type": whitelist.get("target_type") or "IP",
            "whitelist_created_by": whitelist.get("created_by") or "N/A",
            "whitelist_created_at": whitelist.get("created_at") or "N/A",
        })
        audit = (
            f"Whitelist Gate #1 MATCHED; reason={reason}; "
            f"created_by={whitelist.get('created_by') or 'N/A'}."
        )
        audit_control_event(
            "WHITELIST_GATE_SKIPPED_EVENT",
            event.src_ip,
            "orchestrator",
            audit,
        )
        incident_id = insert_alert(
            event, decision, "SKIPPED_WHITELIST",
            "SAFE_EXCLUSION - KHÔNG PHẢN ỨNG", audit, data,
            p1, 0.0, 0.0, p1, p1, None, "NOT_REQUIRED",
            authorization_source="WHITELIST_POLICY",
            execution_source="NOT_EXECUTED",
        )
        pdf = export_pdf(
            incident_id, data, "SKIPPED_WHITELIST", audit,
            event, decision.playbook,
        )
        with db_connect() as conn:
            conn.execute(
                "UPDATE alerts SET pdf_file=? WHERE id=?",
                (pdf, incident_id),
            )
        return

    decision, policy = decide_rule(event.category, event.frequency), get_policy()

    # HIGH: phản ứng trước, LLM hậu kiểm sau.
    if decision.high_priority:
        started = time.perf_counter()
        if policy.get("emergency_stop") or not Config.AUTO_BLOCK_HIGH:
            status, audit, rule_id, approval = "PENDING", "HIGH chuyển HITL do emergency stop/cấu hình.", None, "PENDING"
        else:
            status, audit, rule_id = execute_playbook(decision.playbook, event.src_ip, event.category)
            # Giữ nguyên DRY_RUN_SUCCESS để phân biệt DRY-RUN và LIVE.
            approval = None
        p3 = round(time.perf_counter() - started, 3)
        response_latency = round((p1 or 0.0) + p3, 3)
        high_ai = static_analysis(
            event, decision, source="STATIC_RAG_PENDING_LLM"
        )
        high_ai["whitelist_precheck"] = "NOT_MATCHED"
        high_ai["whitelist_execution_recheck"] = (
            "MATCHED"
            if status == "SKIPPED_WHITELIST"
            else "ERROR_FAIL_CLOSED"
            if status == "SAFETY_HOLD"
            else "NOT_MATCHED"
        )
        incident_id = insert_alert(
            event, decision, status, decision.action_text, audit, high_ai,
            p1, 0.0, p3, response_latency, None, rule_id, approval,
            authorization_source=(
                "ADMIN_PENDING"
                if status == "PENDING"
                else "WHITELIST_POLICY"
                if status == "SKIPPED_WHITELIST"
                else "SAFETY_POLICY"
                if status == "SAFETY_HOLD"
                else "RULE_ENGINE_FAST_PATH"
            ),
            execution_source=(
                "NOT_EXECUTED"
                if status in {"PENDING", "SKIPPED_WHITELIST", "SAFETY_HOLD"}
                else "RESPONSE_ENGINE"
            ),
        )
        if status == "PENDING":
            # HIGH chưa được thực thi: chỉ chờ HITL.
            # Không đưa vào HIGH_POST vì chưa có external effect để hậu kiểm.
            send_approval_request(incident_id, event, decision)
            return

        if status in {"SKIPPED_WHITELIST", "SAFETY_HOLD"}:
            # Safe exclusion hoặc safety policy thắng Playbook.
            pdf = export_pdf(
                incident_id,
                high_ai,
                status,
                audit,
                event,
                decision.playbook,
            )
            with db_connect() as conn:
                conn.execute(
                    "UPDATE alerts SET pdf_file=? WHERE id=?",
                    (pdf, incident_id),
                )
            return

        if status == "FAILED":
            notify_telegram(
                f"❌ <b>HIGH RESPONSE FAILED</b>\n"
                f"🆔 INC-{incident_id}\n"
                f"📍 <code>{event.src_ip}</code>\n"
                f"🛠 {decision.playbook}\n"
                f"Chi tiết: {audit}"
            )
            try:
                REPORT_QUEUE.put_nowait(incident_id)
            except queue.Full:
                pass
            return

        notify_telegram(
            f"🚨 <b>HIGH ĐÃ PHẢN ỨNG</b>\n"
            f"🆔 INC-{incident_id}\n"
            f"📍 <code>{event.src_ip}</code>\n"
            f"🛠 {decision.playbook}\n"
            f"⏱ {response_latency}s"
        )
        try:
            REPORT_QUEUE.put_nowait(incident_id)
        except queue.Full:
            print(
                f"[-] Report queue đầy; INC-{incident_id} "
                "giữ báo cáo tĩnh."
            )
        return

    # MEDIUM: LLM giải thích rồi HITL.
    if decision.severity == "TRUNG BINH":
        ai_data, p2, llm_error = call_llm(
            event, decision, policy, "MEDIUM_PRE"
        )
        ai_data["whitelist_precheck"] = "NOT_MATCHED"
        ai_data["whitelist_execution_recheck"] = "PENDING_HITL"
        report_latency = round((p1 or 0.0) + p2, 3)
        audit = "LLM đã phân tích sự kiện mức TRUNG BÌNH; chờ Admin quyết định Approve hoặc Reject."
        if llm_error:
            audit += f" LLM fallback: {llm_error}"
        incident_id = insert_alert(
            event, decision, "PENDING",
            f"CHỜ DUYỆT: {decision.playbook}", audit, ai_data,
            p1, p2, 0.0, None, report_latency, None, "PENDING",
            authorization_source="ADMIN_PENDING",
            execution_source="NOT_EXECUTED",
        )
        pdf = export_pdf(incident_id, ai_data, "PENDING", audit, event, decision.playbook)
        with db_connect() as conn:
            conn.execute("UPDATE alerts SET pdf_file=? WHERE id=?", (pdf, incident_id))
        send_approval_request(incident_id, event, decision)
        return

    # LOW: Rule Engine cập nhật Watchlist, LLM diễn giải giám sát.
    strikes, escalated, watch_audit = update_watchlist(
        event.src_ip,
        event.category,
    )
    ai_data, p2, llm_error = call_llm(
        event,
        decision,
        policy,
        "LOW_MONITOR",
    )
    ai_data["whitelist_precheck"] = "NOT_MATCHED"
    ai_data["whitelist_execution_recheck"] = "NOT_REQUIRED"
    ai_data["co_so_suy_luan"] = (
        f"{ai_data.get('co_so_suy_luan', '')} "
        f"Watchlist strike={strikes}."
    ).strip()

    if escalated:
        escalated_decision = RuleDecision(
            "TRUNG BINH",
            "PLAYBOOK_2",
            "Watchlist đạt ngưỡng; LLM phân tích và chuyển HITL.",
            True,
            False,
        )
        # Phân tích lại theo ngữ cảnh MEDIUM trước khi Admin quyết định.
        ai_data, p2, llm_error = call_llm(
            event,
            escalated_decision,
            policy,
            "MEDIUM_PRE",
        )
        audit = (
            watch_audit
            + " Đạt ngưỡng; đã qua LLM và đang chờ Admin quyết định."
        )
        if llm_error:
            audit += f" LLM fallback: {llm_error}"

        incident_id = insert_alert(
            event,
            escalated_decision,
            "PENDING",
            f"CHỜ DUYỆT: {escalated_decision.playbook}",
            audit,
            ai_data,
            p1,
            p2,
            0.0,
            None,
            round((p1 or 0.0) + p2, 3),
            None,
            "PENDING",
            authorization_source="ADMIN_PENDING",
            execution_source="NOT_EXECUTED",
        )
        pdf = export_pdf(
            incident_id,
            ai_data,
            "PENDING",
            audit,
            event,
            escalated_decision.playbook,
        )
        with db_connect() as conn:
            conn.execute(
                "UPDATE alerts SET pdf_file=? WHERE id=?",
                (pdf, incident_id),
            )
        send_approval_request(
            incident_id,
            event,
            escalated_decision,
        )
        return

    audit = watch_audit + " Đã qua LLM phân tích giám sát."
    if llm_error:
        audit += f" LLM fallback: {llm_error}"

    report_latency = round((p1 or 0.0) + p2, 3)
    incident_id = insert_alert(
        event,
        decision,
        "SUCCESS",
        "PLAYBOOK_4: WATCHLIST",
        audit,
        ai_data,
        p1,
        p2,
        0.0,
        p1,
        report_latency,
        None,
        None,
        authorization_source="RULE_ENGINE_MONITOR_POLICY",
        execution_source="WATCHLIST_ENGINE",
    )
    pdf = export_pdf(
        incident_id,
        ai_data,
        "SUCCESS",
        audit,
        event,
        decision.playbook,
    )
    with db_connect() as conn:
        conn.execute(
            "UPDATE alerts SET pdf_file=? WHERE id=?",
            (pdf, incident_id),
        )


def high_report_worker() -> None:
    while True:
        incident_id = REPORT_QUEUE.get()
        try:
            with db_connect() as conn:
                row = conn.execute(
                    "SELECT * FROM alerts WHERE id=?", (incident_id,)
                ).fetchone()
            if not row:
                continue

            # E4 safety guard: HIGH_POST chỉ dành cho incident đã có
            # phản ứng kỹ thuật. Incident PENDING/HITL chưa có external
            # effect nên không được gắn nhãn POST_BLOCK_REVIEW.
            if str(row["execution_status"] or "").upper() == "PENDING":
                continue

            event = row_to_event(row)
            decision = RuleDecision(
                str(row["severity"]), str(row["playbook"]),
                str(row["action"]), True, True,
            )
            if Config.POST_ANALYSIS_WAIT_SECONDS > 0:
                time.sleep(Config.POST_ANALYSIS_WAIT_SECONDS)

            kb_result = STATIC_RAG.retrieve(event.category)
            post_context = collect_post_response_context(
                event,
                decision,
                kb_result,
            )
            ai_data, p2, llm_error = call_llm(
                event,
                decision,
                get_policy(),
                "HIGH_POST",
                post_context=post_context,
            )
            payload = json.loads(row["raw_data"] or "{}")
            payload["post_response_context"] = post_context
            metrics = payload.setdefault("metrics", {})
            metrics["p2"] = p2
            report_latency = calculate_p1(event.timestamp)
            metrics["final_report_latency"] = report_latency
            metrics["report_latency"] = report_latency
            metrics["report_measurement_note"] = (
                "HIGH: phản ứng hoàn tất trước; LLM chạy hậu phân tích. "
                "final_report_latency đo từ alert trong ES đến thời điểm "
                "chuẩn bị sinh PDF cuối."
            )
            payload.setdefault("lifecycle", {}).update({
                "state": str(row["execution_status"]),
                "approval_status": row["approval_status"],
                "transitioned_at": utc_now_iso(),
            })
            ai_data.update({
                "admin_review_status": "PENDING_ADMIN_REVIEW",
                "admin_final_action": None,
                "admin_allowed_actions": [
                    "KEEP_BLOCK_UNTIL_TTL",
                    "KEEP_BLOCK_AND_WATCHLIST",
                    "ROLLBACK_UNBLOCK",
                ],
                "advisory_only": True,
            })

            payload["ai_data"] = ai_data
            payload.setdefault("decision_provenance", {}).update({
                "analysis_source": ai_data.get(
                    "analysis_source",
                    "LLM_POST_BLOCK_ADVISORY",
                ),
                "knowledge_source": "STATIC_RAG",
                "authorization_source": "RULE_ENGINE_FAST_PATH",
                "execution_source": "RESPONSE_ENGINE",
            })
            payload.setdefault("lifecycle", {}).update({
                "post_block_review_status": "PENDING_ADMIN_REVIEW",
                "post_block_advisory_status": ai_data.get("llm_status"),
                "post_block_advisory_completed_at": utc_now_iso(),
            })
            if llm_error:
                payload["llm_error"] = llm_error

            accepted_count = int(ai_data.get("llm_accepted_count") or 0)
            required_count = int(ai_data.get("llm_required_count") or 0)
            post_audit = (
                f"{row['audit_trace']} | POST_RESPONSE_ANALYSIS: "
                f"status={ai_data.get('llm_status')}; "
                f"accepted={accepted_count}/{required_count}; "
                f"source={ai_data.get('final_analysis_source')}; "
                f"current_alert={post_context.get('current_alert_count', 0)}; "
                f"related_additional={post_context.get('related_event_count', 0)}; "
                f"scope={post_context.get('context_query_scope')}; "
                f"ttl={post_context.get('rule_ttl_seconds')}s."
            )

            # Persist first so PDF reads final metrics, context and audit fields.
            with db_connect() as conn:
                conn.execute(
                    """UPDATE alerts SET grounding_score=?, kb_id=?, mitre_id=?,
                       retrieval_status=?, llm_status=?, llm_model_used=?,
                       report_latency=?, latency=?, llm_reasoning=?, raw_data=?,
                       audit_trace=?,
                       llm_recommendation=?, policy_decision=?,
                       post_review_status='PENDING_ADMIN_REVIEW',
                       approval_status='POST_BLOCK_REVIEW_PENDING',
                       execution_error=COALESCE(execution_error, ?)
                       WHERE id=?""",
                    (
                        ai_data.get("grounding_score"), ai_data.get("kb_id"),
                        ai_data.get("mitre_id"), ai_data.get("retrieval_status"),
                        ai_data.get("llm_status"), ai_data.get("llm_model"),
                        report_latency, report_latency,
                        ai_data.get("impact_assessment")
                        or ai_data.get("nhan_dinh", ""),
                        json.dumps(payload, ensure_ascii=False),
                        post_audit,
                        ai_data.get("recommended_admin_action"),
                        ai_data.get("containment_assessment"),
                        llm_error, incident_id,
                    ),
                )

            pdf = export_pdf(
                incident_id, ai_data, str(row["execution_status"]),
                str(row["audit_trace"]), event, str(row["playbook"]),
            )
            with db_connect() as conn:
                conn.execute(
                    "UPDATE alerts SET pdf_file=? WHERE id=?",
                    (pdf, incident_id),
                )
            send_post_block_review_request(
                incident_id,
                event,
                ai_data,
            )
            if pdf:
                send_pdf(pdf, f"Báo cáo tham mưu sau chặn INC-{incident_id}")
        except Exception as exc:
            print(f"[-] High report worker: {exc}")
            traceback.print_exc()
        finally:
            REPORT_QUEUE.task_done()


def send_post_block_review_request(
    incident_id: int,
    event: NormalizedEvent,
    ai_data: dict[str, Any],
) -> None:
    """Gửi ba lựa chọn hậu kiểm; LLM không tự thực thi."""
    markup = {
        "inline_keyboard": [
            [
                {
                    "text": "Giữ chặn đến TTL",
                    "callback_data": f"postkeep:{incident_id}",
                }
            ],
            [
                {
                    "text": "Giữ chặn + Watchlist",
                    "callback_data": f"postwatch:{incident_id}",
                }
            ],
            [
                {
                    "text": "Rollback / Bỏ chặn",
                    "callback_data": f"postrollback:{incident_id}",
                }
            ],
        ]
    }
    notify_telegram(
        f"<b>LLM THAM MƯU SAU CHẶN</b>\n"
        f"INC-{incident_id}\n"
        f"IP: <code>{event.src_ip}</code>\n"
        f"Đánh giá: <b>{ai_data.get('containment_assessment')}</b>\n"
        f"Khuyến nghị: <b>{ai_data.get('recommended_admin_action')}</b>\n"
        f"Admin quyết định cuối.",
        markup,
    )


def _regenerate_incident_pdf(incident_id: int) -> str:
    with db_connect() as conn:
        row = conn.execute(
            "SELECT * FROM alerts WHERE id=?",
            (incident_id,),
        ).fetchone()
    if not row:
        return ""
    payload = json.loads(row["raw_data"] or "{}")
    ai_data = payload.get("ai_data") or {}
    event = row_to_event(row)
    pdf = export_pdf(
        incident_id,
        ai_data,
        str(row["execution_status"]),
        str(row["audit_trace"] or ""),
        event,
        str(row["playbook"] or "NONE"),
    )
    if pdf:
        with db_connect() as conn:
            conn.execute(
                "UPDATE alerts SET pdf_file=? WHERE id=?",
                (pdf, incident_id),
            )
    return pdf


def post_block_admin_decision(
    incident_id: int,
    action: str,
    actor: str,
) -> tuple[bool, str]:
    """Quyết định cuối của Admin sau containment mức CAO.

    KEEP_BLOCK_UNTIL_TTL:
        Giữ rule hiện tại đến TTL.
    KEEP_BLOCK_AND_WATCHLIST:
        Giữ rule hiện tại và thêm IP vào Watchlist.
    ROLLBACK_UNBLOCK:
        Gỡ rule ngay. Chỉ Admin được thực hiện.
    """
    action = action.upper().strip()
    allowed = {
        "KEEP_BLOCK_UNTIL_TTL",
        "KEEP_BLOCK_AND_WATCHLIST",
        "ROLLBACK_UNBLOCK",
    }
    if action not in allowed:
        return False, "Hành động hậu kiểm không hợp lệ."

    with db_connect() as conn:
        row = conn.execute(
            "SELECT * FROM alerts WHERE id=?",
            (incident_id,),
        ).fetchone()
    if not row:
        return False, "Không tìm thấy incident."
    if str(row["severity"]).upper() != "CAO":
        return False, "Chỉ áp dụng hậu kiểm sau chặn cho incident mức CAO."
    if str(row["post_review_status"] or "") == "ADMIN_DECIDED":
        return False, "Incident đã có quyết định hậu kiểm cuối."

    ip = str(row["ip"])
    category = str(row["category"])
    action_message = ""

    if action == "KEEP_BLOCK_UNTIL_TTL":
        action_message = "Admin giữ rule chặn hiện tại đến hết TTL."
    elif action == "KEEP_BLOCK_AND_WATCHLIST":
        strikes, escalated, watch_audit = update_watchlist(ip, category)
        action_message = (
            f"Admin giữ rule đến TTL và thêm IP vào Watchlist; "
            f"strike={strikes}; escalated={int(escalated)}. {watch_audit}"
        )
    else:
        ok, message = rollback_firewall_rule(ip, actor)
        if not ok:
            return False, message
        action_message = message

    now = utc_now_iso()
    with db_connect() as conn:
        current = conn.execute(
            "SELECT * FROM alerts WHERE id=?",
            (incident_id,),
        ).fetchone()
        payload = json.loads(current["raw_data"] or "{}")
        ai_data = payload.setdefault("ai_data", {})
        ai_data.update({
            "admin_review_status": "ADMIN_DECIDED",
            "admin_final_action": action,
            "admin_final_action_by": actor,
            "admin_final_action_at": now,
        })
        payload.setdefault("lifecycle", {}).update({
            "post_block_review_status": "ADMIN_DECIDED",
            "admin_final_action": action,
            "transitioned_at": now,
        })
        previous_audit = str(current["audit_trace"] or "")
        audit = (
            f"{previous_audit} | POST_BLOCK_ADMIN_DECISION: "
            f"action={action}; actor={actor}; {action_message}"
        )
        conn.execute(
            """UPDATE alerts SET
                 post_review_status='ADMIN_DECIDED',
                 post_review_action=?,
                 post_review_by=?,
                 post_review_at=?,
                 approval_status='POST_BLOCK_ADMIN_DECIDED',
                 approved_by=?,
                 approved_at=?,
                 audit_trace=?,
                 raw_data=?
               WHERE id=?""",
            (
                action,
                actor,
                now,
                actor,
                now,
                audit,
                json.dumps(payload, ensure_ascii=False),
                incident_id,
            ),
        )

    audit_control_event(
        "POST_BLOCK_ADMIN_DECISION",
        ip,
        actor,
        f"incident={incident_id}; action={action}; {action_message}",
    )
    _regenerate_incident_pdf(incident_id)
    return True, action_message



def manual_decision(incident_id: int, action_type: str, actor: str) -> tuple[bool, str]:
    """Xử lý HITL và tái kiểm tra Whitelist trước khi thực thi.

    Giá trị bool biểu thị yêu cầu đã được hệ thống xử lý hợp lệ; trạng thái
    thực thi cuối cùng được lưu riêng trong alerts.execution_status.
    """
    action_type = action_type.upper()
    if action_type not in {"APPROVE", "REJECT"}:
        return False, "Hành động không hợp lệ"

    whitelist_skip_audit: Optional[str] = None
    rejected_ip: Optional[str] = None

    with db_connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM alerts WHERE id=?", (incident_id,)
        ).fetchone()
        if not row:
            return False, "Không tìm thấy incident"
        if row["execution_status"] != "PENDING":
            return False, (
                f"Incident không còn PENDING ({row['execution_status']})"
            )

        ip = str(row["ip"])
        if action_type == "REJECT":
            conn.execute(
                """UPDATE alerts SET
                   execution_status='REJECTED',
                   approval_status='REJECTED',
                   approved_by=?, approved_at=?,
                   action='TỪ CHỐI PHẢN ỨNG',
                   audit_trace=
                       COALESCE(
                           NULLIF(audit_trace, '') || CHAR(10),
                           ''
                       ) ||
                       'Quản trị viên từ chối thực thi Playbook.',
                   execution_finished_at=?
                   WHERE id=?""",
                (actor, utc_now_iso(), utc_now_iso(), incident_id),
            )
            payload = json.loads(row["raw_data"] or "{}")
            metrics = payload.setdefault("metrics", {})
            metrics.setdefault(
                "pre_hitl_report_latency",
                metrics.get("report_latency"),
            )
            final_report_latency = calculate_p1(
                row_to_event(row).timestamp
            )
            metrics["final_authorization_latency"] = final_report_latency
            metrics["final_report_latency"] = final_report_latency
            metrics["report_latency"] = final_report_latency
            metrics["report_measurement_note"] = (
                "MEDIUM REJECT: pre_hitl_report_latency đo phân tích trước "
                "HITL; final_report_latency đo tới quyết định Reject."
            )
            payload.setdefault("lifecycle", {}).update({
                "state": "REJECTED",
                "approval_status": "REJECTED",
                "transitioned_at": utc_now_iso(),
            })
            payload.setdefault("decision_provenance", {}).update({
                "authorization_source": "ADMIN",
                "execution_source": "NOT_EXECUTED",
            })
            conn.execute(
                """UPDATE alerts
                   SET raw_data=?, report_latency=?
                   WHERE id=?""",
                (
                    json.dumps(payload, ensure_ascii=False),
                    final_report_latency,
                    incident_id,
                ),
            )
            rejected_ip = ip
        else:
            # Gate #2 dùng chính transaction này để tránh race condition.
            whitelist_rows = conn.execute(
                """SELECT * FROM whitelist
                   WHERE COALESCE(status,'ACTIVE')='ACTIVE'
                   ORDER BY CASE WHEN target_type='IP' THEN 0 ELSE 1 END, id"""
            ).fetchall()
            whitelist = find_whitelist_match_in_rows(ip, whitelist_rows)
            if whitelist:
                conn.execute(
                    """UPDATE whitelist SET
                         match_count=COALESCE(match_count,0)+1,
                         last_match_at=?, updated_at=?
                       WHERE id=?""",
                    (utc_now_iso(), utc_now_iso(), int(whitelist["id"])),
                )
                reason = str(
                    whitelist["description"] or "Không có mô tả"
                )
                whitelist_skip_audit = (
                    "Admin Approve nhưng Whitelist Gate #2 MATCHED; "
                    f"không thực thi Playbook. Lý do: {reason}"
                )
                payload = json.loads(row["raw_data"] or "{}")
                ai_data = payload.setdefault("ai_data", {})
                ai_data["whitelist_precheck"] = ai_data.get(
                    "whitelist_precheck", "NOT_MATCHED"
                )
                ai_data["whitelist_execution_recheck"] = "MATCHED"
                ai_data["whitelist_reason"] = reason
                ai_data["whitelist_matched_target"] = (
                    whitelist.get("matched_target") or whitelist.get("ip")
                )
                ai_data["whitelist_target_type"] = (
                    whitelist.get("target_type") or "IP"
                )
                ai_data["whitelist_created_by"] = (
                    whitelist["created_by"]
                    if "created_by" in whitelist.keys()
                    else "N/A"
                )
                ai_data["whitelist_created_at"] = (
                    whitelist["created_at"]
                    if "created_at" in whitelist.keys()
                    else "N/A"
                )
                metrics = payload.setdefault("metrics", {})
                metrics.setdefault(
                    "pre_hitl_report_latency",
                    metrics.get("report_latency"),
                )
                final_report_latency = calculate_p1(
                    row_to_event(row).timestamp
                )
                metrics["final_authorization_latency"] = (
                    final_report_latency
                )
                metrics["final_report_latency"] = final_report_latency
                metrics["report_latency"] = final_report_latency
                metrics["report_measurement_note"] = (
                    "Whitelist Gate #2: final_report_latency đo tới lúc "
                    "safe exclusion được xác nhận sau HITL."
                )
                payload.setdefault("lifecycle", {}).update({
                    "state": "SKIPPED_WHITELIST",
                    "approval_status": "BYPASSED_WHITELIST",
                    "transitioned_at": utc_now_iso(),
                })
                payload.setdefault("decision_provenance", {}).update({
                    "authorization_source": "WHITELIST_POLICY_AFTER_ADMIN",
                    "execution_source": "NOT_EXECUTED",
                })
                conn.execute(
                    """UPDATE alerts SET
                       execution_status='SKIPPED_WHITELIST',
                       approval_status='BYPASSED_WHITELIST',
                       approved_by=?, approved_at=?,
                       action='SAFE_EXCLUSION - KHÔNG THỰC THI',
                       audit_trace=
                           COALESCE(
                               NULLIF(audit_trace, '') || CHAR(10),
                               ''
                           ) || ?,
                       execution_finished_at=?,
                       report_latency=?, raw_data=?
                       WHERE id=?""",
                    (
                        actor,
                        utc_now_iso(),
                        whitelist_skip_audit,
                        utc_now_iso(),
                        final_report_latency,
                        json.dumps(payload, ensure_ascii=False),
                        incident_id,
                    ),
                )
            else:
                payload = json.loads(row["raw_data"] or "{}")
                payload.setdefault("lifecycle", {}).update({
                    "state": "EXECUTING",
                    "approval_status": "APPROVED",
                    "transitioned_at": utc_now_iso(),
                })
                payload.setdefault("decision_provenance", {}).update({
                    "authorization_source": "ADMIN",
                    "execution_source": "RESPONSE_ENGINE",
                })
                now_approved = utc_now_iso()
                conn.execute(
                    """UPDATE alerts SET
                       execution_status='EXECUTING',
                       approval_status='APPROVED',
                       approved_by=?, approved_at=?,
                       execution_started_at=?, raw_data=?
                       WHERE id=?""",
                    (
                        actor, now_approved, now_approved,
                        json.dumps(payload, ensure_ascii=False), incident_id,
                    ),
                )

    if rejected_ip is not None:
        audit_control_event(
            "HITL_REJECT", rejected_ip, actor, f"INC-{incident_id}"
        )
        return True, "Đã từ chối incident"

    if whitelist_skip_audit is not None:
        with db_connect() as conn:
            row = conn.execute(
                "SELECT * FROM alerts WHERE id=?", (incident_id,)
            ).fetchone()
        assert row is not None
        audit_control_event(
            "WHITELIST_GATE_BLOCKED_HITL_APPROVE",
            str(row["ip"]),
            actor,
            f"INC-{incident_id}; {whitelist_skip_audit}",
        )
        event = row_to_event(row)
        payload = json.loads(row["raw_data"] or "{}")
        ai_data = payload.get("ai_data", {})
        pdf = export_pdf(
            incident_id,
            ai_data,
            "SKIPPED_WHITELIST",
            whitelist_skip_audit,
            event,
            str(row["playbook"]),
        )
        with db_connect() as conn:
            conn.execute(
                "UPDATE alerts SET pdf_file=? WHERE id=?",
                (pdf, incident_id),
            )
        return True, whitelist_skip_audit

    with db_connect() as conn:
        row = conn.execute(
            "SELECT * FROM alerts WHERE id=?", (incident_id,)
        ).fetchone()
    assert row is not None

    started = time.perf_counter()
    status, audit, rule_id = execute_playbook(
        str(row["playbook"]), str(row["ip"]), str(row["category"])
    )
    p3 = round(time.perf_counter() - started, 3)
    if status in {"SUCCESS", "DRY_RUN_SUCCESS"}:
        final_status = status
    elif status == "SKIPPED_WHITELIST":
        final_status = "SKIPPED_WHITELIST"
    elif status == "SAFETY_HOLD":
        final_status = "SAFETY_HOLD"
    else:
        final_status = "FAILED"

    payload = json.loads(row["raw_data"] or "{}")
    metrics = payload.setdefault("metrics", {})
    now_finished = utc_now()
    try:
        incident_created = dt.datetime.fromisoformat(
            str(row["timestamp"]).replace("Z", "+00:00")
        )
        if incident_created.tzinfo is None:
            incident_created = incident_created.replace(tzinfo=UTC)
        hitl_waiting = max(
            0.0,
            (now_finished - incident_created.astimezone(UTC)).total_seconds() - p3,
        )
    except Exception:
        hitl_waiting = None
    try:
        event_time = dt.datetime.fromisoformat(
            str(row_to_event(row).timestamp).replace("Z", "+00:00")
        )
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=UTC)
        end_to_end = max(
            0.0,
            (now_finished - event_time.astimezone(UTC)).total_seconds(),
        )
    except Exception:
        end_to_end = None

    metrics.setdefault(
        "pre_hitl_report_latency",
        metrics.get("report_latency"),
    )
    metrics["p3"] = p3
    metrics["p3_after_approval"] = p3
    metrics["technical_execution_latency"] = p3
    metrics["hitl_waiting_time"] = (
        round(hitl_waiting, 3) if hitl_waiting is not None else None
    )
    metrics["response_latency"] = (
        round(end_to_end, 3) if end_to_end is not None else p3
    )
    metrics["end_to_end_post_alert_latency"] = metrics["response_latency"]
    metrics["final_authorization_latency"] = metrics["response_latency"]
    metrics["final_report_latency"] = calculate_p1(
        row_to_event(row).timestamp
    )
    metrics["report_latency"] = metrics["final_report_latency"]
    metrics["measurement_note"] = (
        "P3 là độ trễ kỹ thuật sau Admin Approve; HITL waiting time là "
        "thời gian chờ quyết định; end-to-end response là thời gian từ "
        "alert trong ES đến khi phản ứng hoàn tất. "
        "pre_hitl_report_latency là thời gian tạo phân tích trước HITL; "
        "final_report_latency là thời gian chuẩn bị báo cáo cuối."
    )
    ai_data = payload.setdefault("ai_data", {})
    ai_data["whitelist_execution_recheck"] = (
        "MATCHED"
        if final_status == "SKIPPED_WHITELIST"
        else "ERROR_FAIL_CLOSED"
        if final_status == "SAFETY_HOLD"
        else "NOT_MATCHED"
    )
    payload.setdefault("lifecycle", {}).update({
        "state": final_status,
        "approval_status": (
            "BYPASSED_WHITELIST"
            if final_status == "SKIPPED_WHITELIST"
            else "APPROVED"
        ),
        "transitioned_at": utc_now_iso(),
    })
    provenance = payload.setdefault("decision_provenance", {})
    if final_status == "SKIPPED_WHITELIST":
        provenance.update({
            "authorization_source": "WHITELIST_POLICY_AFTER_ADMIN",
            "execution_source": "NOT_EXECUTED",
        })
    elif final_status == "SAFETY_HOLD":
        provenance.update({
            "authorization_source": "SAFETY_POLICY",
            "execution_source": "NOT_EXECUTED",
        })
    else:
        provenance.update({
            "authorization_source": "ADMIN",
            "execution_source": "RESPONSE_ENGINE",
        })
    payload["approved_by"] = actor

    with db_connect() as conn:
        conn.execute(
            """UPDATE alerts SET
               execution_status=?, action=?,
               audit_trace=
                   COALESCE(
                       NULLIF(audit_trace, '') || CHAR(10),
                       ''
                   ) || ?,
               firewall_rule_id=?, execution_finished_at=?,
               execution_error=?, response_latency=?, report_latency=?,
               raw_data=?
               WHERE id=?""",
            (
                final_status,
                (
                    "SAFE_EXCLUSION - KHÔNG THỰC THI"
                    if final_status == "SKIPPED_WHITELIST"
                    else "SAFETY_HOLD - KHÔNG THỰC THI"
                    if final_status == "SAFETY_HOLD"
                    else f"{row['playbook']}: ĐÃ DUYỆT"
                ),
                audit,
                rule_id,
                utc_now_iso(),
                None if final_status in {
                      "SUCCESS",
                      "DRY_RUN_SUCCESS",
                      "SKIPPED_WHITELIST",
                      "SAFETY_HOLD",
                  } else audit,
                metrics.get("response_latency"),
                metrics.get("final_report_latency"),
                json.dumps(payload, ensure_ascii=False),
                incident_id,
            ),
        )

    with db_connect() as conn:
        row = conn.execute(
            "SELECT * FROM alerts WHERE id=?", (incident_id,)
        ).fetchone()
    assert row is not None
    event = row_to_event(row)
    ai_data = json.loads(row["raw_data"] or "{}").get("ai_data", {})
    pdf = export_pdf(
        incident_id,
        ai_data,
        final_status,
        audit,
        event,
        str(row["playbook"]),
    )
    with db_connect() as conn:
        conn.execute(
            "UPDATE alerts SET pdf_file=? WHERE id=?",
            (pdf, incident_id),
        )

    if final_status == "SUCCESS":
        audit_control_event(
            "HITL_APPROVE_EXECUTED",
            event.src_ip,
            actor,
            f"INC-{incident_id}; playbook={row['playbook']}",
        )
        notify_telegram(
            f"✅ <b>INC-{incident_id} ĐÃ THỰC THI</b>\n"
            f"📍 <code>{event.src_ip}</code>\n"
            f"🛠 {row['playbook']}"
        )
        send_pdf(pdf, f"✅ Báo cáo sau phê duyệt INC-{incident_id}")
    elif final_status == "DRY_RUN_SUCCESS":
        audit_control_event(
            "HITL_APPROVE_DRY_RUN",
            event.src_ip,
            actor,
            (
                f"INC-{incident_id}; playbook={row['playbook']}; "
                "không thay đổi Firewall"
            ),
        )
        notify_telegram(
            f"<b>INC-{incident_id} ĐÃ DUYỆT Ở CHẾ ĐỘ DRY-RUN</b>\n"
            f"IP: <code>{event.src_ip}</code>\n"
            f"Playbook: {row['playbook']}\n"
            "Firewall không bị thay đổi."
        )
        send_pdf(
            pdf,
            f"Báo cáo DRY-RUN sau phê duyệt INC-{incident_id}",
        )
    elif final_status == "SKIPPED_WHITELIST":
        audit_control_event(
            "WHITELIST_GATE_BLOCKED_PLAYBOOK",
            event.src_ip,
            actor,
            f"INC-{incident_id}; {audit}",
        )
    elif final_status == "SAFETY_HOLD":
        audit_control_event(
            "SAFETY_HOLD_RESPONSE",
            event.src_ip,
            actor,
            f"INC-{incident_id}; {audit}",
        )

    # Boolean biểu thị quyết định hợp lệ đã được Core tiếp nhận.
    # Kết quả kỹ thuật nằm riêng trong alerts.execution_status.
    return True, audit


# ---------------------------------------------------------------------
# STARTUP RECOVERY FOR STALE EXECUTING INCIDENTS
# ---------------------------------------------------------------------

def _recovery_rule_definition(
    playbook: str,
    ip_text: str,
) -> tuple[str, list[str], str, int]:
    """Trả về chain, rule args, loại rule và TTL theo Playbook."""
    ip = str(ipaddress.ip_address(ip_text))
    normalized_playbook = str(playbook or "").strip().upper()

    if normalized_playbook in {"PLAYBOOK_1", "PLAYBOOK_3"}:
        return (
            "SOAR_BLOCK",
            ["-s", ip, "-j", "DROP"],
            "BLOCK",
            Config.BLOCK_TTL_SECONDS,
        )

    if normalized_playbook == "PLAYBOOK_2":
        return (
            "SOAR_RATE",
            [
                "-p",
                "tcp",
                "--syn",
                "-s",
                ip,
                "-m",
                "connlimit",
                "--connlimit-above",
                "5",
                "-j",
                "REJECT",
                "--reject-with",
                "tcp-reset",
            ],
            "RATE_LIMIT",
            Config.RATE_LIMIT_TTL_SECONDS,
        )

    raise ValueError(
        f"{normalized_playbook or 'UNKNOWN'} không có rule Firewall "
        "để phục hồi."
    )


def verify_firewall_rule_for_recovery(
    ip_text: str,
    playbook: str,
) -> dict[str, Any]:
    """Đối soát rule LIVE mà không tạo, xóa hoặc chạy lại Playbook."""
    try:
        ip = str(ipaddress.ip_address(ip_text))
        chain, args, rule_kind, ttl = _recovery_rule_definition(
            playbook,
            ip,
        )
    except ValueError as exc:
        return {
            "exists": False,
            "target": None,
            "chain": None,
            "args": [],
            "rule_kind": None,
            "ttl": None,
            "details": str(exc),
        }

    if not Config.ENABLE_NETWORK_ENFORCEMENT:
        return {
            "exists": False,
            "target": None,
            "chain": chain,
            "args": args,
            "rule_kind": rule_kind,
            "ttl": ttl,
            "details": (
                "Core khởi động ở DRY-RUN; không thể xác minh "
                "side effect Firewall của incident EXECUTING."
            ),
        }

    targets: list[str] = []

    # Ưu tiên target đã được SQLite ghi nhận, sau đó mới thử các target
    # cấu hình. Không tin SQLite là bằng chứng rule tồn tại.
    try:
        with db_connect() as conn:
            row = conn.execute(
                """SELECT rule_target
                   FROM blocked_ips
                   WHERE ip=?
                     AND COALESCE(status, 'ACTIVE')
                         IN ('ACTIVE', 'BLOCKED')
                   LIMIT 1""",
                (ip,),
            ).fetchone()

        if row and row["rule_target"]:
            targets.append(str(row["rule_target"]))
    except sqlite3.Error:
        pass

    targets.extend(firewall_targets())

    unique_targets: list[str] = []
    for target in targets:
        if target and target not in unique_targets:
            unique_targets.append(target)

    observations: list[str] = []

    for target in unique_targets:
        try:
            command_prefix = prefix(target)

            jump_result = run_cmd(
                command_prefix
                + [
                    "-C",
                    Config.IPTABLES_PARENT_CHAIN,
                    "-j",
                    chain,
                ],
                check=False,
            )

            rule_result = run_cmd(
                command_prefix + ["-C", chain] + args,
                check=False,
            )

            if (
                jump_result.returncode == 0
                and rule_result.returncode == 0
            ):
                return {
                    "exists": True,
                    "target": target,
                    "chain": chain,
                    "args": args,
                    "rule_kind": rule_kind,
                    "ttl": ttl,
                    "details": (
                        f"Đã xác minh jump "
                        f"{Config.IPTABLES_PARENT_CHAIN}->{chain} "
                        f"và rule LIVE cho {ip} tại {target}."
                    ),
                }

            observations.append(
                f"{target}: jump_rc={jump_result.returncode}; "
                f"rule_rc={rule_result.returncode}"
            )
        except Exception as exc:
            observations.append(f"{target}: {type(exc).__name__}: {exc}")

    return {
        "exists": False,
        "target": None,
        "chain": chain,
        "args": args,
        "rule_kind": rule_kind,
        "ttl": ttl,
        "details": (
            "Không xác minh được rule Firewall LIVE. "
            + " | ".join(observations)
        )[:1500],
    }


def _record_recovered_rule_metadata(
    ip: str,
    category: str,
    verification: dict[str, Any],
) -> None:
    """Phục hồi metadata quản lý rule mà không chạy lại Playbook."""
    target = str(verification["target"])
    chain = str(verification["chain"])
    rule_kind = str(verification["rule_kind"])
    args = list(verification["args"])
    ttl = int(verification["ttl"])
    now = utc_now_iso()
    expires_at = (
        utc_now() + dt.timedelta(seconds=ttl)
    ).isoformat(timespec="seconds").replace("+00:00", "Z")
    rule_spec = f"-A {chain} {' '.join(args)}"

    with db_connect() as conn:
        columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(blocked_ips)"
            ).fetchall()
        }

        existing = conn.execute(
            "SELECT id FROM blocked_ips WHERE ip=?",
            (ip,),
        ).fetchone()

        if existing:
            values: dict[str, Any] = {
                "status": "ACTIVE",
                "rule_target": target,
                "rule_kind": rule_kind,
                "chain_name": chain,
                "rule_spec": rule_spec,
                "last_verified_at": now,
                "verification_status": "LIVE",
            }

            usable = {
                key: value
                for key, value in values.items()
                if key in columns
            }

            assignments = ", ".join(
                f"{key}=?" for key in usable
            )

            conn.execute(
                f"UPDATE blocked_ips SET {assignments} WHERE ip=?",
                (*usable.values(), ip),
            )
            return

        values = {
            "ip": ip,
            "category": category,
            "blocked_at": now,
            "expires_at": expires_at,
            "status": "ACTIVE",
            "rule_target": target,
            "rule_kind": rule_kind,
            "chain_name": chain,
            "rule_spec": rule_spec,
            "last_verified_at": now,
            "verification_status": "LIVE",
        }

        usable = {
            key: value
            for key, value in values.items()
            if key in columns
        }

        names = list(usable)
        placeholders = ",".join("?" for _ in names)

        conn.execute(
            f"""INSERT INTO blocked_ips ({','.join(names)})
                VALUES ({placeholders})""",
            tuple(usable[name] for name in names),
        )


def recover_stale_executing_incidents() -> dict[str, int]:
    """Đối soát incident EXECUTING khi Core khởi động.

    Không gọi execute_playbook() trong hàm này. Rule LIVE được xác minh
    trực tiếp bằng iptables -C. Không xác minh được thì fail-closed sang
    SAFETY_HOLD để tránh thực thi lặp.
    """
    summary = {
        "found": 0,
        "success": 0,
        "safety_hold": 0,
        "update_conflict": 0,
    }

    with db_connect() as conn:
        incidents = conn.execute(
            """SELECT id, ip, category, playbook,
                      firewall_rule_id, execution_started_at
               FROM alerts
               WHERE execution_status='EXECUTING'
               ORDER BY id"""
        ).fetchall()

    summary["found"] = len(incidents)

    if not incidents:
        print("[RECOVERY] Không có incident bị kẹt EXECUTING.")
        return summary

    for incident in incidents:
        incident_id = int(incident["id"])
        ip = str(incident["ip"])
        category = str(incident["category"] or "UNKNOWN")
        playbook = str(incident["playbook"] or "")

        verification = verify_firewall_rule_for_recovery(
            ip,
            playbook,
        )

        if verification["exists"]:
            final_status = "SUCCESS"
            execution_error = None
            action = "STARTUP_RECOVERY - RULE VERIFIED"
            recovered_rule_id = (
                f"{verification['target']}:"
                f"{verification['chain']}:{ip}"
            )
            audit_message = (
                "Startup recovery: incident từng ở EXECUTING; "
                f"{verification['details']} "
                "Core không thực thi lại Playbook."
            )
        else:
            final_status = "SAFETY_HOLD"
            action = "SAFETY_HOLD - STARTUP RECOVERY"
            recovered_rule_id = None
            execution_error = (
                "Core khởi động lại khi incident đang EXECUTING; "
                f"{verification['details']} "
                "Playbook không được thực thi lại."
            )
            audit_message = (
                "Startup recovery chuyển SAFETY_HOLD: "
                f"{verification['details']} "
                "Core không thực thi lại Playbook."
            )

        with db_connect() as conn:
            cursor = conn.execute(
                """UPDATE alerts SET
                     execution_status=?,
                     action=?,
                     execution_finished_at=?,
                     execution_error=?,
                     firewall_rule_id=
                         CASE
                             WHEN ? IS NOT NULL THEN ?
                             ELSE firewall_rule_id
                         END,
                     audit_trace=
                         COALESCE(
                             NULLIF(audit_trace, '') || CHAR(10),
                             ''
                         ) || ?
                   WHERE id=?
                     AND execution_status='EXECUTING'""",
                (
                    final_status,
                    action,
                    utc_now_iso(),
                    execution_error,
                    recovered_rule_id,
                    recovered_rule_id,
                    audit_message,
                    incident_id,
                ),
            )

        if cursor.rowcount != 1:
            summary["update_conflict"] += 1
            print(
                f"[RECOVERY] INC-{incident_id}: bỏ qua vì trạng thái "
                "đã được tiến trình khác thay đổi."
            )
            continue

        if final_status == "SUCCESS":
            summary["success"] += 1
            try:
                _record_recovered_rule_metadata(
                    ip,
                    category,
                    verification,
                )
            except Exception as exc:
                print(
                    f"[RECOVERY] INC-{incident_id}: "
                    f"không cập nhật được metadata rule: {exc}"
                )
        else:
            summary["safety_hold"] += 1

        audit_control_event(
            (
                "STARTUP_RECOVERY_SUCCESS"
                if final_status == "SUCCESS"
                else "STARTUP_RECOVERY_SAFETY_HOLD"
            ),
            ip,
            "soar-core-startup",
            (
                f"INC-{incident_id}; playbook={playbook}; "
                f"final_status={final_status}; "
                f"{verification['details']}"
            ),
        )

        print(
            f"[RECOVERY] INC-{incident_id}: "
            f"EXECUTING -> {final_status}; "
            f"{verification['details']}"
        )

        try:
            _regenerate_incident_pdf(incident_id)
        except Exception as exc:
            print(
                f"[RECOVERY] INC-{incident_id}: "
                f"không tái tạo được PDF: {exc}"
            )

    print(
        "[RECOVERY] Tổng kết: "
        f"found={summary['found']}; "
        f"success={summary['success']}; "
        f"safety_hold={summary['safety_hold']}; "
        f"conflict={summary['update_conflict']}"
    )
    return summary



# ---------------------------------------------------------------------
# ELASTICSEARCH + DURABLE QUEUE
# ---------------------------------------------------------------------

ES = Elasticsearch(Config.ES_URL)
MEM_QUEUE: queue.Queue[int] = queue.Queue(maxsize=Config.EVENT_QUEUE_SIZE)



def is_context_only_document(source: dict[str, Any]) -> bool:
    """Document chỉ dùng làm bằng chứng hậu phân tích, không tạo incident."""
    raw = nested_get(source, "labels.soar_context_only")
    if isinstance(raw, bool):
        return raw
    text = str(raw or "").strip().lower()
    return text in {"1", "true", "yes", "y", "on"}



def insert_queue(es_id: str, payload: dict[str, Any]) -> bool:
    """Trả về True chỉ khi document mới thực sự được thêm vào durable queue."""
    now = utc_now_iso()
    with db_connect() as conn:
        cursor = conn.execute(
            """INSERT OR IGNORE INTO event_queue
               (es_id, payload, status, retry_count, created_at, updated_at)
               VALUES (?, ?, 'NEW', 0, ?, ?)""",
            (es_id, json.dumps(payload, ensure_ascii=False), now, now),
        )
        return cursor.rowcount == 1


def checkpoint_with_lookback(timestamp_text: str) -> str:
    """Lùi checkpoint một khoảng nhỏ để không bỏ sót document đến trễ.

    event_queue.es_id UNIQUE loại bỏ các document bị quét lặp.
    """
    try:
        value = dt.datetime.fromisoformat(timestamp_text.replace("Z", "+00:00"))
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        value -= dt.timedelta(seconds=max(Config.ES_LOOKBACK_SECONDS, 0))
        return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except ValueError:
        return "1970-01-01T00:00:00.000Z"


def ingest_es_once() -> int:
    checkpoint_name = f"es_last_timestamp:{Config.INDEX_NAME}"
    checkpoint_ts = get_checkpoint(checkpoint_name, "1970-01-01T00:00:00.000Z")
    last_ts = checkpoint_with_lookback(checkpoint_ts)
    pit_id: Optional[str] = None
    search_after: Optional[list[Any]] = None
    max_ts, count = checkpoint_ts, 0
    try:
        pit_id = ES.open_point_in_time(index=Config.INDEX_NAME, keep_alive="1m")["id"]
        while True:
            body: dict[str, Any] = {
                "size": Config.ES_BATCH_SIZE,
                "pit": {"id": pit_id, "keep_alive": "1m"},
                "query": {"range": {"@timestamp": {"gte": last_ts}}},
                "sort": [{"@timestamp": {"order": "asc"}}, {"_shard_doc": {"order": "asc"}}],
                "track_total_hits": False,
            }
            if search_after is not None:
                body["search_after"] = search_after
            response = ES.search(body=body)
            hits = response.get("hits", {}).get("hits", [])
            if not hits:
                break
            for hit in hits:
                source = dict(hit.get("_source") or {})
                if not is_context_only_document(source):
                    if insert_queue(str(hit["_id"]), source):
                        count += 1
                ts = str(source.get("@timestamp") or max_ts)
                if ts > max_ts:
                    max_ts = ts
            search_after = list(hits[-1]["sort"])
        set_checkpoint(checkpoint_name, max_ts)
        return count
    finally:
        if pit_id:
            try:
                ES.close_point_in_time(id=pit_id)
            except Exception:
                pass


def dispatcher_loop() -> None:
    while True:
        try:
            capacity = Config.EVENT_QUEUE_SIZE - MEM_QUEUE.qsize()
            if capacity > 0:
                with db_connect() as conn:
                    rows = conn.execute(
                        "SELECT id FROM event_queue WHERE status IN ('NEW','RETRY') ORDER BY id LIMIT ?",
                        (min(capacity, 100),),
                    ).fetchall()
                for row in rows:
                    qid = int(row["id"])
                    # Chuyển trạng thái trước khi đưa vào RAM queue để tránh race
                    # worker ghi DONE rồi dispatcher ghi đè lại ENQUEUED.
                    with db_connect() as conn:
                        cursor = conn.execute(
                            """UPDATE event_queue
                               SET status='ENQUEUED', updated_at=?
                               WHERE id=? AND status IN ('NEW','RETRY')""",
                            (utc_now_iso(), qid),
                        )
                    if cursor.rowcount != 1:
                        continue
                    try:
                        MEM_QUEUE.put_nowait(qid)
                    except queue.Full:
                        with db_connect() as conn:
                            conn.execute(
                                "UPDATE event_queue SET status='NEW', updated_at=? WHERE id=? AND status='ENQUEUED'",
                                (utc_now_iso(), qid),
                            )
                        break
        except Exception as exc:
            print(f"[-] Dispatcher: {exc}")
        time.sleep(0.5)


def worker_loop(name: str) -> None:
    while True:
        qid = MEM_QUEUE.get()
        try:
            with db_connect() as conn:
                conn.execute("UPDATE event_queue SET status='PROCESSING', updated_at=? WHERE id=?", (utc_now_iso(), qid))
                row = conn.execute("SELECT * FROM event_queue WHERE id=?", (qid,)).fetchone()
            if not row:
                continue
            event = normalize_event(str(row["es_id"]), json.loads(row["payload"]))
            with db_connect() as conn:
                exists = conn.execute("SELECT 1 FROM alerts WHERE es_id=?", (event.es_id,)).fetchone()
            if event.category == "NORMAL":
                # Kết thúc hợp lệ: không gọi Rule Engine, HITL hay Response Engine.
                with db_connect() as conn:
                    conn.execute(
                        "UPDATE event_queue "
                        "SET status='NO_ACTION', last_error=NULL, updated_at=? "
                        "WHERE id=? AND status='PROCESSING'",
                        (utc_now_iso(), qid),
                    )
                print(f"[+] {name}: {event.es_id} | NORMAL -> NO_ACTION")
                continue

            if not exists:
                process_event(event)
            with db_connect() as conn:
                conn.execute("UPDATE event_queue SET status='DONE', last_error=NULL, updated_at=? WHERE id=?", (utc_now_iso(), qid))
            print(f"[+] {name}: {event.es_id} | {event.category} | {event.src_ip}")
        except Exception as exc:
            traceback.print_exc()
            with db_connect() as conn:
                row = conn.execute("SELECT retry_count FROM event_queue WHERE id=?", (qid,)).fetchone()
                retries = int(row["retry_count"] if row else 0) + 1
                status = "DEAD" if isinstance(exc, ValidationError) or retries >= Config.MAX_RETRY else "RETRY"
                conn.execute(
                    "UPDATE event_queue SET status=?, retry_count=?, last_error=?, updated_at=? WHERE id=?",
                    (status, retries, f"{type(exc).__name__}: {exc}", utc_now_iso(), qid),
                )
            print(f"[-] {name}: queue={qid} -> {status}: {exc}")
        finally:
            MEM_QUEUE.task_done()


# ---------------------------------------------------------------------
# API + TELEGRAM CALLBACK
# ---------------------------------------------------------------------

class APIHandler(BaseHTTPRequestHandler):
    def log_message(self, format_string: str, *args: Any) -> None:
        print(f"[API] {self.address_string()} - {format_string % args}")

    def send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def is_local_client(self) -> bool:
        host = str(self.client_address[0] if self.client_address else "")
        return host in {"127.0.0.1", "::1", "localhost"}

    def authenticated(self) -> bool:
        if Config.LAB_API_NO_AUTH and self.is_local_client():
            return True
        supplied = self.headers.get("X-API-Key", "")
        return bool(Config.API_KEY) and hmac.compare_digest(
            supplied,
            Config.API_KEY,
        )

    def do_GET(self) -> None:
        if self.path == "/health":
            try:
                es_ok = bool(ES.ping())
            except Exception:
                es_ok = False
            with db_connect() as conn:
                queue_counts = {row["status"]: row["n"] for row in conn.execute(
                    "SELECT status, COUNT(*) AS n FROM event_queue GROUP BY status"
                )}
                alert_count = int(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])
            self.send_json(200 if es_ok else 503, {
                "status": "ok" if es_ok else "degraded",
                "elasticsearch": es_ok,
                "firewall_mode": "ENABLED" if Config.ENABLE_NETWORK_ENFORCEMENT else "DRY_RUN",
                "queue": queue_counts,
                "alerts": alert_count,
            })
            return

        if self.path == "/metrics":
            if not self.authenticated():
                self.send_json(403, {"status": "error", "message": "Forbidden"})
                return
            with db_connect() as conn:
                queue_counts = {row["status"]: row["n"] for row in conn.execute(
                    "SELECT status, COUNT(*) AS n FROM event_queue GROUP BY status"
                )}
                branches = {row["severity"]: row["n"] for row in conn.execute(
                    "SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity"
                )}
                duplicates = int(conn.execute(
                    "SELECT COUNT(*) FROM (SELECT es_id FROM alerts WHERE es_id IS NOT NULL GROUP BY es_id HAVING COUNT(*) > 1)"
                ).fetchone()[0])
            self.send_json(200, {"queue": queue_counts, "severity": branches, "duplicate_es_id": duplicates})
            return

        self.send_json(404, {"status": "error", "message": "Not found"})

    def do_POST(self) -> None:
        if not self.authenticated():
            self.send_json(403, {"status": "error", "message": "Forbidden"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 1024 * 1024:
                raise ValueError("Body không hợp lệ")
            data = json.loads(self.rfile.read(length))
            if self.path in {"/add_whitelist", "/whitelist/add"}:
                print(f"[API] WHITELIST_ADD payload={data}")
                raw_target = str(
                    data.get("target") or data.get("ip") or ""
                )
                target, target_type = normalize_whitelist_target(raw_target)
                description = str(data.get("description", "")).strip()[:250]
                actor = str(data.get("actor") or "api-user").strip()[:120]
                if not description:
                    description = "Safe exclusion do quản trị viên cấu hình."
                now = utc_now_iso()

                with db_connect() as conn:
                    conn.execute(
                        """INSERT INTO whitelist
                           (ip, description, target_type, created_at, created_by,
                            updated_at, disabled_at, disabled_by,
                            last_match_at, match_count, status)
                           VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL, 0, 'ACTIVE')
                           ON CONFLICT(ip) DO UPDATE SET
                             description=excluded.description,
                             target_type=excluded.target_type,
                             created_by=excluded.created_by,
                             updated_at=excluded.updated_at,
                             disabled_at=NULL,
                             disabled_by=NULL,
                             status='ACTIVE'""",
                        (
                            target, description, target_type,
                            now, actor, now,
                        ),
                    )

                    watch_rows = conn.execute(
                        """SELECT id, ip FROM watchlist
                           WHERE COALESCE(status,'ACTIVE')='ACTIVE'"""
                    ).fetchall()
                    watch_ids: list[int] = []
                    for item in watch_rows:
                        try:
                            if whitelist_target_matches(str(item["ip"]), target):
                                watch_ids.append(int(item["id"]))
                        except ValueError:
                            continue
                    for watch_id in watch_ids:
                        conn.execute(
                            "UPDATE watchlist SET status='WHITELISTED' WHERE id=?",
                            (watch_id,),
                        )

                rollback_messages: list[str] = []
                rollback_count = 0
                with db_connect() as conn:
                    active_rules = conn.execute(
                        """SELECT ip FROM blocked_ips
                           WHERE COALESCE(status,'ACTIVE')='ACTIVE'"""
                    ).fetchall()
                for item in active_rules:
                    active_ip = str(item["ip"])
                    try:
                        matched = whitelist_target_matches(active_ip, target)
                    except ValueError:
                        matched = False
                    if matched:
                        rollback_ok, rollback_message = rollback_firewall_rule(
                            active_ip, actor=f"whitelist:{actor}"
                        )
                        rollback_messages.append(rollback_message)
                        rollback_count += int(rollback_ok)

                try:
                    audit_control_event(
                        "WHITELIST_ADD", target, actor,
                        f"type={target_type}; reason={description}; "
                        f"rollback_count={rollback_count}; "
                        f"watchlist_updated={len(watch_ids)}",
                    )
                except Exception as audit_exc:
                    # Không làm mất thao tác Whitelist đã commit chỉ vì bảng
                    # audit legacy gặp lỗi; lỗi vẫn được ghi ra terminal.
                    print(f"[!] WHITELIST_ADD audit warning: {audit_exc}")

                print(
                    f"[+] WHITELIST_ADD success target={target} "
                    f"type={target_type} actor={actor} "
                    f"rollback={rollback_count} watchlist={len(watch_ids)}"
                )
                self.send_json(
                    200,
                    {
                        "status": "success",
                        "message": (
                            f"Đã thêm {target} ({target_type}) vào Whitelist. "
                            f"Rollback {rollback_count} active rule; "
                            f"cập nhật {len(watch_ids)} Watchlist entry."
                        ),
                        "target": target,
                        "target_type": target_type,
                        "created_by": actor,
                        "rollback": {
                            "count": rollback_count,
                            "messages": rollback_messages,
                        },
                    },
                )
                return

            if self.path == "/whitelist_check":
                ip = str(ipaddress.ip_address(str(data.get("ip", ""))))
                match = get_whitelist_entry(ip, touch=False)
                self.send_json(
                    200,
                    {
                        "status": "success",
                        "ip": ip,
                        "matched": bool(match),
                        "entry": match,
                    },
                )
                return

            if self.path == "/delete_whitelist":
                item_id = int(data.get("id", 0))
                if item_id <= 0:
                    raise ValueError("Whitelist ID không hợp lệ")

                with db_connect() as conn:
                    row = conn.execute(
                        "SELECT ip FROM whitelist WHERE id=?",
                        (item_id,),
                    ).fetchone()
                    if not row:
                        self.send_json(
                            404,
                            {
                                "status": "error",
                                "message": "Không tìm thấy Whitelist item.",
                            },
                        )
                        return

                    ip = str(row["ip"])
                    actor = str(data.get("actor") or "api-user")
                    now = utc_now_iso()
                    conn.execute(
                        """UPDATE whitelist SET
                             status='INACTIVE', updated_at=?,
                             disabled_at=?, disabled_by=?
                           WHERE id=?""",
                        (now, now, actor, item_id),
                    )

                audit_control_event(
                    "WHITELIST_DISABLE",
                    ip,
                    actor,
                    f"whitelist_id={item_id}; soft_delete=1",
                )
                self.send_json(
                    200,
                    {
                        "status": "success",
                        "message": f"Đã vô hiệu hóa {ip} khỏi Whitelist và vẫn giữ audit trail.",
                        "id": item_id,
                        "ip": ip,
                    },
                )
                return

            if self.path == "/decision":
                ok, msg = manual_decision(
                    int(data["incident_id"]),
                    str(data["action"]),
                    str(data.get("actor") or "api-user"),
                )
                self.send_json(
                    200 if ok else 409,
                    {
                        "status": "success" if ok else "error",
                        "message": msg,
                    },
                )
                return
            if self.path == "/post-block-decision":
                ok, msg = post_block_admin_decision(
                    int(data["incident_id"]),
                    str(data["action"]),
                    str(data.get("actor") or "api-user"),
                )
                self.send_json(
                    200 if ok else 409,
                    {
                        "status": "success" if ok else "error",
                        "message": msg,
                    },
                )
                return
            if self.path == "/rollback":
                ok, msg = rollback_firewall_rule(
                    str(data.get("ip", "")),
                    str(data.get("actor") or "api-user"),
                )
                self.send_json(
                    200 if ok else 409,
                    {
                        "status": "success" if ok else "error",
                        "message": msg,
                    },
                )
                return
            self.send_json(404, {"status": "error", "message": "Not found"})
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            print(f"[-] API validation error path={self.path}: {exc}")
            self.send_json(400, {"status": "error", "message": str(exc)})
        except Exception as exc:
            print(f"[-] API internal error path={self.path}: {type(exc).__name__}: {exc}")
            traceback.print_exc()
            self.send_json(
                500,
                {
                    "status": "error",
                    "message": f"{type(exc).__name__}: {exc}",
                },
            )


def api_loop() -> None:
    local_binds = {"127.0.0.1", "localhost", "::1"}
    if not Config.API_KEY and Config.API_BIND not in local_binds:
        print("[!] Không khởi động API ngoài localhost khi chưa có API_KEY.")
        return
    if Config.LAB_API_NO_AUTH and Config.API_BIND in local_binds:
        print("[+] API LAB: localhost được phép thao tác không cần API key.")
    elif not Config.API_KEY:
        print("[!] API chỉ bật /health; endpoint quản trị bị khóa vì chưa có API_KEY.")
    server = ThreadingHTTPServer((Config.API_BIND, Config.API_PORT), APIHandler)
    print(f"[+] API: http://{Config.API_BIND}:{Config.API_PORT}")
    server.serve_forever()


def telegram_loop() -> None:
    if not telegram_enabled():
        print("[!] Telegram tắt vì chưa cấu hình TG_TOKEN/TG_CHAT_ID.")
        return
    offset = int(get_checkpoint("telegram_update_id", "0"))
    while True:
        try:
            result = tg_call("getUpdates", payload={"offset": offset + 1, "timeout": 20, "allowed_updates": ["callback_query"]}, timeout=25)
            if not result:
                time.sleep(2)
                continue
            for item in result.get("result", []):
                offset = int(item["update_id"])
                set_checkpoint("telegram_update_id", str(offset))
                cb = item.get("callback_query")
                if not cb:
                    continue
                chat_id = str(((cb.get("message") or {}).get("chat") or {}).get("id", ""))
                if chat_id != str(Config.TG_CHAT_ID):
                    tg_call("answerCallbackQuery", payload={"callback_query_id": cb["id"], "text": "Không được phép", "show_alert": True})
                    continue
                callback_data = str(cb.get("data") or "")
                match = re.fullmatch(
                    r"(approve|reject|postkeep|postwatch|postrollback):(\d+)",
                    callback_data,
                )
                if not match:
                    tg_call(
                        "answerCallbackQuery",
                        payload={
                            "callback_query_id": cb["id"],
                            "text": "Callback không hợp lệ",
                            "show_alert": True,
                        },
                    )
                    continue
                verb, incident = match.groups()
                if verb in {"approve", "reject"}:
                    ok, msg = manual_decision(
                        int(incident),
                        "APPROVE" if verb == "approve" else "REJECT",
                        f"telegram:{chat_id}",
                    )
                else:
                    action_map = {
                        "postkeep": "KEEP_BLOCK_UNTIL_TTL",
                        "postwatch": "KEEP_BLOCK_AND_WATCHLIST",
                        "postrollback": "ROLLBACK_UNBLOCK",
                    }
                    ok, msg = post_block_admin_decision(
                        int(incident),
                        action_map[verb],
                        f"telegram:{chat_id}",
                    )
                tg_call(
                    "answerCallbackQuery",
                    payload={
                        "callback_query_id": cb["id"],
                        "text": msg[:180],
                        "show_alert": not ok,
                    },
                )
        except Exception as exc:
            print(f"[-] Telegram loop: {exc}")
            time.sleep(3)


def main() -> None:
    init_db()
    recover_stale_executing_incidents()
    ensure_es_index()
    print("=" * 64)
    print("SOAR ORCHESTRATOR 8.0 FINAL - POST-BLOCK LLM ADVISORY FOR ADMIN")
    print(f"ES: {Config.ES_URL}/{Config.INDEX_NAME}")
    print(f"Workers: {Config.WORKER_COUNT}")
    print(f"Ollama: {Config.OLLAMA_URL} | model={Config.LLM_MODEL}")
    print(f"Static RAG: {Config.KB_PATH.name} | exact match | no vector DB")
    print(
        "Whitelist: IP/CIDR | dual gate | "
        + ("FAIL-CLOSED" if Config.WHITELIST_FAIL_CLOSED else "FAIL-OPEN")
    )
    print("Firewall: " + ("ENABLED" if Config.ENABLE_NETWORK_ENFORCEMENT else "DRY-RUN"))
    print("API auth: " + ("LOCAL LAB BYPASS" if Config.LAB_API_NO_AUTH else "API KEY"))
    print("=" * 64)

    threading.Thread(target=dispatcher_loop, daemon=True).start()
    for i in range(Config.WORKER_COUNT):
        threading.Thread(target=worker_loop, args=(f"worker-{i+1}",), daemon=True).start()
    threading.Thread(target=high_report_worker, daemon=True).start()
    threading.Thread(target=cleanup_expired_firewall_rules, daemon=True).start()
    threading.Thread(target=telegram_loop, daemon=True).start()
    threading.Thread(target=api_loop, daemon=True).start()

    while True:
        try:
            count = ingest_es_once()
            if count:
                print(f"[+] Đồng bộ {count} document vào durable queue.")
            time.sleep(Config.SCAN_INTERVAL)
        except KeyboardInterrupt:
            print("\n[+] Dừng chương trình.")
            break
        except Exception as exc:
            print(f"[-] Elasticsearch ingest: {exc}")
            time.sleep(5)


if __name__ == "__main__":
    main()
