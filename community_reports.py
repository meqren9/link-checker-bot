import hashlib
import json
import os
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from scanner import normalize_url, registered_domain


REPORT_THRESHOLD = 5
REPORTS_FILE = Path(os.getenv("COMMUNITY_REPORTS_FILE", "community_reports.json"))
_lock = threading.Lock()


def _empty_store() -> dict:
    return {"reports": {}}


def _load_store() -> dict:
    if not REPORTS_FILE.exists():
        return _empty_store()

    try:
        with REPORTS_FILE.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return _empty_store()

    if not isinstance(data, dict) or not isinstance(data.get("reports"), dict):
        return _empty_store()

    return data


def _save_store(store: dict) -> None:
    REPORTS_FILE.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=REPORTS_FILE.parent,
        delete=False,
    ) as handle:
        json.dump(store, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        temp_name = handle.name

    os.replace(temp_name, REPORTS_FILE)


def url_report_key(url: str) -> dict:
    normalized = normalize_url(url)
    parsed = urlsplit(normalized)
    hostname = parsed.hostname or ""
    domain = registered_domain(hostname)

    if domain:
        return {
            "key": f"domain:{domain}",
            "type": "domain",
            "label": domain,
        }

    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return {
        "key": f"url_hash:{digest}",
        "type": "url_hash",
        "label": digest[:12],
    }


def domain_report_key(domain: str) -> dict:
    value = (domain or "").strip().lower()
    if "://" not in value:
        value = f"https://{value}"

    parsed = urlsplit(normalize_url(value))
    hostname = (parsed.hostname or "").strip(".")
    domain_label = registered_domain(hostname)

    if not domain_label:
        return {}

    return {
        "key": f"domain:{domain_label}",
        "type": "domain",
        "label": domain_label,
    }


def reporter_hash(reporter_id: str | int | None, report_key: str = "") -> str:
    if reporter_id is None:
        return ""

    scoped_value = f"{report_key}:{reporter_id}" if report_key else str(reporter_id)
    return hashlib.sha256(scoped_value.encode("utf-8")).hexdigest()


def add_report(url: str, reporter_id: str | int | None = None) -> dict:
    report_key = url_report_key(url)
    return add_report_for_key(report_key, reporter_id=reporter_id)


def add_report_for_key(report_key: dict, reporter_id: str | int | None = None) -> dict:
    hashed_reporter = reporter_hash(reporter_id, report_key=report_key["key"])
    now = int(time.time())

    with _lock:
        store = _load_store()
        reports = store["reports"]
        item = reports.setdefault(
            report_key["key"],
            {
                "type": report_key["type"],
                "label": report_key["label"],
                "count": 0,
                "reporter_hashes": [],
                "first_reported_at": now,
                "last_reported_at": now,
            },
        )

        reporter_hashes = item.setdefault("reporter_hashes", [])
        duplicate = bool(hashed_reporter and hashed_reporter in reporter_hashes)

        if not duplicate:
            item["count"] = int(item.get("count") or 0) + 1
            item["last_reported_at"] = now

            if hashed_reporter:
                reporter_hashes.append(hashed_reporter)

            _save_store(store)

        count = int(item.get("count") or 0)

    return {
        "key_type": report_key["type"],
        "label": report_key["label"],
        "count": count,
        "threshold": REPORT_THRESHOLD,
        "community_suspicious": count >= REPORT_THRESHOLD,
        "duplicate": duplicate,
    }


def get_report_status(url: str) -> dict:
    report_key = url_report_key(url)

    with _lock:
        store = _load_store()
        item = store["reports"].get(report_key["key"], {})
        count = int(item.get("count") or 0)

    return {
        "key_type": report_key["type"],
        "label": report_key["label"],
        "count": count,
        "threshold": REPORT_THRESHOLD,
        "community_suspicious": count >= REPORT_THRESHOLD,
    }


def list_reports(limit: int = 10) -> list[dict]:
    with _lock:
        store = _load_store()
        reports = list(store["reports"].values())

    ordered_reports = sorted(
        reports,
        key=lambda item: (int(item.get("count") or 0), int(item.get("last_reported_at") or 0)),
        reverse=True,
    )

    results = []
    for item in ordered_reports[:limit]:
        count = int(item.get("count") or 0)
        results.append({
            "key_type": item.get("type") or "unknown",
            "label": item.get("label") or "unknown",
            "count": count,
            "threshold": REPORT_THRESHOLD,
            "community_suspicious": count >= REPORT_THRESHOLD,
            "last_reported_at": int(item.get("last_reported_at") or 0),
        })

    return results


def clear_domain_report(domain: str) -> dict:
    report_key = domain_report_key(domain)

    if not report_key:
        return {
            "cleared": False,
            "label": "",
            "reason": "invalid_domain",
        }

    with _lock:
        store = _load_store()
        existed = report_key["key"] in store["reports"]

        if existed:
            store["reports"].pop(report_key["key"], None)
            _save_store(store)

    return {
        "cleared": existed,
        "label": report_key["label"],
        "reason": "" if existed else "not_found",
    }
