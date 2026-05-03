import base64
import json
import os
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, StrictStr

from scanner import clean_url, extract_urls, local_scan_url, normalize_url, safe_url_label


MAX_URL_LENGTH = 2048
VT_CACHE_TTL_SECONDS = 24 * 60 * 60
VT_API_BASE = "https://www.virustotal.com/api/v3"
BASE_DIR = Path(__file__).resolve().parent
WEB_DIR = BASE_DIR / "web"
vt_cache: dict[str, tuple[float, dict]] = {}

app = FastAPI(title="SafeLiinkBot API")
app.mount("/web", StaticFiles(directory=WEB_DIR), name="web")


class ScanRequest(BaseModel):
    url: StrictStr
    initData: StrictStr
    advanced: bool = False


class VirusTotalScanRequest(BaseModel):
    url: StrictStr
    initData: StrictStr


@app.get("/health")
async def health() -> dict:
    return {"ok": True}


@app.get("/")
async def frontend() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


def validate_scan_input(url: str, init_data: str) -> str:
    url = clean_url(url)
    init_data = init_data.strip()

    if not url:
        raise HTTPException(status_code=400, detail="url is required")

    if not init_data:
        raise HTTPException(status_code=400, detail="initData is required")

    urls = extract_urls(url)
    scan_url = urls[0] if urls else url
    normalized_url = normalize_url(scan_url)
    if len(normalized_url) > MAX_URL_LENGTH:
        raise HTTPException(status_code=400, detail="url is too long")

    parsed = urlsplit(normalized_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=400, detail="url must be a valid http(s) URL")

    return normalized_url


def vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def vt_request(path: str, api_key: str, data: bytes | None = None) -> dict:
    headers = {
        "Accept": "application/json",
        "x-apikey": api_key,
    }

    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    request = Request(f"{VT_API_BASE}{path}", data=data, headers=headers)

    try:
        with urlopen(request, timeout=12) as response:
            return json.loads(response.read().decode())
    except HTTPError as error:
        if error.code == 429:
            raise HTTPException(status_code=429, detail="vt rate limit reached") from error

        if error.code == 404:
            raise HTTPException(status_code=404, detail="vt url not found") from error

        if error.code in {401, 403}:
            raise HTTPException(status_code=503, detail="vt api key invalid") from error

        raise HTTPException(status_code=502, detail="vt request failed") from error
    except (TimeoutError, URLError, json.JSONDecodeError) as error:
        raise HTTPException(status_code=502, detail="vt request failed") from error


def summarize_vt_report(report: dict) -> dict:
    attributes = report.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    harmless = int(stats.get("harmless") or 0)
    undetected = int(stats.get("undetected") or 0)
    timeout = int(stats.get("timeout") or 0)
    total = malicious + suspicious + harmless + undetected + timeout

    if malicious:
        level = "high"
        title = "تحذير من VirusTotal"
        message = f"رصدت VirusTotal الرابط كخطر لدى {malicious} مزود فحص."
    elif suspicious:
        level = "medium"
        title = "نتيجة مشبوهة من VirusTotal"
        message = f"ظهر الرابط كمشبوه لدى {suspicious} مزود فحص."
    else:
        level = "low"
        title = "لا توجد مؤشرات متقدمة واضحة"
        message = "لم ترصد VirusTotal مؤشرات خطر واضحة في آخر نتيجة متاحة."

    return {
        "status": "ready",
        "level": level,
        "title": title,
        "message": message,
        "stats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "timeout": timeout,
            "total": total,
        },
    }


def queued_vt_summary() -> dict:
    return {
        "status": "queued",
        "level": "medium",
        "title": "تم إرسال الرابط إلى VirusTotal",
        "message": "لم تكن هناك نتيجة جاهزة لهذا الرابط. تم إرساله للفحص المتقدم، وقد تحتاج النتيجة بعض الوقت.",
        "stats": {},
    }


def get_vt_summary(normalized_url: str, api_key: str) -> dict:
    cached = vt_cache.get(normalized_url)
    now = time.time()

    if cached and now - cached[0] < VT_CACHE_TTL_SECONDS:
        summary = cached[1].copy()
        summary["cached"] = True
        return summary

    try:
        report = vt_request(f"/urls/{vt_url_id(normalized_url)}", api_key)
        summary = summarize_vt_report(report)
    except HTTPException as error:
        if error.status_code != 404:
            raise

        vt_request(
            "/urls",
            api_key,
            data=urlencode({"url": normalized_url}).encode(),
        )
        summary = queued_vt_summary()

    vt_cache[normalized_url] = (now, summary)
    summary = summary.copy()
    summary["cached"] = False
    return summary


@app.post("/api/scan")
async def scan(payload: ScanRequest) -> dict:
    normalized_url = validate_scan_input(payload.url, payload.initData)

    if payload.advanced:
        return scan_virustotal_response(normalized_url)

    return {
        "ok": True,
        "url": safe_url_label(normalized_url),
        "scan": local_scan_url(normalized_url, message_text=payload.url),
    }


def scan_virustotal_response(normalized_url: str) -> dict:
    api_key = os.getenv("VT_API_KEY", "").strip()

    if not api_key:
        raise HTTPException(status_code=503, detail="vt api key missing")

    summary = get_vt_summary(normalized_url, api_key)

    return {
        "ok": True,
        "url": safe_url_label(normalized_url),
        "vt": summary,
    }


@app.post("/api/scan/vt")
async def scan_virustotal(payload: VirusTotalScanRequest) -> dict:
    normalized_url = validate_scan_input(payload.url, payload.initData)
    return scan_virustotal_response(normalized_url)
