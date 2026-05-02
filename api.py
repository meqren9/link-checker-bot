from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, StrictStr

from scanner import clean_url, local_scan_url, normalize_url, safe_url_label


MAX_URL_LENGTH = 2048
BASE_DIR = Path(__file__).resolve().parent
WEB_DIR = BASE_DIR / "web"

app = FastAPI(title="SafeLiinkBot API")
app.mount("/web", StaticFiles(directory=WEB_DIR), name="web")


class ScanRequest(BaseModel):
    url: StrictStr
    initData: StrictStr


@app.get("/health")
async def health() -> dict:
    return {"ok": True}


@app.get("/")
async def frontend() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


@app.post("/api/scan")
async def scan(payload: ScanRequest) -> dict:
    url = clean_url(payload.url)
    init_data = payload.initData.strip()

    if not url:
        raise HTTPException(status_code=400, detail="url is required")

    if not init_data:
        raise HTTPException(status_code=400, detail="initData is required")

    normalized_url = normalize_url(url)
    if len(normalized_url) > MAX_URL_LENGTH:
        raise HTTPException(status_code=400, detail="url is too long")

    parsed = urlsplit(normalized_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=400, detail="url must be a valid http(s) URL")

    return {
        "ok": True,
        "url": safe_url_label(normalized_url),
        "scan": local_scan_url(normalized_url),
    }
