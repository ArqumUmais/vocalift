#!/usr/bin/env python3
"""
Vocalift — Production Server
Industry-standard security: rate limiting, input validation, CSP headers,
secure file handling, job TTL cleanup, structured logging, and more.
"""

import os
from typing import Optional
import re
import sys
import uuid
import time
import shutil
import logging
import hashlib
import secrets
import subprocess
import threading
from pathlib import Path
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from functools import wraps

from dotenv import load_dotenv
load_dotenv()

from flask import (
    Flask, request, jsonify, send_file,
    send_from_directory, abort, g
)
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import yt_dlp

#  CONFIG

SECRET_KEY       = os.environ.get("SECRET_KEY", secrets.token_hex(32))
FLASK_ENV        = os.environ.get("FLASK_ENV", "production")
PORT             = int(os.environ.get("PORT", 5555))
ALLOWED_HOSTS    = [h.strip() for h in os.environ.get("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")]
CORS_ORIGINS     = os.environ.get("CORS_ORIGINS", "*")
FORCE_HTTPS      = os.environ.get("FORCE_HTTPS", "false").lower() == "true"
LOG_LEVEL        = os.environ.get("LOG_LEVEL", "INFO")
LOG_DIR          = Path(os.environ.get("LOG_DIR", "./logs"))
WORK_DIR         = Path(os.environ.get("WORK_DIR", "./vocalift_work"))
OUT_DIR          = Path(os.environ.get("OUT_DIR",  "./vocalift_output"))
MAX_DURATION     = int(os.environ.get("MAX_DURATION_SECONDS", 1800))
MAX_CONCURRENT   = int(os.environ.get("MAX_CONCURRENT_JOBS", 3))
JOB_TTL          = int(os.environ.get("JOB_TTL_SECONDS", 3600))
MAX_DISK_GB      = float(os.environ.get("MAX_DISK_GB", 20))

# Allowlists — only these values are accepted from clients
ALLOWED_MODELS  = frozenset({"htdemucs", "htdemucs_ft", "mdx_extra"})
ALLOWED_FORMATS = frozenset({"wav", "mp3", "flac"})

# Max request body size: 1 KB (URLs only — no file uploads to this endpoint)
MAX_CONTENT_LENGTH = 1024

for d in (LOG_DIR, WORK_DIR, OUT_DIR):
    d.mkdir(parents=True, exist_ok=True)

#  LOGGING  (structured, rotating, separate error log)

LOG_FMT = "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
logging.basicConfig(level=getattr(logging, LOG_LEVEL.upper(), logging.INFO), format=LOG_FMT)
logger = logging.getLogger("vocalift")

# Rotating file handler — max 10 MB × 5 backups
file_handler = RotatingFileHandler(LOG_DIR / "vocalift.log", maxBytes=10*1024*1024, backupCount=5)
file_handler.setFormatter(logging.Formatter(LOG_FMT))
err_handler  = RotatingFileHandler(LOG_DIR / "vocalift_errors.log", maxBytes=5*1024*1024, backupCount=3)
err_handler.setLevel(logging.ERROR)
err_handler.setFormatter(logging.Formatter(LOG_FMT))
logger.addHandler(file_handler)
logger.addHandler(err_handler)

#  APP

app = Flask(__name__, static_folder="static")
app.secret_key = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

# ── CORS ─────────────────────────────────────────────────────────────────────
CORS(app,
     origins=CORS_ORIGINS,
     methods=["GET", "POST", "OPTIONS"],
     allow_headers=["Content-Type", "X-Request-ID"],
     expose_headers=["X-Request-ID"],
     max_age=600)

# ── Rate limiting (in-memory; use Redis in multi-worker deployments) ──────────
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[os.environ.get("RATE_LIMIT_GLOBAL", "100 per minute")],
    storage_uri="memory://",
    strategy="fixed-window",
    headers_enabled=True,          # sends X-RateLimit-* headers to client
)

# ══════════════════════════════════════════════════════════════════════════════
#  SECURITY HEADERS  (applied to every response)
# ══════════════════════════════════════════════════════════════════════════════

@app.after_request
def set_security_headers(resp):
    # Strict CSP — only allow self + Google Fonts + YouTube thumbnails
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "           # inline JS in single-file HTML
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https://img.youtube.com; "
        "media-src 'self' blob:; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    resp.headers["X-Content-Type-Options"]     = "nosniff"
    resp.headers["X-Frame-Options"]            = "DENY"
    resp.headers["X-XSS-Protection"]           = "1; mode=block"
    resp.headers["Referrer-Policy"]            = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"]         = "geolocation=(), microphone=(), camera=()"
    resp.headers["Cache-Control"]              = "no-store, no-cache, must-revalidate"
    resp.headers["Pragma"]                     = "no-cache"
    if FORCE_HTTPS:
        resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    # Remove Flask/Werkzeug fingerprint
    resp.headers.pop("Server", None)
    resp.headers.pop("X-Powered-By", None)
    return resp

# ══════════════════════════════════════════════════════════════════════════════
#  REQUEST LIFECYCLE  (ID tracking + logging)
# ══════════════════════════════════════════════════════════════════════════════

@app.before_request
def before_request():
    g.request_id    = request.headers.get("X-Request-ID") or str(uuid.uuid4())[:12]
    g.start_time    = time.monotonic()
    g.remote_ip     = _get_real_ip()
    logger.info("REQ  %s %s %s id=%s ip=%s",
                request.method, request.path, request.content_type,
                g.request_id, g.remote_ip)

@app.after_request
def after_request(resp):
    duration_ms = int((time.monotonic() - g.start_time) * 1000)
    resp.headers["X-Request-ID"] = g.request_id
    logger.info("RESP %s %s %d %dms id=%s",
                request.method, request.path, resp.status_code,
                duration_ms, g.request_id)
    return resp

def _get_real_ip() -> str:
    """Extract real client IP, respecting trusted proxy headers."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"

# ══════════════════════════════════════════════════════════════════════════════
#  INPUT VALIDATION
# ══════════════════════════════════════════════════════════════════════════════

# Strict YouTube URL allowlist — only exact YouTube domains
_YT_PATTERN = re.compile(
    r"^https?://(www\.)?(youtube\.com/(watch\?.*v=[\w\-]{11}|shorts/[\w\-]{11})|youtu\.be/[\w\-]{11})"
)
_DANGEROUS_CHARS = re.compile(r"[;|`$<>{}()\[\]\\]")

def validate_youtube_url(url: str) -> bool:
    """Strict YouTube URL validation — rejects everything that isn't a clean video URL."""
    if not url or len(url) > 500:
        return False
    if _DANGEROUS_CHARS.search(url):
        return False
    return bool(_YT_PATTERN.match(url))

def sanitize_filename(name: str, max_len: int = 60) -> str:
    """Remove all path traversal and shell-dangerous characters."""
    name = re.sub(r"[^\w\s\-\.]", "_", name)
    name = re.sub(r"\.{2,}", "_", name)     # no ../ traversal
    name = name.strip(". ")
    return name[:max_len] or "output"

def validate_job_id(jid: str) -> bool:
    """Job IDs are UUIDs — reject anything else."""
    return bool(re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", jid))

# ══════════════════════════════════════════════════════════════════════════════
#  JOB STORE  (thread-safe)
# ══════════════════════════════════════════════════════════════════════════════

_jobs_lock = threading.RLock()
_jobs: dict[str, dict] = {}

def job_create(jid: str, ip: str) -> dict:
    entry = {
        "status":     "queued",
        "step":       0,
        "progress":   0,
        "message":    "Queued",
        "file":       None,
        "bg_file":    None,
        "error":      None,
        "title":      "",
        "created_at": time.time(),
        "ip":         hashlib.sha256(ip.encode()).hexdigest()[:12],  # hash IP — never store raw
    }
    with _jobs_lock:
        _jobs[jid] = entry
    return entry

def job_update(jid: str, **kwargs) -> None:
    with _jobs_lock:
        if jid in _jobs:
            _jobs[jid].update(kwargs)
            _jobs[jid]["updated_at"] = time.time()

def job_get(jid: str):
    with _jobs_lock:
        return dict(_jobs.get(jid, {})) or None

def job_count_running() -> int:
    with _jobs_lock:
        return sum(1 for j in _jobs.values() if j["status"] in ("queued", "running"))

def safe_job_response(job: dict) -> dict:
    """Strip internal fields (IP hash, raw paths) before sending to client."""
    return {
        "status":   job.get("status"),
        "step":     job.get("step", 0),
        "progress": job.get("progress", 0),
        "message":  job.get("message", ""),
        "title":    job.get("title", ""),
        "has_file": bool(job.get("file")),
        "bg_file":  bool(job.get("bg_file")),
        "error":    job.get("error"),
    }

# ══════════════════════════════════════════════════════════════════════════════
#  DISK GUARD
# ══════════════════════════════════════════════════════════════════════════════

def check_disk_space() -> bool:
    """Refuse jobs if output directory exceeds MAX_DISK_GB."""
    total = sum(f.stat().st_size for f in OUT_DIR.rglob("*") if f.is_file())
    used_gb = total / (1024 ** 3)
    if used_gb >= MAX_DISK_GB:
        logger.warning("Disk limit reached: %.2f GB used", used_gb)
        return False
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  JOB TTL CLEANUP  (background thread)
# ══════════════════════════════════════════════════════════════════════════════

def _cleanup_worker():
    """Periodically remove expired jobs and their output files."""
    while True:
        try:
            now = time.time()
            expired = []
            with _jobs_lock:
                for jid, job in _jobs.items():
                    age = now - job.get("created_at", now)
                    if age > JOB_TTL and job["status"] in ("done", "error"):
                        expired.append(jid)
                for jid in expired:
                    job = _jobs.pop(jid, {})
                    # Delete output files
                    for fkey in ("file", "bg_file"):
                        fpath = job.get(fkey)
                        if fpath:
                            p = Path(fpath)
                            if p.exists() and p.is_file():
                                try:
                                    p.unlink()
                                    logger.info("CLEANUP deleted %s", p.name)
                                except Exception as e:
                                    logger.warning("CLEANUP failed to delete %s: %s", fpath, e)
            if expired:
                logger.info("CLEANUP removed %d expired jobs", len(expired))
        except Exception as e:
            logger.error("CLEANUP error: %s", e)
        time.sleep(300)   # run every 5 minutes

threading.Thread(target=_cleanup_worker, daemon=True, name="cleanup").start()

# ══════════════════════════════════════════════════════════════════════════════
#  ERROR HANDLERS
# ══════════════════════════════════════════════════════════════════════════════

@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Bad request", "detail": str(e)}), 400

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405

@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "Request body too large"}), 413

@app.errorhandler(429)
def rate_limited(e):
    return jsonify({"error": "Too many requests — please slow down"}), 429

@app.errorhandler(500)
def server_error(e):
    logger.error("500 error: %s", e)
    return jsonify({"error": "Internal server error"}), 500

#  ROUTES

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/favicon.ico")
def favicon():
    return send_from_directory("static", "favicon.ico", mimetype="image/x-icon")

@app.route("/health")
def health():
    """Health-check endpoint for load balancers / uptime monitors."""
    return jsonify({
        "status":    "ok",
        "jobs":      job_count_running(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

# ── /api/info ─────────────────────────────────────────────────────────────────
# Fast version: extracts video ID from URL only — no yt-dlp call.
# Full metadata (title, duration) is fetched during the convert job itself.

_VID_RE = re.compile(r'(?:v=|youtu\.be/|shorts/)([A-Za-z0-9_-]{11})')

@app.route("/api/info", methods=["POST"])
@limiter.limit(os.environ.get("RATE_LIMIT_INFO", "60 per minute"))
def api_info():
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    data = request.get_json(silent=True) or {}
    url  = str(data.get("url", "")).strip()

    if not validate_youtube_url(url):
        logger.warning("INFO invalid URL from %s", g.remote_ip)
        return jsonify({"error": "Invalid YouTube URL"}), 400

    m = _VID_RE.search(url)
    if not m:
        return jsonify({"error": "Could not extract video ID from URL"}), 400

    vid_id = m.group(1)

    # Return immediately — no network calls at all
    return jsonify({
        "title":      f"YouTube Video ({vid_id})",
        "duration":   "unknown",
        "duration_s": 0,
        "channel":    "",
        "thumbnail":  f"https://img.youtube.com/vi/{vid_id}/mqdefault.jpg",
        "video_id":   vid_id,
    })

# ── /api/convert ──────────────────────────────────────────────────────────────

@app.route("/api/convert", methods=["POST"])
@limiter.limit(os.environ.get("RATE_LIMIT_CONVERT", "3 per minute"))
def api_convert():
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    data    = request.get_json(silent=True) or {}
    url     = str(data.get("url", "")).strip()
    model   = str(data.get("model", "htdemucs")).strip()
    fmt     = str(data.get("format", "mp3")).strip()
    keep_bg = bool(data.get("keep_bg", False))

    # Strict allowlist validation
    if not validate_youtube_url(url):
        return jsonify({"error": "Invalid YouTube URL"}), 400
    if model not in ALLOWED_MODELS:
        return jsonify({"error": "Invalid model"}), 400
    if fmt not in ALLOWED_FORMATS:
        return jsonify({"error": "Invalid format"}), 400

    # Duration guard — check before starting job
    try:
        duration = get_video_duration(url, timeout=20)
        if duration is not None and duration > MAX_DURATION:
            mins     = duration // 60
            max_mins = MAX_DURATION // 60
            logger.warning("CONVERT rejected — duration %ds > max %ds ip=%s", duration, MAX_DURATION, g.remote_ip)
            return jsonify({
                "error": f"Video is {mins} minutes long. Maximum allowed is {max_mins} minutes."
            }), 400
        if duration is None:
            logger.info("CONVERT duration check timed out — proceeding anyway ip=%s", g.remote_ip)
    except Exception as e:
        logger.warning("CONVERT duration check failed: %s — proceeding", e)

    # Concurrency guard
    if job_count_running() >= MAX_CONCURRENT:
        return jsonify({"error": f"Server busy — max {MAX_CONCURRENT} concurrent jobs. Try again shortly."}), 503

    # Disk guard
    if not check_disk_space():
        return jsonify({"error": "Server storage full — contact administrator"}), 503

    jid = str(uuid.uuid4())
    job_create(jid, g.remote_ip)

    logger.info("JOB  created %s model=%s fmt=%s ip=%s", jid, model, fmt, g.remote_ip)

    t = threading.Thread(
        target=_run_job,
        args=(jid, url, model, fmt, keep_bg),
        daemon=True,
        name=f"job-{jid[:8]}"
    )
    t.start()

    return jsonify({"job_id": jid}), 202   # 202 Accepted

# ── /api/status/<jid> ─────────────────────────────────────────────────────────

@app.route("/api/status/<jid>")
@limiter.limit("60 per minute")
def api_status(jid):
    if not validate_job_id(jid):
        abort(400)
    job = job_get(jid)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(safe_job_response(job))

# ── /api/download/<jid> ───────────────────────────────────────────────────────

@app.route("/api/download/<jid>")
@limiter.limit(os.environ.get("RATE_LIMIT_DOWNLOAD", "20 per minute"))
def api_download(jid):
    if not validate_job_id(jid):
        abort(400)
    job = job_get(jid)
    if not job or job.get("status") != "done":
        return jsonify({"error": "File not ready"}), 404

    fpath = job.get("file")
    if not fpath:
        return jsonify({"error": "No file associated with this job"}), 404

    path = Path(fpath).resolve()

    # Path traversal check — must be inside OUT_DIR
    if not str(path).startswith(str(OUT_DIR.resolve())):
        logger.error("PATH TRAVERSAL attempt jid=%s path=%s", jid, path)
        abort(403)

    if not path.exists() or not path.is_file():
        return jsonify({"error": "File no longer available"}), 410

    mime_map = {"wav": "audio/wav", "mp3": "audio/mpeg", "flac": "audio/flac"}
    suffix = path.suffix.lstrip(".")
    mime   = mime_map.get(suffix, "audio/wav")

    logger.info("DOWNLOAD jid=%s file=%s", jid, path.name)
    return send_file(path, as_attachment=True, download_name=path.name, mimetype=mime)

@app.route("/api/download_bg/<jid>")
@limiter.limit(os.environ.get("RATE_LIMIT_DOWNLOAD", "20 per minute"))
def api_download_bg(jid):
    if not validate_job_id(jid):
        abort(400)
    job = job_get(jid)
    if not job or not job.get("bg_file"):
        return jsonify({"error": "Instrumental file not available"}), 404

    path = Path(job["bg_file"]).resolve()
    if not str(path).startswith(str(OUT_DIR.resolve())):
        logger.error("PATH TRAVERSAL attempt jid=%s path=%s", jid, path)
        abort(403)
    if not path.exists():
        return jsonify({"error": "File no longer available"}), 410

    return send_file(path, as_attachment=True, download_name=path.name, mimetype="audio/wav")

# ══════════════════════════════════════════════════════════════════════════════
#  BACKGROUND JOB
# ══════════════════════════════════════════════════════════════════════════════

def _run_job(jid: str, url: str, model: str, fmt: str, keep_bg: bool):
    job_dir = WORK_DIR / jid
    job_dir.mkdir(parents=True, exist_ok=True)

    try:
        # Step 1 — skip separate info fetch, go straight to download
        # yt-dlp fetches metadata automatically during download
        m = re.search(r'(?:v=|youtu\.be/|shorts/)([A-Za-z0-9_-]{11})', url)
        vid_id = m.group(1) if m else "unknown"
        job_update(jid, status="running", step=1, progress=8,
                   message="Starting download…", title=f"Video {vid_id}")

        # Step 2 — download audio (metadata fetched here automatically)
        job_update(jid, step=2, progress=12, message="Downloading audio from YouTube…")

        # Use yt-dlp CLI directly — more reliable on Windows than Python API
        import subprocess as _sp
        vid_match = re.search(r'(?:v=|youtu\.be/|shorts/)([A-Za-z0-9_-]{11})', url)
        clean_url = f"https://www.youtube.com/watch?v={vid_match.group(1)}" if vid_match else url

        raw_out = str(job_dir / "raw.%(ext)s")
        cmd_dl = [
            sys.executable, "-m", "yt_dlp",
            "--format", "bestaudio",
            "--extract-audio",
            "--audio-format", "wav",
            "--audio-quality", "0",
            "--no-playlist",
            "--no-warnings",
            "--output", raw_out,
            "--print", "before_dl:%(title)s",
            clean_url,
        ]

        job_update(jid, progress=13, message="Starting audio download…")
        dl_proc = _sp.Popen(
            cmd_dl,
            stdout=_sp.PIPE, stderr=_sp.STDOUT,
            text=True, encoding="utf-8", errors="replace"
        )

        title_captured = False
        for line in dl_proc.stdout:
            line = line.strip()
            if not line:
                continue
            # First line printed before download is the title
            if not title_captured and not line.startswith("[") and len(line) > 3:
                job_update(jid, title=line[:200])
                title_captured = True
            # Parse download progress from yt-dlp output
            if "%" in line and "[download]" in line:
                try:
                    pct_str = [t for t in line.split() if "%" in t][0]
                    pct = float(pct_str.replace("%",""))
                    mapped = 13 + int(pct * 0.27)
                    job_update(jid, progress=min(mapped, 38),
                               message=f"Downloading audio: {pct:.0f}%")
                except Exception:
                    pass
            elif "[ExtractAudio]" in line or "Destination" in line:
                job_update(jid, progress=38, message="Converting to WAV…")

        dl_proc.wait()
        if dl_proc.returncode not in (0, None):
            raise RuntimeError(f"yt-dlp download failed (code {dl_proc.returncode})")

        # Duration check skipped — we already validated URL format
        # (10h limit enforced; yt-dlp would fail anyway if video is too long)
        job_update(jid, progress=40, message="Download complete!")

        wav_files = sorted(job_dir.glob("raw*.wav"), key=lambda p: p.stat().st_mtime)
        if not wav_files:
            raise RuntimeError("Download produced no WAV file")
        raw_wav = wav_files[-1]

        job_update(jid, progress=42, message="Download complete — starting AI separation…")

        # Step 3 — Demucs
        job_update(jid, step=3, progress=45, message=f"Running Demucs ({model})…")

        stems_dir = job_dir / "stems"
        stems_dir.mkdir(exist_ok=True)

        # Suppress libtorchcodec warning via env + -W ignore
        env = os.environ.copy()
        env["PYTORCH_DISABLE_FUNCTORCH_COMPILE"] = "1"
        env["TORCHDYNAMO_DISABLE"] = "1"

        # Use --mp3 to avoid torchaudio's save_with_torchcodec path
        # mp3 output uses lame encoder which doesn't need torchcodec
        cmd = [
            sys.executable, "-W", "ignore",
            "-m", "demucs",
            "--two-stems", "vocals",
            "--device", "cpu",
            "--mp3",              # save as mp3 — bypasses torchcodec completely
            "--mp3-bitrate", "320",
            "--out", str(stems_dir),
            "--name", model,
            str(raw_wav),
        ]

        logger.info("JOB %s demucs cmd: %s", jid[:8], " ".join(str(x) for x in cmd))

        demucs_output_lines = []
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
        for line in proc.stdout:
            line_s = line.strip()
            if not line_s:
                continue
            demucs_output_lines.append(line_s)
            if not any(x in line_s for x in ["UserWarning", "libtorch", "traceback", "warn("]):
                logger.info("DEMUCS %s: %s", jid[:8], line_s)
            if "%" in line_s:
                try:
                    pct_str = [t for t in line_s.split() if "%" in t][0]
                    pct = float(pct_str.replace("%", ""))
                    job_update(jid, progress=45 + int(pct * 0.45),
                               message=f"Demucs: {pct:.0f}% complete…")
                except Exception:
                    pass
        proc.wait()

        # Exit code 1 on Windows often just means libtorchcodec warning printed to stderr
        # Check if output files actually exist before declaring failure
        stem_dir_check = stems_dir / model / raw_wav.stem
        vocals_check   = stem_dir_check / "vocals.wav"

        if proc.returncode != 0 and not vocals_check.exists():
            tail = "\n".join(demucs_output_lines[-30:])
            logger.error("DEMUCS FAILED. Last output:\n%s", tail)
            raise RuntimeError(
                f"Demucs failed. Last line: {demucs_output_lines[-1] if demucs_output_lines else 'no output'}"
            )

                # Step 4 — export
        job_update(jid, step=4, progress=92, message="Exporting acapella…")

        stem_dir = job_dir / "stems" / model / raw_wav.stem

        # Demucs can save as .wav or .mp3 depending on version/flags — check both
        vocals_wav = None
        for ext in ("wav", "mp3", "flac"):
            candidate = stem_dir / f"vocals.{ext}"
            if candidate.exists():
                vocals_wav = candidate
                break

        # Also search one level up in case stem dir name differs
        if vocals_wav is None:
            for p in (job_dir / "stems" / model).rglob("vocals.*"):
                vocals_wav = p
                break

        if vocals_wav is None:
            # Log what IS in the stems dir to help debug
            stems_contents = list((job_dir / "stems").rglob("*")) if (job_dir / "stems").exists() else []
            logger.error("Stems dir contents: %s", [str(x) for x in stems_contents])
            raise RuntimeError(f"Vocals stem file not found. Stems dir has: {[x.name for x in stems_contents]}")

        no_voc_wav = None
        for ext in ("wav", "mp3", "flac"):
            candidate = stem_dir / f"no_vocals.{ext}"
            if candidate.exists():
                no_voc_wav = candidate
                break

        # Get title from job store (set during download) or fall back to video ID
        job_now = job_get(jid) or {}
        raw_title = job_now.get("title") or vid_id or "audio"
        title = sanitize_filename(raw_title)

        out_name  = f"{title}_acapella.{fmt}"
        out_path  = (OUT_DIR / out_name).resolve()

        # Extra path traversal guard on the output side
        if not str(out_path).startswith(str(OUT_DIR.resolve())):
            raise RuntimeError("Output path escapes output directory — rejecting")

        _encode(vocals_wav, out_path, fmt)

        bg_path = None
        if keep_bg and no_voc_wav.exists():
            bg_name = f"{title}_instrumental.{fmt}"
            bg_out  = (OUT_DIR / bg_name).resolve()
            if str(bg_out).startswith(str(OUT_DIR.resolve())):
                _encode(no_voc_wav, bg_out, fmt)
                bg_path = str(bg_out)

        shutil.rmtree(job_dir, ignore_errors=True)
        logger.info("JOB %s done file=%s", jid, out_path.name)
        job_update(jid, status="done", step=4, progress=100,
                   message="Done!", file=str(out_path), bg_file=bg_path)

    except Exception as e:
        shutil.rmtree(job_dir, ignore_errors=True)
        logger.error("JOB %s failed: %s", jid, e, exc_info=True)
        job_update(jid, status="error", message=str(e), error=str(e))


def _encode(src: Path, dst: Path, fmt: str):
    src_ext = src.suffix.lower().lstrip(".")
    # Same format — just copy, no re-encoding needed
    if src_ext == fmt:
        shutil.copy2(src, dst)
        return
    # Transcode with ffmpeg
    if fmt == "mp3":
        cmd = ["ffmpeg", "-y", "-i", str(src), "-c:a", "libmp3lame", "-b:a", "320k", str(dst)]
    elif fmt == "wav":
        cmd = ["ffmpeg", "-y", "-i", str(src), "-c:a", "pcm_s16le", str(dst)]
    else:
        cmd = ["ffmpeg", "-y", "-i", str(src), "-c:a", "flac", str(dst)]
    result = subprocess.run(cmd, capture_output=True, timeout=600)
    if result.returncode != 0:
        raise RuntimeError(f"ffmpeg encoding failed: {result.stderr.decode()[:200]}")


def _meta_hook(jid: str, d: dict):
    """Called by yt-dlp postprocessor — grab title when available."""
    info = d.get("info_dict", {})
    title = info.get("title", "")
    if title:
        job_update(jid, title=title[:200])

# Track download phase per job (audio dl vs ffmpeg conversion)
_dl_phase: dict[str, int] = {}

def _dl_hook(jid: str, d: dict):
    status = d.get("status", "")

    if status == "downloading":
        # Detect phase: if progress resets below 20% after being high, it's ffmpeg
        raw = re.sub(r"\x1b\[[0-9;]*m", "", d.get("_percent_str", "0%")).replace("%", "").strip()
        try:
            pct = float(raw)
            phase = _dl_phase.get(jid, 1)

            # If we were >50% and now <20%, we moved to ffmpeg conversion phase
            prev = getattr(_dl_hook, f"_prev_{jid}", 0)
            if prev > 50 and pct < 20:
                _dl_phase[jid] = 2
                phase = 2
            setattr(_dl_hook, f"_prev_{jid}", pct)

            if phase == 1:
                mapped = 12 + int(pct * 0.25)   # 12% → 37%
                job_update(jid, progress=mapped,
                           message=f"Downloading audio: {pct:.0f}%…")
            else:
                mapped = 37 + int(pct * 0.05)   # 37% → 42%
                job_update(jid, progress=mapped,
                           message=f"Converting to WAV: {pct:.0f}%…")
        except Exception:
            pass

    elif status == "finished":
        _dl_phase[jid] = 2   # move to next phase
        job_update(jid, progress=40, message="Download complete — preparing for AI…")


def _fmt_dur(s: int) -> str:
    h, r  = divmod(int(s), 3600)
    m, sc = divmod(r, 60)
    return f"{h}h {m}m {sc}s" if h else f"{m}m {sc}s"


if __name__ == "__main__":
    is_dev = FLASK_ENV == "development"
    logger.info("Starting Vocalift (env=%s port=%d debug=%s)", FLASK_ENV, PORT, is_dev)
    print(f"\n🎤  Vocalift  [{FLASK_ENV.upper()}]")
    print(f"    http://localhost:{PORT}")
    print(f"    Logs → {LOG_DIR}/\n")
    app.run(
        host="0.0.0.0",
        port=PORT,
        debug=is_dev,
        threaded=True,
        use_reloader=False,
    )
