# Vocalift

**AI-powered vocal extraction from any YouTube video.**

Vocalift separates the human voice from a mixed audio recording using Meta's HTDemucs neural network. Paste a YouTube link, receive a clean MP3 acapella — no music, no instruments, just the vocals.

---

## What It Does

Vocalift performs audio stem separation on YouTube content. It downloads the audio stream, runs it through a hybrid transformer model trained on thousands of professional recordings, and returns an isolated vocal track in your chosen format.

Use it for remixing, sampling, transcription, karaoke preparation, language learning, vocal analysis, or archival purposes.

---

## Demo

![Vocalift Screenshot](https://img.shields.io/badge/status-active-10b981?style=flat-square)

1. Paste a YouTube URL
2. Click **Extract Acapella**
3. Download your MP3

---

## Features

- Clean vocal isolation using Meta HTDemucs (hybrid transformer architecture)
- Supports YouTube videos up to **30 minutes**
- Output formats: **MP3** (default, 320 kbps), WAV, FLAC
- Optional instrumental track export
- Mobile-responsive interface
- Real-time progress tracking across all processing stages
- Session history with re-download support
- Production-hardened backend with rate limiting, input validation, and security headers

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Vanilla HTML/CSS/JS — no framework |
| Backend | Python 3.11+ / Flask |
| AI Model | Meta HTDemucs (via Demucs v4) |
| Downloader | yt-dlp |
| Audio | ffmpeg |
| Production server | Gunicorn + Nginx |

---

## Requirements

- Python 3.10 or higher (3.11 recommended)
- ffmpeg installed on your system
- ~2 GB disk space for model weights (downloaded automatically on first run)
- Internet connection (for YouTube downloads)

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/vocalift.git
cd vocalift
```

### 2. Create a virtual environment

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Install ffmpeg

**Windows**
```powershell
winget install Gyan.FFmpeg
```

**macOS**
```bash
brew install ffmpeg
```

**Ubuntu / Debian**
```bash
sudo apt install ffmpeg
```

### 5. Configure environment

```bash
cp .env.example .env
```

Open `.env` and set your secret key:
```
SECRET_KEY=your_random_secret_here
FLASK_ENV=production
```

Generate a secure key with:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### 6. Run

```bash
python server.py
```

Open **http://localhost:5555** in your browser.

---

## Windows Notes

If you encounter a long path error during installation:

1. Open PowerShell as Administrator
2. Run:
```powershell
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force
```
3. Restart your machine
4. Re-run `pip install -r requirements.txt`

If `torchcodec` causes Demucs to fail:
```bash
pip uninstall torchaudio -y
pip install torchaudio==2.3.0 --index-url https://download.pytorch.org/whl/cpu
pip install soundfile
```

---

## Production Deployment

For public-facing deployment on a Linux VPS:

### System dependencies
```bash
sudo apt update && sudo apt install -y python3.11 python3.11-venv ffmpeg nginx certbot python3-certbot-nginx
```

### SSL certificate
```bash
sudo certbot --nginx -d yourdomain.com
```

### Nginx
```bash
sudo cp config/nginx.conf /etc/nginx/sites-available/vocalift
# Edit yourdomain.com in the config
sudo ln -s /etc/nginx/sites-available/vocalift /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### Systemd service
```bash
sudo cp config/vocalift.service /etc/systemd/system/
sudo systemctl enable vocalift && sudo systemctl start vocalift
```

### Run with Gunicorn
```bash
gunicorn -c gunicorn.conf.py server:app
```

### Verify
```bash
curl https://yourdomain.com/health
# {"status":"ok","jobs":0,"timestamp":"..."}
```

---

## Project Structure

```
vocalift/
├── server.py              # Flask application
├── gunicorn.conf.py       # Production WSGI config
├── requirements.txt       # Python dependencies
├── .env.example           # Environment template
├── .gitignore
├── static/
│   ├── index.html         # Frontend (single file)
│   └── favicon.ico
├── config/
│   ├── nginx.conf         # Nginx reverse proxy config
│   └── vocalift.service   # Systemd unit file
├── logs/                  # Created at runtime
├── vocalift_work/         # Temporary processing files
└── vocalift_output/       # Completed output files
```

---

## Security

Vocalift is built with production security in mind:

- Strict YouTube URL validation with shell-character rejection
- Rate limiting on all API endpoints (Flask-Limiter)
- Security headers on every response (CSP, X-Frame-Options, nosniff, HSTS)
- Path traversal protection on all file operations
- Job TTL cleanup — output files deleted after 1 hour
- Disk space guard prevents storage exhaustion
- Hashed IP logging (GDPR-friendly)
- Runs as a non-root user under systemd

---

## Performance

Processing time depends on your hardware:

| Hardware | 3-min song | 15-min track |
|---|---|---|
| CPU only | ~2–4 min | ~10–20 min |
| GPU (mid-range) | ~15 sec | ~1–2 min |
| GPU (high-end) | ~8 sec | ~30 sec |

GPU acceleration requires a CUDA-compatible Nvidia GPU. Demucs will use it automatically if available.

---

## Limitations

- Maximum video duration: 30 minutes
- Private or age-restricted videos require browser cookies
- Live recordings produce less clean results than studio productions
- Vocals with heavy reverb or close harmonic doubling may exhibit mild artefacts
- First run downloads model weights (~300 MB)

---

## License

MIT License. See `LICENSE` for details.

---

## Acknowledgements

- [Demucs](https://github.com/facebookresearch/demucs) by Meta AI Research
- [yt-dlp](https://github.com/yt-dlp/yt-dlp) for YouTube audio extraction
- [Flask](https://flask.palletsprojects.com/) web framework

---

*All audio processing is performed locally on your machine. No audio content is transmitted to or stored by any third party.*
