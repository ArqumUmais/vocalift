# gunicorn.conf.py — Production WSGI config
# Usage: gunicorn -c gunicorn.conf.py server:app

import multiprocessing
import os

# Workers: (2 × CPU cores) + 1 is the standard formula
# For AI workloads keep this lower to avoid OOM
workers     = int(os.environ.get("GUNICORN_WORKERS", 2))
threads     = int(os.environ.get("GUNICORN_THREADS", 4))
worker_class = "gthread"

bind        = f"0.0.0.0:{os.environ.get('PORT', 5555)}"
timeout     = 1800          # 30 min — Demucs on long tracks needs time
keepalive   = 5
max_requests        = 500   # recycle workers to prevent memory leaks
max_requests_jitter = 50

# Logging
accesslog   = "./logs/gunicorn_access.log"
errorlog    = "./logs/gunicorn_error.log"
loglevel    = os.environ.get("LOG_LEVEL", "info").lower()
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)sµs'

# Security
limit_request_line   = 4094
limit_request_fields = 50
limit_request_field_size = 8190

# Graceful shutdown
graceful_timeout = 30
