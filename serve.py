# Production launcher for the NPI Dashboard (Waitress, Windows-compatible).
#   pip install -r requirements.txt
#   python serve.py            ->  http://<server-ip>:5001
import os, logging
from waitress import serve
from npi_app import app
if __name__ == "__main__":
    host    = os.environ.get("HOST", "0.0.0.0")
    port    = int(os.environ.get("PORT", "5001"))
    threads = int(os.environ.get("THREADS", "8"))
    logging.getLogger("serve").info("NPI Dashboard on http://%s:%s", host, port)
    serve(app, host=host, port=port, threads=threads, ident="")