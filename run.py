#!/usr/bin/env python3
# =============================================================================
# DomainRecon - Lanceur Simplifié
# =============================================================================
# Usage : python run.py
# =============================================================================

import sys
import os
import webbrowser
import threading
import time


def main():
    try:
        import uvicorn
    except ImportError:
        print("[*] Installation des dépendances...")
        os.system(f"{sys.executable} -m pip install -r requirements.txt")
        import uvicorn

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    dev = os.getenv("ENV", "development") == "development"

    def open_browser():
        time.sleep(2)
        webbrowser.open(f"http://localhost:{port}")

    threading.Thread(target=open_browser, daemon=True).start()

    print(f"""
    ╔══════════════════════════════════════════╗
    ║       🔍 DomainRecon v2.0                ║
    ║       OSINT Domain Scanner               ║
    ╠══════════════════════════════════════════╣
    ║  URL  : http://localhost:{port}             ║
    ║  API  : http://localhost:{port}/api/docs    ║
    ║  Mode : {'Développement' if dev else 'Production'}             ║
    ╚══════════════════════════════════════════╝
    """)

    uvicorn.run(
        "backend.app.main:app",
        host=host,
        port=port,
        reload=dev,
    )


if __name__ == "__main__":
    main()
