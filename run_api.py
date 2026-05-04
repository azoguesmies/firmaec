#!/usr/bin/env python3
"""
Ejecutor de la API - Firma Electrónica Ecuador
Uso:
    python run_api.py          # Modo normal
    python run_api.py --reload # Modo desarrollo con autoreload
"""

import sys
import uvicorn

if __name__ == "__main__":
    print("=" * 60)
    print("  API FIRMA ELECTRÓNICA ECUADOR")
    print("=" * 60)
    print("  Servidor: http://localhost:8000")
    print("  Documentación: http://localhost:8000/docs")
    print("=" * 60)
    
    # Verificar si se quiere modo reload
    if len(sys.argv) > 1 and sys.argv[1] == "--reload":
        print("  Modo desarrollo con autoreload activado")
        uvicorn.run("api_firma:app", host="0.0.0.0", port=8000, reload=True)
    else:
        print("  Modo normal (sin autoreload)")
        from api_firma import app
        uvicorn.run(app, host="0.0.0.0", port=8000)