#!/usr/bin/env python3
"""
API REST para firma electrónica - PWA
Corregido: Manejo correcto de sesiones y ejecución de Uvicorn
"""

import os
import io
import tempfile
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Importar el script de firma
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Importar funciones del script de firma
try:
    from firma_ec_endesive import (
        obtener_certificado_vigente,
        firmar_con_endesive,
        ahora_ecuador,
        TZ_ECUADOR
    )
except ImportError as e:
    print(f"Error al importar firma_ec_endesive: {e}")
    print("Asegúrate de que el archivo firma_ec_endesive.py está en el mismo directorio")
    sys.exit(1)

# Crear la aplicación FastAPI
app = FastAPI(title="Firma Electrónica Ecuador API", version="1.0.0")

# CORS para permitir la PWA
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Directorio temporal para archivos
TEMP_DIR = Path(tempfile.gettempdir()) / "firma_ec_api"
TEMP_DIR.mkdir(exist_ok=True)


class SessionData:
    """Almacenamiento de datos de sesión"""
    def __init__(self):
        self.cert_path = None
        self.cert_filename = None
        self.pdf_path = None
        self.pdf_filename = None
        self.output_path = None
        self.password = None
        self.nombre_firmante = None
        self.created_at = datetime.now()
        self.verified = False


# Almacenamiento de sesiones en memoria
sessions: Dict[str, SessionData] = {}


def limpiar_sesiones_viejas():
    """Limpiar sesiones con más de 1 hora"""
    ahora = datetime.now()
    to_delete = []
    for sid, session in sessions.items():
        if ahora - session.created_at > timedelta(hours=1):
            to_delete.append(sid)
            # Eliminar archivos
            for attr in ['cert_path', 'pdf_path', 'output_path']:
                path = getattr(session, attr)
                if path and os.path.exists(path):
                    try:
                        os.unlink(path)
                    except:
                        pass
    for sid in to_delete:
        del sessions[sid]


# ─────────────────────────────────────────────────────────────────
# ENDPOINTS DE LA API
# ─────────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    """Endpoint raíz para verificar que la API funciona"""
    return {"status": "ok", "message": "API Firma Electrónica Ecuador"}


@app.post("/upload-cert")
async def upload_certificate(
    cert: UploadFile = File(...),
    session_id: Optional[str] = None
):
    """Subir certificado P12"""
    try:
        # Verificar extensión
        if not cert.filename.endswith(('.p12', '.pfx')):
            raise HTTPException(400, "El archivo debe ser .p12 o .pfx")
        
        # Generar session_id si no existe
        if not session_id or session_id not in sessions:
            session_id = str(uuid.uuid4())
        
        # Guardar certificado
        cert_path = TEMP_DIR / f"{session_id}_cert.p12"
        with open(cert_path, "wb") as f:
            content = await cert.read()
            f.write(content)
        
        # Crear o actualizar sesión
        if session_id not in sessions:
            sessions[session_id] = SessionData()
        
        sessions[session_id].cert_path = str(cert_path)
        sessions[session_id].cert_filename = cert.filename
        sessions[session_id].created_at = datetime.now()
        
        # Limpiar sesiones viejas
        limpiar_sesiones_viejas()
        
        return JSONResponse(content={
            "success": True,
            "session_id": session_id,
            "message": "Certificado cargado correctamente"
        })
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/verify-cert")
async def verify_certificate(
    session_id: str = Form(...),
    password: str = Form(...)
):
    """Verificar certificado y obtener información"""
    try:
        if session_id not in sessions:
            raise HTTPException(404, "Sesión no encontrada. Por favor, cargue el certificado nuevamente.")
        
        session = sessions[session_id]
        cert_path = session.cert_path
        
        if not cert_path or not os.path.exists(cert_path):
            raise HTTPException(404, "Certificado no encontrado. Por favor, cargue nuevamente.")
        
        # Verificar certificado
        from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
        from cryptography.x509.oid import NameOID
        
        with open(cert_path, "rb") as f:
            p12_data = f.read()
        
        try:
            clave, certificado, cadena = load_key_and_certificates(
                p12_data, password.encode("utf-8")
            )
        except Exception as e:
            raise HTTPException(401, f"Contraseña incorrecta o certificado inválido: {str(e)}")
        
        if certificado is None:
            raise HTTPException(401, "Contraseña incorrecta")
        
        # Extraer información
        attrs = certificado.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        nombre = attrs[0].value if attrs else "Desconocido"
        if isinstance(nombre, bytes):
            nombre = nombre.decode('utf-8', errors='ignore')
        
        emi = certificado.not_valid_before_utc
        exp = certificado.not_valid_after_utc
        
        emi_local = emi.astimezone(TZ_ECUADOR)
        exp_local = exp.astimezone(TZ_ECUADOR)
        
        ahora = ahora_ecuador()
        vigente = emi_local <= ahora <= exp_local
        dias = (exp_local - ahora).days if vigente else 0
        
        # Guardar en sesión
        session.password = password
        session.nombre_firmante = nombre
        session.verified = True
        
        return {
            "success": True,
            "firmante": nombre,
            "emision": emi_local.strftime("%d/%m/%Y"),
            "expiracion": exp_local.strftime("%d/%m/%Y"),
            "vigente": vigente,
            "dias_restantes": dias
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/upload-pdf")
async def upload_pdf(
    pdf: UploadFile = File(...),
    session_id: str = Form(...)
):
    """Subir PDF a firmar"""
    try:
        if session_id not in sessions:
            raise HTTPException(404, "Sesión no encontrada. Por favor, cargue el certificado nuevamente.")
        
        session = sessions[session_id]
        
        if not pdf.filename.endswith('.pdf'):
            raise HTTPException(400, "El archivo debe ser PDF")
        
        pdf_path = TEMP_DIR / f"{session_id}_document.pdf"
        with open(pdf_path, "wb") as f:
            content = await pdf.read()
            f.write(content)
        
        session.pdf_path = str(pdf_path)
        session.pdf_filename = pdf.filename
        
        return {"success": True, "filename": pdf.filename}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


class SignRequest(BaseModel):
    session_id: str
    password: str


@app.post("/sign")
async def sign_document(request: SignRequest):
    """Firmar el documento"""
    try:
        session_id = request.session_id
        password = request.password
        
        if session_id not in sessions:
            raise HTTPException(404, "Sesión no encontrada. Por favor, cargue el certificado nuevamente.")
        
        session = sessions[session_id]
        
        cert_path = session.cert_path
        pdf_path = session.pdf_path
        nombre_firmante = session.nombre_firmante
        
        if not cert_path or not os.path.exists(cert_path):
            raise HTTPException(404, "Certificado no encontrado. Por favor, cargue nuevamente.")
        
        if not pdf_path or not os.path.exists(pdf_path):
            raise HTTPException(404, "PDF no encontrado. Por favor, cargue nuevamente.")
        
        if not nombre_firmante:
            raise HTTPException(400, "No se ha verificado el certificado. Por favor, verifique primero.")
        
        # Leer PDF
        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()
        
        # Generar fecha de firma
        fecha_firma = ahora_ecuador().strftime("%d/%m/%Y %H:%M:%S")
        
        # Firmar
        pdf_firmado = firmar_con_endesive(
            pdf_bytes, cert_path, password, nombre_firmante, fecha_firma
        )
        
        # Guardar resultado
        output_path = TEMP_DIR / f"{session_id}_signed.pdf"
        with open(output_path, "wb") as f:
            f.write(pdf_firmado)
        
        session.output_path = str(output_path)
        
        return {
            "success": True,
            "message": "Documento firmado exitosamente",
            "filename": f"{Path(pdf_path).stem}_firmado.pdf"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/download/{session_id}")
async def download(session_id: str):
    """Descargar PDF firmado"""
    try:
        if session_id not in sessions:
            raise HTTPException(404, "Sesión no encontrada")
        
        output_path = sessions[session_id].output_path
        if not output_path or not os.path.exists(output_path):
            raise HTTPException(404, "Archivo no encontrado. Primero debe firmar el documento.")
        
        filename = sessions[session_id].pdf_filename or "documento"
        filename = filename.replace(".pdf", "_firmado.pdf") if filename else "documento_firmado.pdf"
        
        return FileResponse(
            output_path,
            media_type="application/pdf",
            filename=filename
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


@app.delete("/session/{session_id}")
async def clear_session(session_id: str):
    """Limpiar sesión y archivos temporales"""
    try:
        if session_id in sessions:
            session = sessions[session_id]
            # Eliminar archivos temporales
            for path in [session.cert_path, session.pdf_path, session.output_path]:
                if path and os.path.exists(path):
                    try:
                        os.unlink(path)
                    except:
                        pass
            del sessions[session_id]
        
        return {"success": True}
        
    except Exception as e:
        raise HTTPException(500, str(e))


# ─────────────────────────────────────────────────────────────────
# PUNTO DE ENTRADA (CORREGIDO)
# ─────────────────────────────────────────────────────────────────

def main():
    """Función principal para ejecutar el servidor"""
    import uvicorn
    
    print("=" * 60)
    print("  API FIRMA ELECTRÓNICA ECUADOR")
    print("=" * 60)
    print(f"  Servidor iniciando en: http://localhost:8000")
    print(f"  Documentación: http://localhost:8000/docs")
    print("  Para detener: Ctrl+C")
    print("=" * 60)
    
    # Forma CORRECTA de ejecutar uvicorn con reload
    # Opción 1: Sin reload (para producción)
    uvicorn.run(app, host="0.0.0.0", port=8000)
    
    # Opción 2: Con reload (solo para desarrollo) - DESCOMENTAR SI SE NECESITA
    # uvicorn.run("api_firma:app", host="0.0.0.0", port=8000, reload=True)


# Script alternativo para ejecutar con reload (desarrollo)
if __name__ == "__main__":
    # Verificar si se quiere ejecutar con reload
    import sys
    if "--reload" in sys.argv:
        # Modo desarrollo con reload
        import uvicorn
        print("=" * 60)
        print("  API FIRMA ELECTRÓNICA ECUADOR (MODO DESARROLLO)")
        print("=" * 60)
        print("  Servidor con autoreload activado")
        print("=" * 60)
        uvicorn.run("api_firma:app", host="0.0.0.0", port=8000, reload=True)
    else:
        main()