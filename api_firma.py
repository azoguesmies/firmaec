#!/usr/bin/env python3
"""
API REST para firma electrónica - PWA
Endpoints:
  - POST /upload-cert     : Subir certificado P12
  - POST /upload-pdf      : Subir PDF a firmar
  - POST /sign            : Firmar documento
  - GET  /download/{id}   : Descargar PDF firmado
"""

import os
import io
import tempfile
import shutil
import uuid
from pathlib import Path
from datetime import datetime
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

# Importar tu script de firma
from firma_ec_endesive import (
    obtener_certificado_vigente,
    firmar_con_endesive,
    ahora_ecuador
)

app = FastAPI(title="Firma Electrónica Ecuador API", version="1.0.0")

# CORS para permitir la PWA
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En producción, especifica tu dominio
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Directorio temporal para archivos
TEMP_DIR = Path(tempfile.gettempdir()) / "firma_ec_api"
TEMP_DIR.mkdir(exist_ok=True)

# Almacenamiento temporal en memoria (para demo)
# En producción usar Redis o base de datos
sessions = {}


class SignRequest(BaseModel):
    session_id: str
    password: str


def limpiar_archivos_viejos():
    """Limpiar archivos temporales antiguos (más de 1 hora)"""
    ahora = datetime.now().timestamp()
    for item in TEMP_DIR.iterdir():
        if item.is_file() and (ahora - item.stat().st_mtime) > 3600:
            try:
                item.unlink()
            except:
                pass


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
        if not session_id:
            session_id = str(uuid.uuid4())
        
        # Guardar certificado
        cert_path = TEMP_DIR / f"{session_id}_cert.p12"
        with open(cert_path, "wb") as f:
            content = await cert.read()
            f.write(content)
        
        # Guardar metadata
        if session_id not in sessions:
            sessions[session_id] = {}
        sessions[session_id]["cert_path"] = str(cert_path)
        sessions[session_id]["cert_filename"] = cert.filename
        
        # Intentar leer información del certificado (sin contraseña)
        info = {"session_id": session_id}
        
        return JSONResponse(content=info)
        
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
            raise HTTPException(404, "Sesión no encontrada")
        
        cert_path = sessions[session_id].get("cert_path")
        if not cert_path or not os.path.exists(cert_path):
            raise HTTPException(404, "Certificado no encontrado")
        
        # Verificar certificado
        from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
        from cryptography.x509.oid import NameOID
        
        with open(cert_path, "rb") as f:
            p12_data = f.read()
        
        clave, certificado, cadena = load_key_and_certificates(
            p12_data, password.encode("utf-8")
        )
        
        if certificado is None:
            raise HTTPException(400, "Contraseña incorrecta o certificado inválido")
        
        # Extraer información
        attrs = certificado.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        nombre = attrs[0].value if attrs else "Desconocido"
        if isinstance(nombre, bytes):
            nombre = nombre.decode('utf-8', errors='ignore')
        
        emi = certificado.not_valid_before_utc
        exp = certificado.not_valid_after_utc
        
        from firma_ec_endesive import TZ_ECUADOR
        emi_local = emi.astimezone(TZ_ECUADOR)
        exp_local = exp.astimezone(TZ_ECUADOR)
        
        ahora = ahora_ecuador()
        vigente = emi_local <= ahora <= exp_local
        dias = (exp_local - ahora).days if vigente else 0
        
        sessions[session_id]["password"] = password
        sessions[session_id]["nombre_firmante"] = nombre
        
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
            raise HTTPException(404, "Sesión no encontrada")
        
        if not pdf.filename.endswith('.pdf'):
            raise HTTPException(400, "El archivo debe ser PDF")
        
        pdf_path = TEMP_DIR / f"{session_id}_document.pdf"
        with open(pdf_path, "wb") as f:
            content = await pdf.read()
            f.write(content)
        
        sessions[session_id]["pdf_path"] = str(pdf_path)
        sessions[session_id]["pdf_filename"] = pdf.filename
        
        return {"success": True, "filename": pdf.filename}
        
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/sign")
async def sign_document(request: SignRequest):
    """Firmar el documento"""
    try:
        session_id = request.session_id
        password = request.password
        
        if session_id not in sessions:
            raise HTTPException(404, "Sesión no encontrada")
        
        session = sessions[session_id]
        
        cert_path = session.get("cert_path")
        pdf_path = session.get("pdf_path")
        nombre_firmante = session.get("nombre_firmante")
        
        if not cert_path or not os.path.exists(cert_path):
            raise HTTPException(404, "Certificado no encontrado")
        
        if not pdf_path or not os.path.exists(pdf_path):
            raise HTTPException(404, "PDF no encontrado")
        
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
        
        sessions[session_id]["output_path"] = str(output_path)
        
        return {
            "success": True,
            "message": "Documento firmado exitosamente",
            "filename": f"{Path(pdf_path).stem}_firmado.pdf"
        }
        
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/download/{session_id}")
async def download(session_id: str):
    """Descargar PDF firmado"""
    try:
        if session_id not in sessions:
            raise HTTPException(404, "Sesión no encontrada")
        
        output_path = sessions[session_id].get("output_path")
        if not output_path or not os.path.exists(output_path):
            raise HTTPException(404, "Archivo no encontrado")
        
        filename = sessions[session_id].get("pdf_filename", "documento")
        filename = filename.replace(".pdf", "_firmado.pdf")
        
        return FileResponse(
            output_path,
            media_type="application/pdf",
            filename=filename
        )
        
    except Exception as e:
        raise HTTPException(500, str(e))


@app.delete("/session/{session_id}")
async def clear_session(session_id: str):
    """Limpiar sesión y archivos temporales"""
    try:
        if session_id in sessions:
            # Eliminar archivos temporales
            for key in ["cert_path", "pdf_path", "output_path"]:
                path = sessions[session_id].get(key)
                if path and os.path.exists(path):
                    try:
                        os.unlink(path)
                    except:
                        pass
            del sessions[session_id]
        
        return {"success": True}
        
    except Exception as e:
        raise HTTPException(500, str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)