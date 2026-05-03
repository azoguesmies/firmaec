#!/usr/bin/env python3
"""
====================================================================
 FIRMA ELECTRONICA ECUADOR - PAdES con endesive
====================================================================
Firma documentos PDF con certificado P12, compatible con FIRMAEC.
CORREGIDO: Busca automáticamente el certificado VIGENTE dentro del P12,
           incluso si el principal está vencido (soporte para renovaciones).
====================================================================
Uso:
    # Modo línea de comandos
    python firma_ec_endesive.py --p12 certificado.p12 --pass "clave" --pdf documento.pdf
    
    # Modo interactivo
    python firma_ec_endesive.py --interactive
"""

import argparse
import io
import os
import sys
import tempfile
import getpass
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ─────────────────────────────────────────────────────────────────
# VERIFICACION DE DEPENDENCIAS
# ─────────────────────────────────────────────────────────────────

try:
    from endesive.pdf import cms
except ImportError:
    print("ERROR: Instala endesive: pip install endesive")
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
    from cryptography.x509.oid import NameOID
    from cryptography.x509 import BasicConstraints
except ImportError:
    print("ERROR: Instala cryptography>=42.0.8: pip install cryptography>=42.0.8")
    sys.exit(1)

try:
    import qrcode
    from PIL import Image, ImageDraw, ImageFont, ImageFilter, ImageEnhance
except ImportError:
    print("ERROR: Instala qrcode y pillow: pip install 'qrcode[pil]' pillow")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────
# CONSTANTES
# ─────────────────────────────────────────────────────────────────

TZ_ECUADOR = timezone(timedelta(hours=-5))

# Configuración de la imagen de firma
IMAGEN_FIRMA_ANCHO = 300
IMAGEN_FIRMA_ALTO = 108
QR_SIZE = 80
QR_BOX_SIZE = 5
QR_BORDER = 2
QR_VERSION = 2

# Posición del campo de firma en el PDF
CAMPO_FIRMA_X = 50
CAMPO_FIRMA_Y = 80
CAMPO_FIRMA_W = 280
CAMPO_FIRMA_H = 100

# Calidad de la imagen
IMAGEN_CALIDAD = 100


def ahora_ecuador() -> datetime:
    """Retorna fecha/hora actual en UTC-5 (Ecuador)"""
    return datetime.now(TZ_ECUADOR)


def obtener_fuente(tamano: int, bold: bool = False):
    """Carga una fuente TrueType con soporte para negrita"""
    if bold:
        rutas = [
            "C:/Windows/Fonts/arialbd.ttf",
            "C:/Windows/Fonts/calibrib.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "/System/Library/Fonts/Helvetica-Bold.ttc",
        ]
    else:
        rutas = [
            "C:/Windows/Fonts/arial.ttf",
            "C:/Windows/Fonts/calibri.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/System/Library/Fonts/Helvetica.ttc",
        ]
    
    for ruta in rutas:
        if os.path.isfile(ruta):
            try:
                from PIL import ImageFont
                return ImageFont.truetype(ruta, tamano)
            except:
                continue
    
    from PIL import ImageFont
    return ImageFont.load_default()


def es_certificado_ca(cert) -> bool:
    """Determina si un certificado es de Autoridad Certificadora"""
    try:
        bc = cert.extensions.get_extension_for_class(BasicConstraints)
        return bc.value.ca
    except Exception:
        return False


def obtener_certificado_vigente(ruta_p12: str, contrasena: str):
    """
    Busca en TODO el P12 (principal + cadena) el certificado VIGENTE
    del mismo titular (mismo CN) que NO sea CA.
    
    Retorna (certificado_vigente, clave_privada, lista_cadena_completa, fecha_expiracion)
    o lanza excepción si no encuentra ninguno.
    """
    with open(ruta_p12, "rb") as f:
        p12_data = f.read()
    
    clave_privada, cert_principal, cadena = load_key_and_certificates(
        p12_data, contrasena.encode("utf-8")
    )
    
    if cert_principal is None:
        raise Exception("El archivo P12 no contiene un certificado con clave privada")
    
    ahora = ahora_ecuador()
    
    # Extraer CN del certificado principal (es el titular)
    attrs = cert_principal.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attrs:
        raise Exception("No se pudo extraer el nombre del titular del certificado")
    
    cn_titular = attrs[0].value
    if isinstance(cn_titular, bytes):
        cn_titular = cn_titular.decode('utf-8', errors='ignore')
    
    print(f"  Titular del certificado: {cn_titular}")
    print(f"  Buscando certificado vigente...")
    
    # Recopilar todos los certificados (principal + cadena)
    todos_certs = [cert_principal] + (cadena or [])
    
    mejor_cert = None
    mejor_fecha_exp = None
    
    for i, cert in enumerate(todos_certs):
        # Extraer CN del certificado actual
        attrs_cert = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not attrs_cert:
            continue
        
        cn_cert = attrs_cert[0].value
        if isinstance(cn_cert, bytes):
            cn_cert = cn_cert.decode('utf-8', errors='ignore')
        
        # Verificar que sea del mismo titular
        if cn_cert != cn_titular:
            continue
        
        # Verificar que NO sea CA
        if es_certificado_ca(cert):
            print(f"    [{i}] {cn_cert} - omitido (es CA)")
            continue
        
        # Verificar vigencia
        try:
            emi = cert.not_valid_before_utc.replace(tzinfo=timezone.utc).astimezone(TZ_ECUADOR)
            exp = cert.not_valid_after_utc.replace(tzinfo=timezone.utc).astimezone(TZ_ECUADOR)
        except AttributeError:
            emi = cert.not_valid_before.replace(tzinfo=timezone.utc).astimezone(TZ_ECUADOR)
            exp = cert.not_valid_after.replace(tzinfo=timezone.utc).astimezone(TZ_ECUADOR)
        
        if emi <= ahora <= exp:
            dias = (exp - ahora).days
            print(f"    ✓ [{i}] {cn_cert} - VIGENTE (expira en {dias} días, {exp.strftime('%d/%m/%Y')})")
            
            # Elegir el que expire más tarde (por si hay múltiples vigentes)
            if mejor_fecha_exp is None or exp > mejor_fecha_exp:
                mejor_cert = cert
                mejor_fecha_exp = exp
        else:
            estado = "aún no vigente" if ahora < emi else "vencido"
            print(f"    ✗ [{i}] {cn_cert} - {estado} (expiraba: {exp.strftime('%d/%m/%Y')})")
    
    if mejor_cert is None:
        raise Exception(f"No se encontró ningún certificado VIGENTE para el titular '{cn_titular}'")
    
    # Mostrar información del certificado encontrado
    emi, exp = None, None
    try:
        emi = mejor_cert.not_valid_before_utc.replace(tzinfo=timezone.utc).astimezone(TZ_ECUADOR)
        exp = mejor_cert.not_valid_after_utc.replace(tzinfo=timezone.utc).astimezone(TZ_ECUADOR)
    except AttributeError:
        emi = mejor_cert.not_valid_before.replace(tzinfo=timezone.utc).astimezone(TZ_ECUADOR)
        exp = mejor_cert.not_valid_after.replace(tzinfo=timezone.utc).astimezone(TZ_ECUADOR)
    
    dias = (exp - ahora).days
    print(f"\n  ✅ Usando certificado VIGENTE:")
    print(f"     Titular: {cn_titular}")
    print(f"     Emisión: {emi.strftime('%d/%m/%Y')}")
    print(f"     Expira:  {exp.strftime('%d/%m/%Y')} ({dias} días restantes)")
    
    return mejor_cert, clave_privada, cadena, exp


def generar_imagen_firma_alta_resolucion(nombre_firmante: str, fecha_firma: str, 
                                          fecha_expiracion: datetime = None) -> io.BytesIO:
    """
    Genera una imagen PNG de alta resolución con el sello de firma.
    Incluye fecha de expiración del certificado si está disponible.
    """
    # Crear imagen en blanco
    img = Image.new("RGB", (IMAGEN_FIRMA_ANCHO, IMAGEN_FIRMA_ALTO), "#FFFFFF")
    draw = ImageDraw.Draw(img)
    
    # ─────────────────────────────────────────────────────────
    # 1. Generar QR code con alta resolución
    # ─────────────────────────────────────────────────────────
    datos_qr = (
        f"Documento firmado digitalmente\n"
        f"Firmante: {nombre_firmante}\n"
        f"Fecha: {fecha_firma}\n"
        f"Estandar: PAdES - Ecuador"
    )
    
    qr = qrcode.QRCode(
        version=QR_VERSION,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=QR_BOX_SIZE,
        border=QR_BORDER,
    )
    qr.add_data(datos_qr)
    qr.make(fit=True)
    
    img_qr = qr.make_image(fill_color="#000000", back_color="#FFFFFF").convert("RGB")
    img_qr = img_qr.resize((QR_SIZE, QR_SIZE), Image.Resampling.LANCZOS)
    
    # Mejorar contraste y nitidez del QR
    enhancer = ImageEnhance.Contrast(img_qr)
    img_qr = enhancer.enhance(1.5)
    img_qr = img_qr.filter(ImageFilter.UnsharpMask(radius=0.5, percent=100, threshold=0))
    
    # Pegar QR
    y_qr = (IMAGEN_FIRMA_ALTO - QR_SIZE) // 2
    x_qr = 10
    img.paste(img_qr, (x_qr, y_qr))
    
    # ─────────────────────────────────────────────────────────
    # 2. Línea separadora
    # ─────────────────────────────────────────────────────────
    separador_x = QR_SIZE + 22
    draw.line([(separador_x, 8), (separador_x, IMAGEN_FIRMA_ALTO - 8)], fill="#999999", width=1)
    
    # ─────────────────────────────────────────────────────────
    # 3. Texto
    # ─────────────────────────────────────────────────────────
    x_texto = QR_SIZE + 35
    y_centro = IMAGEN_FIRMA_ALTO // 2
    
    altura_total_texto = 50
    y_inicio = y_centro - (altura_total_texto // 2)
    
    fuente_etiq = obtener_fuente(9)
    fuente_nombre = obtener_fuente(11, bold=True)
    fuente_fecha = obtener_fuente(9)
    
    texto_etiqueta = "Firmado digitalmente por:"
    texto_nombre = nombre_firmante[:32]
    texto_fecha = fecha_firma
    
    draw.text((x_texto, y_inicio), texto_etiqueta, fill="#555555", font=fuente_etiq)
    draw.text((x_texto, y_inicio + 16), texto_nombre, fill="#000000", font=fuente_nombre)
    draw.text((x_texto, y_inicio + 34), texto_fecha, fill="#333333", font=fuente_fecha)
    
    # ─────────────────────────────────────────────────────────
    # 4. Borde
    # ─────────────────────────────────────────────────────────
    draw.rectangle([(2, 2), (IMAGEN_FIRMA_ANCHO - 2, IMAGEN_FIRMA_ALTO - 2)], outline="#CCCCCC", width=1)
    
    # ─────────────────────────────────────────────────────────
    # 5. Guardar
    # ─────────────────────────────────────────────────────────
    img_bytes = io.BytesIO()
    img.save(img_bytes, format="PNG", quality=IMAGEN_CALIDAD, optimize=True)
    img_bytes.seek(0)
    
    return img_bytes


def obtener_nombre_del_certificado_vigente(ruta_p12: str, contrasena: str) -> tuple:
    """Obtiene el nombre del certificado vigente y la fecha de expiración"""
    cert, clave, cadena, expiracion = obtener_certificado_vigente(ruta_p12, contrasena)
    
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    nombre = attrs[0].value if attrs else "Firmante"
    if isinstance(nombre, bytes):
        nombre = nombre.decode('utf-8', errors='ignore')
    
    return nombre, cert, clave, cadena, expiracion


def firmar_con_endesive(pdf_bytes: bytes, ruta_p12: str, contrasena: str,
                         nombre_firmante: str, fecha_firma: str) -> bytes:
    """
    Firma el PDF usando endesive con signature_img.
    Usa el certificado vigente (busca en todo el P12).
    """
    # Obtener certificado vigente (busca en principal y cadena)
    print("    Buscando certificado vigente en el P12...")
    cert_vigente, clave_privada, cadena, fecha_exp = obtener_certificado_vigente(ruta_p12, contrasena)
    
    # Generar la imagen de la firma
    print("    Generando imagen de firma (QR mejorado)...")
    img_bytes = generar_imagen_firma_alta_resolucion(nombre_firmante, fecha_firma, fecha_exp)
    
    # Guardar imagen temporalmente
    img_temp = Path(tempfile.gettempdir()) / f"signature_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.png"
    with open(img_temp, "wb") as f:
        f.write(img_bytes.getvalue())
    
    # Formato de fecha Adobe
    ahora = ahora_ecuador()
    fecha_adobe = ahora.strftime("D:%Y%m%d%H%M%S-05'00'")
    
    # Configuración de la firma
    udct = {
        "sigflags": 3,
        "sigflagsft": 132,
        "sigpage": 0,
        "sigbutton": True,
        "sigfield": "Signature1",
        "auto_sigfield": True,
        "sigandcertify": False,
        "signaturebox": (CAMPO_FIRMA_X, CAMPO_FIRMA_Y,
                         CAMPO_FIRMA_X + CAMPO_FIRMA_W,
                         CAMPO_FIRMA_Y + CAMPO_FIRMA_H),
        "signature_img": str(img_temp),
        "signature_img_distort": False,
        "signature_img_width": CAMPO_FIRMA_W,
        "signature_img_height": CAMPO_FIRMA_H,
        "contact": nombre_firmante,
        "location": "Ecuador",
        "signingdate": fecha_adobe,
        "reason": f"Documento firmado digitalmente por {nombre_firmante}",
    }
    
    print("    Aplicando firma digital PAdES...")
    
    try:
        datas = cms.sign(
            datau=pdf_bytes,
            udct=udct,
            key=clave_privada,
            cert=cert_vigente,
            othercerts=cadena or [],
            algomd="sha256"
        )
    finally:
        if img_temp.exists():
            img_temp.unlink()
    
    return pdf_bytes + datas


def procesar_documento(ruta_pdf: str, ruta_p12: str, contrasena: str,
                        nombre_firmante: str, fecha_firma: str) -> str:
    """Proceso completo: aplicar firma digital con endesive"""
    ruta = Path(ruta_pdf)
    ruta_salida = ruta.parent / f"{ruta.stem}_firmado.pdf"

    print(f"\n  📄 Procesando: {ruta.name}")

    with open(ruta_pdf, "rb") as f:
        pdf_original = f.read()

    pdf_firmado = firmar_con_endesive(
        pdf_original, ruta_p12, contrasena, nombre_firmante, fecha_firma
    )

    with open(ruta_salida, "wb") as f:
        f.write(pdf_firmado)

    tamaño = os.path.getsize(ruta_salida) / 1024
    print(f"    💾 Guardado: {ruta_salida.name} ({tamaño:.1f} KB)")

    return str(ruta_salida)


def modo_interactivo():
    """Modo interactivo: solicita los datos al usuario"""
    print("\n" + "="*60)
    print("  MODO INTERACTIVO - FIRMA ELECTRONICA ECUADOR")
    print("="*60)
    
    while True:
        ruta_p12 = input("\n📜 Ruta del certificado P12: ").strip()
        if os.path.isfile(ruta_p12):
            break
        print(f"  ❌ Archivo no encontrado: {ruta_p12}")
    
    contrasena = getpass.getpass("🔒 Contraseña del certificado: ")
    while not contrasena:
        print("  ❌ La contraseña no puede estar vacía.")
        contrasena = getpass.getpass("🔒 Contraseña del certificado: ")
    
    while True:
        ruta_pdf = input("\n📄 Ruta del PDF a firmar: ").strip()
        if os.path.isfile(ruta_pdf):
            break
        print(f"  ❌ Archivo no encontrado: {ruta_pdf}")
    
    print(f"\n  Certificado: {Path(ruta_p12).name}")
    print(f"  Documento: {Path(ruta_pdf).name}")
    confirmar = input("\n  ¿Desea continuar con la firma? (s/N): ").strip().lower()
    
    if confirmar != 's':
        print("  Operación cancelada.")
        return
    
    print(f"\n📜 Analizando certificado...")
    try:
        nombre_firmante, cert, clave, cadena, fecha_exp = obtener_nombre_del_certificado_vigente(
            ruta_p12, contrasena
        )
        print(f"   Firmante: {nombre_firmante}")
        
        fecha_firma = ahora_ecuador().strftime("%d/%m/%Y %H:%M:%S")
        print(f"   Fecha: {fecha_firma} (UTC-5)")
        
        salida = procesar_documento(
            ruta_pdf, ruta_p12, contrasena, nombre_firmante, fecha_firma
        )
        print(f"\n  ✅ FIRMA EXITOSA!")
        print(f"  📁 Archivo generado: {salida}")
    except Exception as e:
        print(f"\n  ❌ ERROR: {e}")
        import traceback
        traceback.print_exc()


def modo_linea_comandos(args):
    """Modo línea de comandos tradicional"""
    if not os.path.isfile(args.p12):
        sys.exit(f"❌ Certificado no encontrado: {args.p12}")

    invalidos = [p for p in args.pdfs if not os.path.isfile(p)]
    if invalidos:
        sys.exit(f"❌ PDFs no encontrados: {invalidos}")

    print(f"\n{'='*60}")
    print("  FIRMA ELECTRONICA ECUADOR - PAdES (con soporte para renovaciones)")
    print(f"{'='*60}")

    print(f"\n📜 Analizando certificado: {Path(args.p12).name}")
    try:
        nombre_firmante, cert, clave, cadena, fecha_exp = obtener_nombre_del_certificado_vigente(
            args.p12, args.contrasena
        )
    except Exception as e:
        sys.exit(f"❌ Error al leer el certificado: {e}")

    fecha_firma = ahora_ecuador().strftime("%d/%m/%Y %H:%M:%S")
    print(f"   Fecha: {fecha_firma} (UTC-5)")
    print(f"   Documentos: {len(args.pdfs)}")

    exitosos = []
    fallidos = []

    for pdf_file in args.pdfs:
        try:
            salida = procesar_documento(
                pdf_file, args.p12, args.contrasena,
                nombre_firmante, fecha_firma
            )
            exitosos.append((pdf_file, salida))
        except Exception as e:
            fallidos.append((pdf_file, str(e)))
            print(f"    ❌ ERROR: {e}")
            import traceback
            traceback.print_exc()

    print(f"\n{'='*60}")
    print(f"  RESUMEN")
    print(f"{'='*60}")
    print(f"  ✅ Exitosos: {len(exitosos)}")
    if fallidos:
        print(f"  ❌ Fallidos: {len(fallidos)}")
        for pdf, error in fallidos:
            print(f"      - {Path(pdf).name}: {error}")

    if exitosos:
        print(f"\n  Archivos generados:")
        for orig, firmado in exitosos:
            print(f"      📄 {Path(orig).name} → {Path(firmado).name}")

    print(f"\n  Verificar con FIRMAEC o Adobe Acrobat Reader")
    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Firma Electrónica Ecuador - PAdES con endesive (soporta renovaciones)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modos de uso:
  # Modo línea de comandos
  python %(prog)s --p12 certificado.p12 --pass "clave" --pdfs documento.pdf
  
  # Modo interactivo
  python %(prog)s --interactive
  
Características:
  - Busca automáticamente el certificado VIGENTE dentro del P12
  - Soporta certificados renovados (principal vencido, renovaciones en cadena)
        """
    )
    parser.add_argument("--p12", help="Ruta al certificado P12")
    parser.add_argument("--pass", dest="contrasena", help="Contraseña del certificado")
    parser.add_argument("--pdfs", nargs="+", help="Uno o más PDFs a firmar")
    parser.add_argument("--interactive", action="store_true", 
                       help="Modo interactivo (solicita datos al usuario)")
    
    args = parser.parse_args()
    
    if args.interactive:
        modo_interactivo()
        return
    
    if not args.p12 or not args.contrasena or not args.pdfs:
        parser.print_help()
        print("\n❌ Error: Debe especificar --p12, --pass y --pdfs")
        print("   O use --interactive para modo interactivo")
        sys.exit(1)
    
    modo_linea_comandos(args)


if __name__ == "__main__":
    main()