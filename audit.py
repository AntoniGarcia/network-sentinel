"""Auditoría acotada: conexiones TCP, HEAD HTTP y handshake TLS.

No autentica, no sigue redirecciones, no ejecuta payloads ni modifica objetivos.
La política de destinos se aplica en NetworkSecurity.start_audit().
"""
import hashlib
import ipaddress
import re
import socket
import ssl
import time
import uuid
from urllib.parse import urlsplit

AUDIT_PORTS = (21, 22, 23, 80, 139, 443, 445, 3389, 5900, 8080, 8443)
HTTP_PORTS = (80, 8080)
TLS_PORTS = (443, 8443)
TIMEOUT = 1.0
MAX_HEADERS = 16384
TLS_REFERENCE = 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html'
HTTP_REFERENCE = 'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html'


def validate_hostname(value):
    """Host/SNI opcional. Nunca se usa para resolver ni cambiar la IP objetivo."""
    value = value.strip().rstrip('.')
    if not value:
        return ''
    try:
        value = value.encode('idna').decode('ascii')
    except UnicodeError as exc:
        raise ValueError('Nombre DNS no válido.') from exc
    if len(value) > 253 or not all(re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', p)
                                   for p in value.split('.')):
        raise ValueError('Escribe sólo un nombre DNS, sin URL, ruta ni puerto.')
    return value.lower()


def finding(ip, port, rule, severity, evidence, remedy, group, confidence='Comprobación directa', reference=''):
    return dict(ID=hashlib.sha256(f'{ip}:{port}:{rule}'.encode()).hexdigest()[:20], IP=ip,
                Puerto=port, Regla=rule, Prioridad=severity, Evidencia=evidence[:1000],
                Recomendacion=remedy, Grupo=group, Confianza=confidence, Referencia=reference,
                Hora=time.time(), Verificacion='Detectado', Gestion='Pendiente', Nota='')


def assess_http(ip, port, response, secure=False, hostname=''):
    group = f'http_html:{port}'
    headers, status = response['headers'], response['status']
    result = []
    if not secure and response.get('redirect_scheme') != 'https':
        result.append(finding(ip, port, 'HTTP sin redirección HTTPS en /', 'Media',
            f'HEAD / respondió HTTP {status}; no se observó redirección HTTPS.',
            'Si este servicio maneja datos sensibles, habilita HTTPS y redirige HTTP. '
            'Comprueba que los clientes legítimos sigan funcionando.', f'http_transport:{port}', reference=TLS_REFERENCE))
    # No recomendar cabeceras para protocolos ajenos o respuestas sin contexto HTML.
    if 'text/html' in headers.get('content-type', '').lower() and 200 <= status < 400:
        if headers.get('x-content-type-options', '').lower() != 'nosniff':
            result.append(finding(ip, port, 'HTML sin X-Content-Type-Options: nosniff', 'Baja',
                f'HEAD / HTTP {status}, Content-Type HTML; cabecera nosniff ausente o diferente.',
                'Configura X-Content-Type-Options: nosniff y tipos MIME correctos en el servidor web.',
                group, reference=HTTP_REFERENCE))
        csp = headers.get('content-security-policy', '').lower()
        if not re.search(r'(?:^|;)\s*frame-ancestors\s+', csp) and headers.get('x-frame-options', '').lower() not in ('deny', 'sameorigin'):
            result.append(finding(ip, port, 'HTML sin política anti-framing observada', 'Baja',
                'No se observó frame-ancestors en CSP ni X-Frame-Options DENY/SAMEORIGIN.',
                "Define Content-Security-Policy: frame-ancestors 'self' (o 'none') según el uso de iframes de la aplicación.",
                group, reference=HTTP_REFERENCE))
        if secure and hostname and not re.search(r'\bmax-age\s*=\s*[1-9]\d*', headers.get('strict-transport-security', '').lower()):
            result.append(finding(ip, port, 'HSTS no observado para el nombre DNS', 'Baja',
                'Respuesta HTTPS HTML sin un max-age HSTS positivo.',
                'Tras asegurar certificados válidos y HTTPS estable, configura HSTS para ese nombre. '
                'No añadas includeSubDomains sin revisar todos los subdominios.', group, reference=HTTP_REFERENCE))
    return result


def http_probe(ip, port, secure=False, hostname=''):
    """Lee sólo cabeceras acotadas. No guarda cuerpo, cookies ni autenticación."""
    host = validate_hostname(hostname) or ip
    raw = socket.create_connection((ip, port), timeout=TIMEOUT)
    stream = raw
    try:
        if secure:
            # Exclusivamente esta conexión: se inspeccionan cabeceras aunque el
            # certificado falle; la validación independiente queda en tls_probe.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            stream = context.wrap_socket(raw, server_hostname=host)
        stream.settimeout(TIMEOUT)
        stream.sendall(f'HEAD / HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\nUser-Agent: NetworkSentinel-Audit/1\r\n\r\n'.encode('ascii'))
        data = b''
        deadline = time.monotonic() + TIMEOUT
        while b'\r\n\r\n' not in data and len(data) < MAX_HEADERS:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Tiempo límite al recibir cabeceras HTTP.')
            stream.settimeout(remaining)
            chunk = stream.recv(min(4096, MAX_HEADERS - len(data)))
            if not chunk:
                break
            data += chunk
        if b'\r\n\r\n' not in data:
            raise ValueError('Cabeceras incompletas o superiores a 16 KiB; prueba no evaluable.')
        lines = data.split(b'\r\n\r\n', 1)[0].decode('iso-8859-1').split('\r\n')
        match = re.fullmatch(r'HTTP/1\.[01] (\d{3})(?: .*)?', lines[0])
        if not match:
            raise ValueError('El servicio no respondió con HTTP/1.x reconocible.')
        allowed = {'content-type', 'x-content-type-options', 'x-frame-options',
                   'content-security-policy', 'strict-transport-security', 'server'}
        headers, redirect_scheme = {}, ''
        for line in lines[1:]:
            if ':' not in line:
                continue
            name, value = line.split(':', 1)
            name, value = name.lower().strip(), value.strip()
            if name in allowed:
                headers[name] = value[:1000]
            if name == 'location' and 300 <= int(match[1]) < 400:
                redirect_scheme = urlsplit(value).scheme.lower()
        return dict(status=int(match[1]), headers=headers, redirect_scheme=redirect_scheme)
    finally:
        stream.close()
        if stream is not raw:
            raw.close()


def tls_probe(ip, port, hostname=''):
    """Valida contra almacén CA del Python local y el nombre/IP indicado."""
    context = ssl.create_default_context()
    with socket.create_connection((ip, port), timeout=TIMEOUT) as raw:
        with context.wrap_socket(raw, server_hostname=validate_hostname(hostname) or ip) as stream:
            return dict(version=stream.version(), cipher=stream.cipher()[0],
                        fingerprint=hashlib.sha256(stream.getpeercert(binary_form=True)).hexdigest())


def run_audit(ip, hostname='', cancel=None, progress=None, ports=AUDIT_PORTS):
    ip = str(ipaddress.IPv4Address(ip))
    hostname = validate_hostname(hostname)
    report = dict(id=uuid.uuid4().hex, ip=ip, hostname=hostname, started=time.time(),
                  finished=None, cancelled=False, checks=[], findings=[], completed_groups=[])
    exposures = {21:('FTP', 'Desactiva FTP si no es necesario o usa SFTP/FTPS; comprueba la configuración real.'),
                 23:('Telnet', 'Sustituye Telnet por SSH y restringe el acceso de administración.'),
                 139:('NetBIOS', 'Deshabilita NetBIOS si no se utiliza y restringe el servicio por firewall.'),
                 445:('SMB', 'Revisa actualizaciones del sistema, SMBv1 deshabilitado y acceso limitado a equipos necesarios.'),
                 3389:('RDP', 'Mantén el sistema actualizado, habilita NLA y limita el acceso a administración/VPN.'),
                 5900:('VNC', 'Revisa autenticación y cifrado en el producto concreto; limita el acceso de red.')}
    for port in ports:
        if cancel and cancel.is_set():
            report['cancelled'] = True
            break
        group = f'tcp:{port}'
        try:
            with socket.create_connection((ip, port), timeout=TIMEOUT):
                pass
        except ConnectionRefusedError:
            report['checks'].append(dict(Puerto=port, Prueba='TCP', Estado='Cerrado', Detalle='Conexión rechazada; no demuestra la ausencia de otras superficies.'))
        except OSError as exc:
            report['checks'].append(dict(Puerto=port, Prueba='TCP', Estado='No evaluable', Detalle=str(exc)[:300]))
        else:
            report['completed_groups'].append(group)
            report['checks'].append(dict(Puerto=port, Prueba='TCP', Estado='Abierto', Detalle='Conexión TCP establecida; no identifica versión ni vulnerabilidad.'))
            if port in exposures:
                name, remedy = exposures[port]
                report['findings'].append(finding(ip, port, f'Revisar exposición {name}', 'Revisar',
                    f'Conexión TCP a {ip}:{port} aceptada. Servicio estimado por puerto, no confirmado.',
                    remedy, group, confidence='Exposición, no CVE confirmada'))
            if port in TLS_PORTS and not (cancel and cancel.is_set()):
                try:
                    tls = tls_probe(ip, port, hostname)
                    report['completed_groups'].append(f'tls:{port}')
                    report['checks'].append(dict(Puerto=port, Prueba='TLS', Estado='Validado',
                        Detalle=f"{tls['version']} · {tls['cipher']} · SHA256 {tls['fingerprint']}"))
                except ssl.SSLCertVerificationError as exc:
                    report['completed_groups'].append(f'tls:{port}')
                    report['checks'].append(dict(Puerto=port, Prueba='TLS', Estado='Certificado no validado', Detalle=str(exc)[:300]))
                    report['findings'].append(finding(ip, port, 'Certificado TLS no validado', 'Media',
                        f"Validación para {hostname or ip}: {exc}",
                        'Comprueba fecha del equipo, nombre DNS, caducidad, cadena de certificados y CA interna. '
                        'Instala o renueva el certificado adecuado. Un certificado privado/autofirmado no prueba explotación.',
                        f'tls:{port}', reference=TLS_REFERENCE))
                except (OSError, ValueError) as exc:
                    report['checks'].append(dict(Puerto=port, Prueba='TLS', Estado='No evaluable', Detalle=str(exc)[:300]))
            if port in HTTP_PORTS + TLS_PORTS and not (cancel and cancel.is_set()):
                try:
                    response = http_probe(ip, port, port in TLS_PORTS, hostname)
                    report['completed_groups'].append(f'http_transport:{port}')
                    if 'text/html' in response['headers'].get('content-type', '').lower() and 200 <= response['status'] < 400:
                        report['completed_groups'].append(f'http_html:{port}')
                    report['checks'].append(dict(Puerto=port, Prueba='HTTP HEAD /', Estado='Evaluado',
                        Detalle=f"HTTP {response['status']} · Servidor declarado: {response['headers'].get('server', 'no indicado')}"))
                    report['findings'].extend(assess_http(ip, port, response, port in TLS_PORTS, hostname))
                except (OSError, ValueError) as exc:
                    report['checks'].append(dict(Puerto=port, Prueba='HTTP HEAD /', Estado='No evaluable', Detalle=str(exc)[:300]))
        if progress:
            progress(port)
    report['cancelled'] = report['cancelled'] or bool(cancel and cancel.is_set())
    report['finished'] = time.time()
    return report


def reconcile(previous, current):
    """Un servicio inaccesible nunca se convierte automáticamente en 'parchado'."""
    findings = {row['ID']: dict(row) for row in current['findings']}
    for row in (previous or {}).get('findings', []):
        if row['ID'] in findings:
            findings[row['ID']].update(Gestion=row.get('Gestion', 'Pendiente'), Nota=row.get('Nota', ''))
        else:
            copy = dict(row)
            copy['Verificacion'] = ('No observado en reauditoría' if row['Grupo'] in current['completed_groups']
                                    else 'Sin verificar en reauditoría')
            findings[row['ID']] = copy
    return dict(current, findings=list(findings.values())[:128])
