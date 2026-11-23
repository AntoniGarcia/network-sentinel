"""Telemetría defensiva acotada; descubrimiento local explícito sin dependencias extra."""
from collections import OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor
import errno
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time
import uuid
import copy

import psutil
from device_registry import DeviceRegistry, normalize_mac
from audit import AUDIT_PORTS, validate_hostname, run_audit, reconcile

PRIVATE = tuple(ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
CHECK_PORTS = (21, 22, 23, 53, 80, 139, 443, 445, 3389, 5900, 8080, 8443)
SERVICES = {21:'FTP',22:'SSH',23:'Telnet',53:'DNS',80:'HTTP',139:'NetBIOS',443:'HTTPS',445:'SMB',3389:'RDP',5900:'VNC',8080:'HTTP alternativo',8443:'HTTPS alternativo',123:'NTP',5353:'mDNS',1900:'SSDP'}


def local_networks():
    result = []
    stats = psutil.net_if_stats()
    for name, addresses in psutil.net_if_addrs().items():
        if name not in stats or not stats[name].isup:
            continue
        for addr in addresses:
            if addr.family != socket.AF_INET or not addr.netmask:
                continue
            interface = ipaddress.ip_interface(f'{addr.address}/{addr.netmask}')
            if any(interface.ip in net for net in PRIVATE):
                result.append(dict(interface=name, ip=str(interface.ip), network=str(interface.network)))
    return result


def validate_network(value):
    net = ipaddress.ip_network(value, strict=False)
    if net.version != 4 or net.num_addresses > 256 or not any(net.subnet_of(n) for n in PRIVATE):
        raise ValueError('Selecciona una subred IPv4 privada de hasta 256 direcciones (/24 o menor).')
    if not any(net.subnet_of(ipaddress.ip_network(row['network'])) for row in local_networks()):
        raise ValueError('La subred debe pertenecer a un adaptador local activo.')
    return net


def parse_neighbors(output):
    """Acepta arp -a (Windows/macOS) e ip neigh (Linux), sin depender del idioma."""
    rows = []
    for line in output.splitlines():
        ip = re.search(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])', line)
        mac = re.search(r'\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b', line)
        if ip and mac:
            try:
                address = ipaddress.IPv4Address(ip.group())
                normalized = mac.group().replace('-', ':').lower()
                if not address.is_multicast and not address.is_unspecified and normalized not in ('00:00:00:00:00:00','ff:ff:ff:ff:ff:ff'):
                    rows.append((str(address), normalized))
            except ValueError:
                pass
    return rows


class NetworkSecurity:
    MAX_DEVICES = 1024
    MAX_CONNECTIONS = 4096

    def __init__(self, registry_path=None):
        self.lock = threading.RLock()
        self.registry = DeviceRegistry(registry_path)
        self.devices = OrderedDict()
        self.connections = OrderedDict()
        self.dns = deque(maxlen=1000)
        self.alerts = deque(maxlen=500)
        self._dedup = OrderedDict()
        self._syn = OrderedDict()
        self._networks = [ipaddress.ip_network(row['network']) for row in local_networks()]
        self._own = {addr.address for addrs in psutil.net_if_addrs().values() for addr in addrs if addr.family == socket.AF_INET}
        self._job = None
        self._cancel = threading.Event()
        self.job_status = dict(running=False, message='Sin tareas activas', progress=0, total=0, error=None)
        self.port_results = []
        self.audit_reports = OrderedDict()

    def refresh_context(self):
        """Actualizar adaptadores antes de acciones, sin depender de la LAN al abrir la app."""
        networks = [ipaddress.ip_network(row['network']) for row in local_networks()]
        own = {addr.address for addrs in psutil.net_if_addrs().values()
               for addr in addrs if addr.family == socket.AF_INET}
        with self.lock:
            self._networks, self._own = networks, own
            for row in self.devices.values():
                row['Tipo'] = 'Este equipo' if row['IP'] in own else 'LAN' if self.is_lan(row['IP']) else 'Externo'

    def _metadata(self, row):
        address = ipaddress.IPv4Address(row['IP'])
        network = next((net for net in sorted(self._networks, key=lambda net: -net.prefixlen)
                        if address in net), None)
        record = self.registry.get(str(network), row['IP'], row['MAC']) if network else None
        return dict(Nombre=record['name'] if record else '', Notas=record['notes'] if record else '',
                    Reconocido=bool(record and record['recognized']), Subred=str(network) if network else '',
                    Identificacion='MAC + subred' if row['MAC'] else 'Sólo IP (débil)')

    def save_device(self, ip, name, notes='', recognized=False):
        with self.lock:
            row = self.devices.get(ip)
            if row is None or not self.is_lan(ip):
                raise ValueError('Selecciona un dispositivo de la LAN observada.')
            meta = self._metadata(row)
            self.registry.save(meta['Subred'], ip, row['MAC'], name, notes, recognized)
            if recognized:
                self._resolve_new_device(ip)

    def _resolve_new_device(self, ip):
        for alert in self.alerts:
            if alert['Regla'] == 'Dispositivo nuevo' and alert['IP'] == ip and alert['Estado'] == 'Pendiente':
                alert.update(Estado='Reconocido', Revisada=time.time())

    def review_alert(self, alert_id):
        with self.lock:
            for alert in self.alerts:
                if alert['ID'] == alert_id:
                    alert.update(Estado='Revisada', Revisada=time.time())
                    return True
            return False

    def is_lan(self, ip):
        try:
            address = ipaddress.ip_address(ip)
            return any(address in net for net in self._networks)
        except ValueError:
            return False

    def _alert(self, rule, subject, severity, message):
        now = time.monotonic()
        key = (rule, subject)
        if now - self._dedup.get(key, -1000) < 60:
            return
        self._dedup[key] = now
        self._dedup.move_to_end(key)
        while len(self._dedup) > 2048:
            self._dedup.popitem(last=False)
        self.alerts.appendleft(dict(ID=uuid.uuid4().hex, Hora=time.time(), Nivel=severity,
                                   Regla=rule, IP=subject, Detalle=message, Estado='Pendiente', Revisada=None))

    def observe_device(self, ip, mac='', source='Tráfico IPv4', confirmed=True):
        try:
            address = ipaddress.IPv4Address(ip)
        except ValueError:
            return
        if address.is_multicast or address.is_unspecified or any(address == net.broadcast_address for net in self._networks):
            return
        with self.lock:
            new = ip not in self.devices
            if new:
                self.devices[ip] = dict(IP=ip, MAC='', Tipo='Este equipo' if ip in self._own else 'LAN' if self.is_lan(ip) else 'Externo',
                    Fuente=source, Primero=time.time(), Ultimo=time.time(), Confirmado=None, Bytes=0)
            entry = self.devices[ip]
            mac = normalize_mac(mac)
            if mac:
                if entry['MAC'] and entry['MAC'] != mac and self.is_lan(ip):
                    self._alert('Cambio de MAC', ip, 'Revisar', f"{entry['MAC']} → {mac}. Puede ser DHCP, MAC aleatoria o cambio de equipo.")
                entry['MAC'] = mac
            entry.update(Ultimo=time.time(), Fuente=source)
            first_confirmation = entry['Confirmado'] is None and confirmed and not source.startswith('Caché')
            if confirmed and not source.startswith('Caché'):
                entry['Confirmado'] = time.time()
            # Las lecturas sin MAC no heredan reconocimiento de una MAC guardada.
            # Si ARP aporta la identidad después, resolver el aviso provisional.
            if self.is_lan(ip) and ip not in self._own:
                if self._metadata(entry)['Reconocido']:
                    self._resolve_new_device(ip)
                elif first_confirmation:
                    self._alert('Dispositivo nuevo', ip, 'Info', 'Identidad todavía no reconocida. Puede faltar su MAC; no implica intrusión.')
            self.devices.move_to_end(ip)
            while len(self.devices) > self.MAX_DEVICES:
                self.devices.popitem(last=False)

    def observe_packet(self, src, dst, sport, dport, proto, length, syn=False, ack=False):
        now = time.monotonic()
        with self.lock:
            self.observe_device(src)
            if dst != src:
                self.observe_device(dst, source='Destino IPv4 (sin confirmar)', confirmed=False)
            for ip in {src, dst}:
                if ip in self.devices:
                    self.devices[ip]['Bytes'] += length
            key = (src, dst, sport, dport, proto)
            row = self.connections.setdefault(key, dict(Origen=src, Destino=dst, Puerto_origen=sport,
                Puerto_destino=dport, Protocolo=proto.upper(), Servicio=SERVICES.get(dport, 'Otro'),
                Bytes=0, Paquetes=0, Ultimo=time.time()))
            row['Bytes'] += length
            row['Paquetes'] += 1
            row['Ultimo'] = time.time()
            self.connections.move_to_end(key)
            while len(self.connections) > self.MAX_CONNECTIONS:
                self.connections.popitem(last=False)
            # Sólo SYN sin ACK: no confundir respuestas de puertos efímeros con barridos.
            if syn and not ack:
                pair = (src, dst)
                ports = self._syn.setdefault(pair, OrderedDict())
                ports[dport] = now
                ports.move_to_end(dport)
                while ports and next(iter(ports.values())) < now - 10:
                    ports.popitem(last=False)
                while len(ports) > 128:
                    ports.popitem(last=False)
                self._syn.move_to_end(pair)
                while len(self._syn) > 512:
                    self._syn.popitem(last=False)
                if len(ports) >= 20:
                    self._alert('Posible barrido TCP', src, 'Revisar', f'{len(ports)} puertos de {dst} en 10 s; verifica si es una herramienta autorizada.')
            if dport in (21, 23) and self.is_lan(src):
                self._alert('Servicio sin cifrado habitual', src, 'Revisar', f'Tráfico hacia {dst}:{dport} ({SERVICES[dport]}). El puerto no confirma contenido ni vulnerabilidad.')

    def observe_dns(self, client, domain, response):
        with self.lock:
            self.dns.appendleft(dict(Hora=time.time(), Cliente=client, Dominio=str(domain)[:253],
                                     Tipo='Respuesta' if response else 'Consulta'))

    def snapshot(self):
        with self.lock:
            now = time.time()
            devices = [dict(row, **self._metadata(row), Presencia_reciente=bool(row['Confirmado'] and now-row['Confirmado'] < 120))
                       for row in self.devices.values()]
            return dict(devices=devices, connections=[dict(r) for r in self.connections.values()],
                        dns=[dict(r) for r in self.dns], alerts=[dict(r) for r in self.alerts], job=dict(self.job_status),
                        ports=[dict(r) for r in self.port_results], registry=self.registry.list_records(),
                        registry_error=self.registry.error, audits=copy.deepcopy(list(self.audit_reports.values())))

    def _launch(self, target, total):
        with self.lock:
            if self._job and self._job.is_alive():
                return False
            self._cancel.clear()
            self.job_status = dict(running=True, message='Iniciando', progress=0, total=total, error=None)
            def run():
                try:
                    target()
                except Exception as exc:
                    with self.lock:
                        self.job_status['error'] = str(exc)
                finally:
                    with self.lock:
                        self.job_status.update(running=False, message='Cancelado' if self._cancel.is_set() else 'Finalizado')
            self._job = threading.Thread(target=run, name='network-discovery', daemon=True)
            self._job.start()
            return True

    def cancel(self, wait=False):
        self._cancel.set()
        if wait and self._job:
            self._job.join(timeout=6)

    def clear(self):
        self.cancel(wait=True)
        with self.lock:
            if self._job and self._job.is_alive():
                return False
            self.devices.clear()
            self.connections.clear()
            self.dns.clear()
            self.alerts.clear()
            self._syn.clear()
            self._dedup.clear()
            self.port_results.clear()
            self.audit_reports.clear()
            self.job_status = dict(running=False, message='Sin tareas activas', progress=0, total=0, error=None)
            return True

    def start_discovery(self, cidr):
        self.refresh_context()
        network = validate_network(cidr)
        hosts = [str(ip) for ip in network.hosts()]
        def ping(ip):
            if self._cancel.is_set():
                return
            command = ['ping', '-n', '1', '-w', '400', ip] if os.name == 'nt' else ['ping', '-c', '1', ip]
            try:
                result = subprocess.run(command, capture_output=True, text=True, errors="replace", timeout=1.5)
                success = result.returncode == 0 and (os.name != "nt" or re.search(r"ttl[= ]\d+", result.stdout, re.I))
                if success:
                    self.observe_device(ip, source='Respuesta ICMP')
            except subprocess.TimeoutExpired:
                pass
            finally:
                with self.lock:
                    self.job_status['progress'] += 1
        def discover():
            if not shutil.which('ping'):
                raise RuntimeError('No se encontró ping en el sistema.')
            with self.lock:
                self.job_status['message'] = f'Descubriendo {network}'
            with ThreadPoolExecutor(max_workers=16) as pool:
                list(pool.map(ping, hosts))
            if self._cancel.is_set():
                return
            command = ['ip', 'neigh'] if shutil.which('ip') and os.name != 'nt' else ['arp', '-a']
            result = subprocess.run(command, capture_output=True, text=True, errors='replace', timeout=5)
            if result.returncode:
                raise RuntimeError(result.stderr.strip() or 'No se pudo leer la tabla de vecinos.')
            for ip, mac in parse_neighbors(result.stdout):
                if ipaddress.ip_address(ip) in network:
                    self.observe_device(ip, mac, 'Caché de vecinos (no confirma presencia actual)')
        return self._launch(discover, len(hosts))

    def start_port_check(self, ip):
        self.refresh_context()
        address = ipaddress.IPv4Address(ip)
        if not self.is_lan(ip) or not any(address in n for n in PRIVATE):
            raise ValueError('Elige una IP privada de una red local conectada.')
        def check():
            with self.lock:
                self.port_results = []
                self.job_status['message'] = f'Comprobación TCP de {ip}'
            for port in CHECK_PORTS:
                if self._cancel.is_set():
                    return
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(0.4)
                        code = sock.connect_ex((str(address), port))
                    state = 'Abierto' if code == 0 else 'Cerrado' if code in (errno.ECONNREFUSED, 10061) else 'Sin respuesta / filtrado'
                except OSError:
                    state = 'Sin respuesta / error'
                with self.lock:
                    self.port_results.append(dict(IP=ip, Puerto=port, Servicio=SERVICES[port], Estado=state, Hora=time.time()))
                    self.job_status['progress'] += 1
        return self._launch(check, len(CHECK_PORTS))

    def export_json(self):
        return json.dumps(self.snapshot(), ensure_ascii=False, indent=2)

    def start_audit(self, ip, hostname=''):
        self.refresh_context()
        address = ipaddress.IPv4Address(ip)
        hostname = validate_hostname(hostname)
        if not self.is_lan(ip) or not any(address in n for n in PRIVATE):
            raise ValueError('La auditoría requiere una IP privada de una red local conectada.')
        if any(address in (net.network_address, net.broadcast_address) for net in self._networks if address in net and net.prefixlen < 31):
            raise ValueError('Selecciona un host, no la dirección de red o broadcast.')
        with self.lock:
            if ip not in self.devices:
                raise ValueError('Descubre o captura el equipo primero para incorporarlo al inventario.')
            identity = (self._metadata(self.devices[ip])['Subred'], self.devices[ip]['MAC'])
        def progress(port):
            with self.lock:
                self.job_status.update(progress=self.job_status['progress'] + 1,
                                       message=f'Auditoría {ip} · puerto {port}')
        def check():
            with self.lock:
                self.job_status['message'] = f'Auditando {ip}'
            result = run_audit(ip, hostname, self._cancel, progress)
            with self.lock:
                previous = self.audit_reports.get(ip)
                if previous and (previous.get('identity') != identity or previous.get('hostname') != hostname):
                    previous = None
                result = reconcile(previous, result)
                result['identity'] = identity
                self.audit_reports[ip] = result
                self.audit_reports.move_to_end(ip)
                while len(self.audit_reports) > 16:
                    self.audit_reports.popitem(last=False)
        return self._launch(check, len(AUDIT_PORTS))

    def update_finding(self, ip, finding_id, state, note=''):
        if state not in ('Pendiente', 'En progreso', 'Mitigado por usuario', 'Falso positivo / aceptado') or len(note) > 500:
            raise ValueError('Estado no válido o nota superior a 500 caracteres.')
        with self.lock:
            for row in self.audit_reports.get(ip, {}).get('findings', []):
                if row['ID'] == finding_id:
                    row.update(Gestion=state, Nota=note.strip())
                    return True
            return False
