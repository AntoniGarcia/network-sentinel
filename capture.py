"""Captura IPv4 por aplicación, con recursos acotados y cierre en su propio hilo."""
import asyncio
import atexit
import ipaddress
import logging
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import threading
import time
from collections import OrderedDict, deque

import pandas as pd
import psutil
from managed_capture import ManagedLiveCapture

from security import NetworkSecurity

logger = logging.getLogger(__name__)

PORT_NAMES = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP-Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "SQL-Server",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


def _port_label(port):
    if port is None:
        return "Desconocido"
    return PORT_NAMES.get(port, f"Otro (puerto {port})")



def tshark_path():
    found = shutil.which("tshark")
    if found:
        return found
    for base in (os.environ.get("ProgramFiles", ""), os.environ.get("ProgramFiles(x86)", "")):
        candidate = Path(base) / "Wireshark" / "tshark.exe"
        if candidate.is_file():
            return str(candidate)
    return None


def _error_message(detail):
    low = detail.lower()
    if "unable to load npcap" in low or "wpcap.dll" in low:
        return detail + "\nInstala o repara Npcap desde https://npcap.com/ y reinicia si el instalador lo solicita."
    if "permission" in low or "access is denied" in low or "privilege" in low:
        return detail + "\nRevisa los permisos de captura de Npcap/dumpcap; en Windows prueba una terminal como administrador."
    return detail


def capture_diagnostics():
    """No inicia capturas; conserva stderr real sin deducir la causa por el código."""
    path = tshark_path()
    result = {"ok": False, "path": path, "interfaces": [], "error": None}
    if not path:
        result["error"] = "No se encontró TShark. Instala Wireshark/TShark."
        return result
    try:
        proc = subprocess.run([path, "-D"], capture_output=True, text=True,
                              errors="replace", timeout=10)
        if proc.returncode:
            raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or
                               f"TShark terminó con código {proc.returncode}")
        for line in proc.stdout.splitlines():
            match = re.match(r"^(\d+)\.\s+(\S+)(?:\s+\((.*)\))?$", line.strip())
            if match:
                _, name, label = match.groups()
                # Los lectores extcap no representan interfaces de red locales.
                if name in {"etwdump", "sshdump", "ciscodump", "udpdump", "randpkt"}:
                    continue
                result["interfaces"].append((name, label or name))
        if not result["interfaces"]:
            raise RuntimeError("TShark no encontró interfaces de red capturables. Revisa Npcap/dumpcap y sus permisos.")
        result["ok"] = True
    except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
        result["error"] = _error_message(str(exc))
    return result


def list_capture_interfaces():
    return capture_diagnostics()["interfaces"]


class BandwidthMonitor:
    """Una sesión conserva totales al detener/reanudar; reset() comienza otra.

    Bps usa una ventana fija de cinco segundos (incluye periodos sin tráfico).
    Las conexiones son flujos observados durante los últimos cinco segundos,
    no un censo de sockets abiertos del sistema.
    """
    MAX_APPS = 512
    MAX_DNS = 4096
    MAX_FLOWS = 2048
    BUCKET_SECONDS = 0.25
    COLUMNS = ["Aplicación", "Bytes", "Descarga Bytes", "Subida Bytes", "Bps",
               "Mbps", "Descarga Mbps", "Subida Mbps", "Conexiones activas"]

    def __init__(self, window_seconds=5, proc_refresh_interval=2, registry_path=None):
        if window_seconds <= 0 or proc_refresh_interval <= 0:
            raise ValueError("Los intervalos deben ser positivos")
        self.window_seconds = window_seconds
        self.proc_refresh_interval = proc_refresh_interval
        self.interface = None
        self.security = NetworkSecurity(registry_path=registry_path)
        self._lock = threading.RLock()
        self._lifecycle = threading.Lock()
        self._stop = threading.Event()
        self._stop.set()
        self._threads = []
        self._workers = {}
        self._traffic = {}
        self._dns_map = OrderedDict()
        self._proc_map = {}
        self._history = deque(maxlen=300)
        self._totals = [0, 0]
        self._started = None
        self._active_since = None
        self._elapsed = 0.0
        self._local_ips = self._get_local_ips()
        self._status = dict(last_error=None, dns_last_error=None, packets_captured=0,
                            dns_packets_captured=0, proc_permission_warning=False,
                            last_packet=None, state="Detenido")
        atexit.register(self.stop)

    @staticmethod
    def _get_local_ips():
        return {addr.address.split("%")[0] for addrs in psutil.net_if_addrs().values()
                for addr in addrs if addr.family == socket.AF_INET}

    def _set_status(self, **kwargs):
        with self._lock:
            self._status.update(kwargs)

    def get_status(self):
        with self._lock:
            return dict(self._status, running=self.is_running(), interface=self.interface,
                        workers_alive=sum(t.is_alive() for t in self._threads))

    def is_running(self):
        return not self._stop.is_set()

    def _finish_active_time(self):
        with self._lock:
            if self._active_since is not None:
                self._elapsed += time.monotonic() - self._active_since
                self._active_since = None

    def start(self, interface=None):
        with self._lifecycle:
            if self.is_running():
                return True
            if not self._stop_workers():
                return False
            self._set_status(last_error=None, dns_last_error=None, state="Comprobando")
            diagnosis = capture_diagnostics()
            if not diagnosis["ok"]:
                self._set_status(last_error=diagnosis["error"], state="Error")
                return False
            interfaces = diagnosis["interfaces"]
            selected = interface or self.interface
            if selected:
                selected = next((name for i, (name, label) in enumerate(interfaces, 1)
                                 if selected in (name, label, str(i))), None)
                if selected is None:
                    self._set_status(last_error="La interfaz seleccionada ya no está disponible. Actualiza la lista.", state="Error")
                    return False
            else:
                busiest = self._busiest_interface_name()
                selected = next((name for name, label in interfaces if label == busiest), None)
                if not selected:
                    # En Unix, TShark suele usar el nombre del adaptador directamente.
                    selected = next((name for name, _ in interfaces if name == busiest), interfaces[0][0])
            self.interface = selected
            self._path = diagnosis["path"]
            self._local_ips = self._get_local_ips()
            self.security.refresh_context()
            with self._lock:
                self._proc_map.clear()
                for entry in self._traffic.values():
                    entry["buckets"].clear()
                    entry["flows"].clear()
                self._active_since = time.monotonic()
                self._started = self._started or time.time()
            self._stop.clear()
            self._set_status(state="Iniciando captura", proc_permission_warning=False)
            self._threads = [
                threading.Thread(target=self._capture_loop, args=(False,), name="capture-thread", daemon=True),
                threading.Thread(target=self._capture_loop, args=(True,), name="dns-thread", daemon=True),
                threading.Thread(target=self._proc_refresh_loop, name="proc-thread", daemon=True),
            ]
            for thread in self._threads:
                thread.start()
            return True

    @staticmethod
    def _busiest_interface_name():
        stats = psutil.net_if_stats()
        before = psutil.net_io_counters(pernic=True)
        time.sleep(0.25)
        after = psutil.net_io_counters(pernic=True)
        names = [name for name, stat in stats.items() if stat.isup and name in before and name in after]
        return max(names, key=lambda n: after[n].bytes_recv + after[n].bytes_sent -
                   before[n].bytes_recv - before[n].bytes_sent, default=None)

    def _stop_workers(self):
        self._stop.set()
        self._finish_active_time()
        with self._lock:
            workers = list(self._workers.values())
        for loop, task in workers:
            try:
                loop.call_soon_threadsafe(task.cancel)
            except RuntimeError:
                pass  # El hilo ya cerró su loop.
        deadline = time.monotonic() + 8
        for thread in self._threads:
            if thread is not threading.current_thread():
                thread.join(timeout=max(0, deadline - time.monotonic()))
        self._threads = [t for t in self._threads if t.is_alive()]
        if self._threads:
            self._set_status(last_error="La captura aún está cerrando. Espera y vuelve a detenerla; no se iniciarán hilos duplicados.", state="Cerrando")
            return False
        return True

    def stop(self):
        self.security.cancel(wait=True)
        with self._lifecycle:
            stopped = self._stop_workers()
            if stopped:
                self._set_status(state="Detenido")
            return stopped

    def reset(self):
        with self._lifecycle:
            if not self._stop_workers():
                return False
            if not self.security.clear():
                return False
            with self._lock:
                self._traffic.clear()
                self._dns_map.clear()
                self._proc_map.clear()
                self._history.clear()
                self._totals = [0, 0]
                self._started = None
                self._elapsed = 0.0
                self._status.update(last_error=None, dns_last_error=None, packets_captured=0,
                                    dns_packets_captured=0, last_packet=None, state="Detenido")
            return True

    def _capture_loop(self, dns_only):
        # Proactor soporta los subprocesos de asyncio en Windows, incluso si
        # Streamlit configura una política Selector en el hilo principal.
        loop = asyncio.ProactorEventLoop() if os.name == "nt" else asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        key = "dns" if dns_only else "ip"

        async def consume():
            capture = None
            try:
                capture = ManagedLiveCapture(interface=self.interface,
                    bpf_filter="ip and port 53" if dns_only else "ip or arp",
                    tshark_path=self._path, eventloop=loop)
                def callback(packet):
                    if self._stop.is_set():
                        return
                    try:
                        if dns_only:
                            self._handle_dns_packet(packet)
                        else:
                            self._handle_packet(packet)
                            with self._lock:
                                self._status["packets_captured"] += int(hasattr(packet, "ip"))
                                self._status.update(last_packet=time.time(), state="Capturando")
                    except (AttributeError, ValueError, TypeError, IndexError):
                        logger.debug("Paquete incompleto", exc_info=True)
                await capture.packets_from_tshark(callback, close_tshark=False)
                if not self._stop.is_set():
                    raise RuntimeError("TShark terminó la captura inesperadamente")
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                detail = _error_message(str(exc))
                if dns_only:
                    self._set_status(dns_last_error=detail)
                else:
                    self._set_status(last_error=detail, state="Error")
                    self._stop.set()
                    self._finish_active_time()
                    with self._lock:
                        dns_worker = self._workers.get("dns")
                    if dns_worker:
                        try:
                            dns_worker[0].call_soon_threadsafe(dns_worker[1].cancel)
                        except RuntimeError:
                            pass
            finally:
                if capture is not None:
                    try:
                        await capture.close_async()
                    except Exception as exc:
                        logger.warning("Error cerrando captura: %s", exc)

        task = loop.create_task(consume())
        with self._lock:
            self._workers[key] = (loop, task)
        if self._stop.is_set():
            task.cancel()
        try:
            loop.run_until_complete(task)
        except asyncio.CancelledError:
            pass
        finally:
            with self._lock:
                self._workers.pop(key, None)
            pending = asyncio.all_tasks(loop)
            for pending_task in pending:
                pending_task.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()
            asyncio.set_event_loop(None)

    def _handle_packet(self, packet):
        if hasattr(packet, "arp"):
            self.security.observe_device(str(getattr(packet.arp, "src_proto_ipv4", "")),
                str(getattr(packet.arp, "src_hw_mac", "")), "ARP observado")
        if not hasattr(packet, "ip"):
            return
        proto = "tcp" if hasattr(packet, "tcp") else "udp" if hasattr(packet, "udp") else "ip"
        transport = getattr(packet, proto)
        src_port, dst_port = int(getattr(transport, "srcport", 0)), int(getattr(transport, "dstport", 0))
        self.security.observe_packet(packet.ip.src, packet.ip.dst, src_port, dst_port, proto, int(packet.length),
            syn=str(getattr(transport, "flags_syn", "0")) == "1",
            ack=str(getattr(transport, "flags_ack", "0")) == "1")
        self._classify_and_record(packet.ip.src, packet.ip.dst, src_port, dst_port, proto, int(packet.length))

    def _classify_and_record(self, src_ip, dst_ip, src_port, dst_port, proto, length):
        now = time.monotonic()
        if src_ip in self._local_ips:
            local_ip, local_port, remote_ip, remote_port, direction = src_ip, src_port, dst_ip, dst_port, 1
        elif dst_ip in self._local_ips:
            local_ip, local_port, remote_ip, remote_port, direction = dst_ip, dst_port, src_ip, src_port, 0
        else:
            return  # No atribuir tráfico de terceros a las tasas de este equipo.
        flow = (proto, local_ip, local_port, remote_ip, remote_port)
        with self._lock:
            app = self._proc_map.get(flow)
            if app is None:
                for address in (local_ip, "0.0.0.0", "::"):
                    app = self._proc_map.get((proto, address, local_port, "", 0))
                    if app:
                        break
            dns = self._dns_map.get(remote_ip)
            if app is None and dns and dns[1] > now:
                app = dns[0]
            app = app or (_port_label(remote_port) if proto != "ip" else "IPv4 (sin puertos)")
            if app not in self._traffic and len(self._traffic) >= self.MAX_APPS - 1:
                app = "Otros (límite de aplicaciones)"
            entry = self._traffic.setdefault(app, dict(totals=[0, 0], buckets=deque(), flows=OrderedDict()))
            entry["totals"][direction] += length
            self._totals[direction] += length
            tick = int(now / self.BUCKET_SECONDS)
            if not entry["buckets"] or entry["buckets"][-1][0] != tick:
                entry["buckets"].append([tick, 0, 0])
            entry["buckets"][-1][direction + 1] += length
            self._prune_entry(entry, now)
            entry["flows"][flow] = now
            entry["flows"].move_to_end(flow)
            if len(entry["flows"]) > self.MAX_FLOWS:
                entry["flows"].popitem(last=False)

    def _prune_entry(self, entry, now):
        cutoff = now - self.window_seconds
        while entry["buckets"] and (entry["buckets"][0][0] + 1) * self.BUCKET_SECONDS <= cutoff:
            entry["buckets"].popleft()
        while entry["flows"] and next(iter(entry["flows"].values())) < cutoff:
            entry["flows"].popitem(last=False)

    @staticmethod
    def _field_values(layer, name):
        field = getattr(layer, name, None)
        if field is None:
            return []
        return [str(value) for value in getattr(field, "all_fields", [field])]

    def _handle_dns_packet(self, packet):
        if not hasattr(packet, "dns"):
            return
        dns = packet.dns
        domain = getattr(dns, "qry_name", None)
        if domain and hasattr(packet, "ip"):
            response = str(getattr(dns, "flags_response", "0")) == "1"
            self.security.observe_dns(packet.ip.dst if response else packet.ip.src, domain, response)
        with self._lock:
            self._status["dns_packets_captured"] += 1
        if str(getattr(dns, "flags_response", "0")) != "1":
            return
        name = str(getattr(dns, "qry_name", "")).rstrip(".")
        if not name:
            return
        ttls = self._field_values(dns, "resp_ttl")
        # Conservador con respuestas mixtas/CNAME: nunca exceder el TTL mínimo.
        ttl = min((int(t) for t in ttls), default=60)
        if ttl <= 0:
            return
        now = time.monotonic()
        with self._lock:
            for value in self._field_values(dns, "a"):
                try:
                    ip = str(ipaddress.IPv4Address(value))
                except ipaddress.AddressValueError:
                    continue
                self._dns_map[ip] = (name, now + min(ttl, 86400))
                self._dns_map.move_to_end(ip)
                while len(self._dns_map) > self.MAX_DNS:
                    self._dns_map.popitem(last=False)

    def _refresh_proc_map(self):
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError, OSError, RuntimeError):
            with self._lock:
                self._proc_map.clear()
            self._set_status(proc_permission_warning=True)
            return
        mapping, names = {}, {}
        for conn in connections:
            if not conn.laddr or not conn.pid:
                continue
            try:
                if conn.pid not in names:
                    names[conn.pid] = psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            proto = "tcp" if conn.type == socket.SOCK_STREAM else "udp"
            remote_ip, remote_port = (conn.raddr.ip, conn.raddr.port) if conn.raddr else ("", 0)
            key = (proto, conn.laddr.ip, conn.laddr.port, remote_ip, remote_port)
            # Un puerto compartido por procesos distintos es ambiguo: usar fallback.
            if key in mapping and mapping[key] != names[conn.pid]:
                mapping[key] = None
            else:
                mapping[key] = names[conn.pid]
        with self._lock:
            self._proc_map = mapping
        self._set_status(proc_permission_warning=False)

    def _proc_refresh_loop(self):
        while not self._stop.is_set():
            try:
                self._refresh_proc_map()
                self._maintenance()
            except Exception:
                logger.exception("Error actualizando procesos")
            self._stop.wait(self.proc_refresh_interval)
    def _maintenance(self):
        now = time.monotonic()
        with self._lock:
            for ip, (_, expires) in list(self._dns_map.items()):
                if expires <= now:
                    del self._dns_map[ip]
            for entry in self._traffic.values():
                self._prune_entry(entry, now)
            frame = self.get_dataframe()
            self._history.append({"Hora": pd.Timestamp.now(),
                "Descarga Mbps": float(frame["Descarga Mbps"].sum()),
                "Subida Mbps": float(frame["Subida Mbps"].sum())})

    def get_dataframe(self):
        now = time.monotonic()
        rows = []
        with self._lock:
            for app, entry in self._traffic.items():
                self._prune_entry(entry, now)
                down = sum(b[1] for b in entry["buckets"]) / self.window_seconds if self.is_running() else 0
                up = sum(b[2] for b in entry["buckets"]) / self.window_seconds if self.is_running() else 0
                rows.append({"Aplicación": app, "Bytes": sum(entry["totals"]),
                    "Descarga Bytes": entry["totals"][0], "Subida Bytes": entry["totals"][1],
                    "Bps": down + up, "Mbps": (down + up) * 8 / 1e6,
                    "Descarga Mbps": down * 8 / 1e6, "Subida Mbps": up * 8 / 1e6,
                    "Conexiones activas": len(entry["flows"]) if self.is_running() else 0})
        return pd.DataFrame(rows, columns=self.COLUMNS).sort_values("Bps", ascending=False).reset_index(drop=True)

    def get_history(self):
        with self._lock:
            return pd.DataFrame(list(self._history), columns=["Hora", "Descarga Mbps", "Subida Mbps"])

    def get_session_stats(self):
        with self._lock:
            elapsed = self._elapsed + (time.monotonic() - self._active_since if self._active_since is not None else 0)
            return dict(total_bytes=sum(self._totals), download_bytes=self._totals[0],
                        upload_bytes=self._totals[1], elapsed_seconds=elapsed)
