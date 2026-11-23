"""Prueba optativa con captura real: python smoke_capture.py."""
import json
import socket
import time
from capture import BandwidthMonitor, capture_diagnostics

report = capture_diagnostics()
if not report['ok']:
    raise SystemExit(report['error'])
monitor = BandwidthMonitor()
try:
    for cycle in range(2):
        previous_packets = monitor.get_status()["packets_captured"]
        assert monitor.start(), monitor.get_status()
        # Dar tiempo a dumpcap/TShark a iniciar, sin depender del tráfico ajeno.
        for attempt in range(15):
            if not monitor.is_running():
                raise RuntimeError(monitor.get_status())
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(b'bandwidth-monitor-smoke', ('1.1.1.1', 9))
            time.sleep(1)
            if monitor.get_status()["packets_captured"] > previous_packets and monitor.get_dataframe()["Bps"].sum() > 0:
                break
        frame = monitor.get_dataframe()
        telemetry = monitor.security.snapshot()
        print('Diagnóstico:', monitor.get_status(), flush=True)
        assert telemetry['connections'], 'Faltan flujos en el panel de seguridad'
        assert telemetry['devices'], 'Falta inventario observado'
        print(f"Seguridad: {len(telemetry['devices'])} equipos/destinos y {len(telemetry['connections'])} flujos")
        assert not frame.empty and monitor.get_status()["packets_captured"] > previous_packets, monitor.get_status()
        print(json.dumps(dict(cycle=cycle + 1, status=monitor.get_status(),
                              stats=monitor.get_session_stats()), default=str))
        assert monitor.stop(), monitor.get_status()
        assert not monitor._threads and not monitor._workers
        assert monitor.get_dataframe()['Bps'].sum() == 0
        print('Cierre correcto: hilos y loops liberados')
finally:
    monitor.stop()
