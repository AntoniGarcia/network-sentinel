"""Pruebas de telemetría y tareas activas sin escanear la LAN."""
import socket
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from security import NetworkSecurity, parse_neighbors, validate_network
from capture import BandwidthMonitor
from security_ui import network_figure

NETWORKS = [dict(interface='test', ip='192.168.1.2', network='192.168.1.0/24')]


class SecurityTests(unittest.TestCase):
    def setUp(self):
        with patch('security.local_networks', return_value=NETWORKS):
            self.engine = NetworkSecurity()
        self.engine._own = {'192.168.1.2'}

    def tearDown(self):
        self.engine.cancel(wait=True)

    def test_only_connected_small_private_networks(self):
        with patch('security.local_networks', return_value=NETWORKS):
            self.assertEqual(str(validate_network('192.168.1.0/24')), '192.168.1.0/24')
            for invalid in ['0.0.0.0/0', '192.168.0.0/16', '8.8.8.0/24', '192.168.2.0/24', '::1/128']:
                with self.assertRaises(ValueError):
                    validate_network(invalid)

    def test_neighbor_parser(self):
        text = '''Interface: 192.168.1.2 --- 0x4
192.168.1.1  aa-bb-cc-dd-ee-ff  dynamic
192.168.1.255 ff-ff-ff-ff-ff-ff static
192.168.1.3 dev eth0 lladdr 02:12:34:56:78:90 REACHABLE
? (192.168.1.4) at 04:12:34:56:78:90 on en0
'''
        self.assertEqual(len(parse_neighbors(text)), 3)
        self.assertEqual(parse_neighbors(text)[0], ('192.168.1.1','aa:bb:cc:dd:ee:ff'))

    def test_new_device_and_mac_change_deduplicated(self):
        for _ in range(3):
            self.engine.observe_device('192.168.1.10', '00:11:22:33:44:55')
        self.engine.observe_device('192.168.1.10', '00:11:22:33:44:66')
        rules = [r['Regla'] for r in self.engine.snapshot()['alerts']]
        self.assertEqual(rules.count('Dispositivo nuevo'), 1)
        self.assertEqual(rules.count('Cambio de MAC'), 1)

    def test_only_syn_attempts_trigger_scan_rule(self):
        for port in range(1000,1030):
            self.engine.observe_packet('192.168.1.10','192.168.1.11',50000,port,'tcp',60,syn=True,ack=True)
        self.assertFalse(any(r['Regla']=='Posible barrido TCP' for r in self.engine.snapshot()['alerts']))
        for port in range(1000,1020):
            self.engine.observe_packet('192.168.1.10','192.168.1.11',50000,port,'tcp',60,syn=True)
        self.assertEqual(sum(r['Regla']=='Posible barrido TCP' for r in self.engine.snapshot()['alerts']), 1)

    def test_scan_window_expires(self):
        for port in range(10):
            with patch('security.time.monotonic', return_value=100):
                self.engine.observe_packet('192.168.1.10','192.168.1.11',50000,port,'tcp',60,syn=True)
        for port in range(10,20):
            with patch('security.time.monotonic', return_value=111):
                self.engine.observe_packet('192.168.1.10','192.168.1.11',50000,port,'tcp',60,syn=True)
        self.assertFalse(any(r['Regla']=='Posible barrido TCP' for r in self.engine.snapshot()['alerts']))

    def test_storage_bounded_and_snapshot_detached(self):
        self.engine.MAX_DEVICES = 4
        self.engine.MAX_CONNECTIONS = 5
        for i in range(30):
            self.engine.observe_packet('192.168.1.2',f'192.168.1.{i+3}',50000,80,'tcp',100)
        snapshot = self.engine.snapshot()
        self.assertLessEqual(len(snapshot['devices']), 4)
        self.assertLessEqual(len(snapshot['connections']), 5)
        snapshot['connections'][0]['Bytes'] = -1
        self.assertGreater(self.engine.snapshot()['connections'][0]['Bytes'],0)

    def test_third_party_capture_does_not_count_as_laptop_bandwidth(self):
        monitor = BandwidthMonitor()
        monitor._local_ips = {'192.168.1.2'}
        monitor.security = self.engine
        packet = SimpleNamespace(ip=SimpleNamespace(src='192.168.1.10',dst='8.8.8.8'),
            tcp=SimpleNamespace(srcport='50000',dstport='443',flags_syn='1',flags_ack='0'),length='80')
        monitor._handle_packet(packet)
        self.assertEqual(len(self.engine.snapshot()['connections']),1)
        self.assertEqual(monitor.get_session_stats()['total_bytes'],0)
        monitor.stop()

    def test_dns_event_client_direction(self):
        monitor = BandwidthMonitor()
        monitor.security = self.engine
        packet = SimpleNamespace(ip=SimpleNamespace(src='8.8.8.8',dst='192.168.1.10'),
            dns=SimpleNamespace(flags_response='1',qry_name='example.org'))
        monitor._handle_dns_packet(packet)
        self.assertEqual(self.engine.snapshot()['dns'][0]['Cliente'],'192.168.1.10')
        monitor.stop()

    def test_port_check_real_local_socket(self):
        self.engine._networks = [__import__('ipaddress').ip_network('127.0.0.0/8')]
        with socket.socket() as server:
            server.bind(('127.0.0.1',0))
            server.listen(1)
            port = server.getsockname()[1]
            # Evita red externa; valida connect_ex contra un listener real de loopback.
            fake_private = [__import__('ipaddress').ip_network('127.0.0.0/8')]
            with patch('security.CHECK_PORTS',(port,)), patch.dict('security.SERVICES',{port:'Test'}), patch('security.PRIVATE',fake_private), patch.object(self.engine, 'refresh_context'):
                self.assertTrue(self.engine.start_port_check('127.0.0.1'))
                self.engine._job.join(timeout=3)
            self.assertFalse(self.engine.snapshot()['job']['running'])
            self.assertEqual(self.engine.snapshot()['ports'][0]['Estado'],'Abierto')

    def test_discovery_does_not_duplicate_jobs_and_cancels(self):
        entered, release = threading.Event(), threading.Event()
        def job():
            entered.set()
            release.wait(1)
        self.assertTrue(self.engine._launch(job,1))
        self.assertTrue(entered.wait(1))
        self.assertFalse(self.engine._launch(job,1))
        self.engine.cancel()
        release.set()
        self.engine._job.join(2)
        self.assertEqual(self.engine.snapshot()['job']['message'],'Cancelado')

    def test_map_populated(self):
        self.engine.observe_packet('192.168.1.2','1.1.1.1',50000,443,'tcp',500)
        snapshot = self.engine.snapshot()
        figure = network_figure(snapshot['connections'],snapshot['devices'])
        self.assertEqual(len(figure.data),4)
        self.assertIn('192.168.1.2',str(figure.to_plotly_json()))

    def test_destination_and_neighbor_cache_do_not_confirm_presence(self):
        self.engine.observe_packet('192.168.1.2', '192.168.1.15', 50000, 443, 'tcp', 60)
        self.engine.observe_device('192.168.1.16', '00:11:22:33:44:55', 'Caché de vecinos')
        devices = {row['IP']: row for row in self.engine.snapshot()['devices']}
        self.assertTrue(devices['192.168.1.2']['Presencia_reciente'])
        self.assertFalse(devices['192.168.1.15']['Presencia_reciente'])
        self.assertFalse(devices['192.168.1.16']['Presencia_reciente'])
        self.assertFalse(any(row['Regla'] == 'Dispositivo nuevo' for row in self.engine.snapshot()['alerts']))
        self.engine.observe_device('192.168.1.15')
        self.assertEqual(self.engine.snapshot()['alerts'][0]['IP'], '192.168.1.15')

    def test_port_check_revalidates_network_after_adapter_change(self):
        replacement = [dict(interface='other', ip='192.168.2.2', network='192.168.2.0/24')]
        with patch('security.local_networks', return_value=replacement):
            with self.assertRaises(ValueError):
                self.engine.start_port_check('192.168.1.10')

    def test_reviewed_alert_does_not_silence_future_signal(self):
        with patch('security.time.monotonic', return_value=100):
            self.engine.observe_packet('192.168.1.10', '192.168.1.11', 50000, 23, 'tcp', 60)
        alert = next(row for row in self.engine.snapshot()['alerts'] if row['Nivel'] == 'Revisar')
        self.assertTrue(self.engine.review_alert(alert['ID']))
        with patch('security.time.monotonic', return_value=161):
            self.engine.observe_packet('192.168.1.10', '192.168.1.11', 50000, 23, 'tcp', 60)
        alerts = [row for row in self.engine.snapshot()['alerts'] if row['Nivel'] == 'Revisar']
        self.assertEqual([row['Estado'] for row in alerts], ['Pendiente', 'Revisada'])
        alerts[0]['Estado'] = 'Modified snapshot'
        self.assertEqual(self.engine.snapshot()['alerts'][0]['Estado'], 'Pendiente')


if __name__ == '__main__':
    unittest.main()
