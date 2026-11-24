"""Comprobaciones contra fixtures locales y fallos simulados, sin auditar la LAN."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import ssl
import threading
import unittest
from unittest.mock import MagicMock, patch

from audit import assess_http, finding, http_probe, reconcile, run_audit, validate_hostname
from security import NetworkSecurity


class Handler(BaseHTTPRequestHandler):
    requests = []

    def do_HEAD(self):
        type(self).requests.append(self.path)
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Set-Cookie', 'secret=do-not-export')
        self.end_headers()

    def log_message(self, *args):
        pass


class AuditTests(unittest.TestCase):
    def test_hostname_cannot_inject_headers_or_change_connection(self):
        self.assertEqual(validate_hostname('Router.Home.'), 'router.home')
        for value in ('https://host/', 'host:443', 'a\r\nHost: evil', 'user@host', '../router'):
            with self.assertRaises(ValueError):
                validate_hostname(value)

    def test_real_head_request_and_bounded_evidence(self):
        Handler.requests = []
        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            response = http_probe('127.0.0.1', port, hostname='router.home')
            self.assertEqual(response['status'], 200)
            self.assertNotIn('set-cookie', response['headers'])
            with patch('audit.HTTP_PORTS', (port,)):
                report = run_audit('127.0.0.1', ports=(port,))
            self.assertIn(f'http_html:{port}', report['completed_groups'])
            self.assertTrue(any('nosniff' in row['Regla'] for row in report['findings']))
            self.assertEqual(Handler.requests, ['/', '/'])
            self.assertNotIn('do-not-export', str(report))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)

    def test_redirect_is_reported_but_never_followed(self):
        sock = MagicMock()
        sock.recv.return_value = b'HTTP/1.1 302 Found\r\nLocation: https://example.org/private?token=secret\r\n\r\n'
        with patch('audit.socket.create_connection', return_value=sock) as connect:
            response = http_probe('192.168.1.10', 80, hostname='router.home')
        self.assertEqual(connect.call_count, 1)
        self.assertEqual(connect.call_args.args[0], ('192.168.1.10', 80))
        self.assertEqual(response['redirect_scheme'], 'https')
        self.assertNotIn('secret', str(response))
        self.assertEqual(assess_http('192.168.1.10', 80, response), [])

    def test_truncated_headers_are_not_a_clean_result(self):
        sock = MagicMock()
        sock.recv.return_value = b'x' * 4096
        with patch('audit.socket.create_connection', return_value=sock):
            with self.assertRaises(ValueError):
                http_probe('192.168.1.10', 80)
        self.assertTrue(sock.close.called)

    def test_header_checks_only_for_html_and_hsts_for_dns_name(self):
        response = dict(status=200, headers={'content-type': 'application/json'})
        self.assertEqual(assess_http('192.168.1.10', 443, response, True, 'router.home'), [])
        response['headers'] = {'content-type':'text/html', 'x-content-type-options':'nosniff',
                               'content-security-policy':"default-src 'self'; frame-ancestors 'none'"}
        self.assertEqual(assess_http('192.168.1.10', 443, response, True), [])
        result = assess_http('192.168.1.10', 443, response, True, 'router.home')
        self.assertEqual(len(result), 1)
        self.assertIn('HSTS', result[0]['Regla'])

    def test_tls_validation_failure_has_evidence_not_exploit_claim(self):
        sock = MagicMock()
        with patch('audit.socket.create_connection', return_value=sock), patch('audit.tls_probe', side_effect=ssl.SSLCertVerificationError('hostname mismatch')), patch('audit.http_probe', return_value=dict(status=200, headers={})):
            report = run_audit('192.168.1.10', ports=(443,))
        self.assertEqual(len(report['findings']), 1)
        self.assertIn('no validado', report['findings'][0]['Regla'])
        self.assertIn('tls:443', report['completed_groups'])

    def test_reaudit_unreachable_does_not_mean_patched(self):
        old = finding('192.168.1.10',80,'Header','Baja','observado','corregir','http_html:80')
        old.update(Gestion='En progreso', Nota='Cambio en revisión')
        current = dict(findings=[], completed_groups=[])
        merged = reconcile(dict(findings=[old]), current)
        self.assertEqual(merged['findings'][0]['Verificacion'], 'Sin verificar en reauditoría')
        current['completed_groups'] = ['http_html:80']
        merged = reconcile(dict(findings=[old]), current)
        self.assertEqual(merged['findings'][0]['Verificacion'], 'No observado en reauditoría')
        self.assertEqual(merged['findings'][0]['Gestion'], 'En progreso')

    def test_reaudit_preserves_notes_and_cancellation(self):
        row = finding('192.168.1.10',80,'Header','Baja','observado','corregir','http_html:80')
        old = dict(row, Gestion='Mitigado por usuario', Nota='Actualizado')
        merged = reconcile(dict(findings=[old]),dict(findings=[row],completed_groups=['http_html:80']))
        self.assertEqual(merged['findings'][0]['Nota'],'Actualizado')
        self.assertEqual(merged['findings'][0]['Verificacion'],'Detectado')
        cancel = threading.Event()
        cancel.set()
        with patch('audit.socket.create_connection') as connect:
            report = run_audit('192.168.1.10', cancel=cancel)
        connect.assert_not_called()
        self.assertTrue(report['cancelled'])

    def test_engine_rejects_external_and_missing_hosts(self):
        engine = NetworkSecurity()
        engine._networks = [ipaddress.ip_network('192.168.1.0/24')]
        with patch.object(engine, 'refresh_context'):
            for ip in ('1.1.1.1','192.168.1.255','192.168.1.20'):
                with self.assertRaises(ValueError):
                    engine.start_audit(ip)
        self.assertFalse(engine.snapshot()['job']['running'])

    def test_engine_job_report_and_patch_tracking(self):
        engine = NetworkSecurity()
        engine._networks = [ipaddress.ip_network('192.168.1.0/24')]
        engine.observe_device('192.168.1.10')
        result = run_audit('192.168.1.10', ports=())
        result['findings'] = [finding('192.168.1.10',80,'HTTP','Media','HEAD /','HTTPS','http_transport:80')]
        with patch.object(engine,'refresh_context'), patch('security.run_audit',return_value=result):
            self.assertTrue(engine.start_audit('192.168.1.10'))
            engine._job.join(2)
        self.assertFalse(engine.snapshot()['job']['running'])
        self.assertTrue(engine.update_finding('192.168.1.10', result['findings'][0]['ID'],'En progreso','Probando actualización'))
        report = engine.snapshot()['audits'][0]
        self.assertEqual(report['findings'][0]['Nota'],'Probando actualización')
        report['findings'][0]['Nota'] = 'alterado'
        self.assertNotEqual(engine.snapshot()['audits'][0]['findings'][0]['Nota'],'alterado')
        self.assertTrue(engine.clear())
        self.assertEqual(engine.snapshot()['audits'],[])

    def test_audit_history_persists_in_sqlite(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / 'devices.sqlite3'
            engine1 = NetworkSecurity(registry_path=db_path)
            engine1._networks = [ipaddress.ip_network('192.168.1.0/24')]
            engine1.observe_device('192.168.1.10')
            result = run_audit('192.168.1.10', ports=())
            result['findings'] = [finding('192.168.1.10', 80, 'HTTP', 'Media', 'HEAD /', 'HTTPS', 'http_transport:80')]
            with patch.object(engine1, 'refresh_context'), patch('security.run_audit', return_value=result):
                self.assertTrue(engine1.start_audit('192.168.1.10'))
                engine1._job.join(2)
            self.assertTrue(engine1.update_finding('192.168.1.10', result['findings'][0]['ID'], 'Mitigado por usuario', 'HTTPS activado'))

            engine2 = NetworkSecurity(registry_path=db_path)
            audits = engine2.snapshot()['audits']
            self.assertEqual(len(audits), 1)
            self.assertEqual(audits[0]['ip'], '192.168.1.10')
            self.assertEqual(audits[0]['findings'][0]['Gestion'], 'Mitigado por usuario')
            self.assertEqual(audits[0]['findings'][0]['Nota'], 'HTTPS activado')


if __name__ == '__main__':
    unittest.main()
