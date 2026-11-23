"""Verifica que el dashboard muestre gráficos incluso sin paquetes."""
import unittest
import ipaddress
from unittest.mock import patch
from streamlit.testing.v1 import AppTest
import streamlit as st
from capture import BandwidthMonitor
from audit import finding, run_audit


class DashboardTests(unittest.TestCase):
    def setUp(self):
        st.cache_resource.clear()
        st.cache_data.clear()

    def tearDown(self):
        st.cache_resource.clear()
        st.cache_data.clear()

    def test_name_device_and_review_alert(self):
        monitor = BandwidthMonitor()
        monitor.security._networks = [ipaddress.ip_network('192.168.1.0/24')]
        monitor.security._own = {'192.168.1.2'}
        monitor.security.observe_device('192.168.1.10', '00:11:22:33:44:55')
        monitor.security.observe_packet('192.168.1.10', '8.8.8.8', 50000, 23, 'tcp', 60)
        diagnosis = dict(ok=False, path=None, interfaces=[], error='Prueba sin captura')
        try:
            with patch('capture.capture_diagnostics', return_value=diagnosis), patch('capture.BandwidthMonitor', return_value=monitor):
                app = AppTest.from_file('app.py').run(timeout=15)
                self.assertEqual(len(app.exception), 0)
                app.text_input(key='device_name_192.168.1.10_00:11:22:33:44:55').set_value('Portátil de casa')
                app.checkbox(key='device_known_192.168.1.10_00:11:22:33:44:55').check()
                next(button for button in app.button if button.label == 'Guardar dispositivo').click().run()
                self.assertEqual(len(app.exception), 0)
                row = next(row for row in monitor.security.snapshot()['devices'] if row['IP'] == '192.168.1.10')
                self.assertEqual(row['Nombre'], 'Portátil de casa')
                self.assertTrue(row['Reconocido'])
                app.run()
                app.button(key='review_alert').click().run()
                self.assertEqual(len(app.exception), 0)
                pending = [row for row in monitor.security.snapshot()['alerts'] if row['Estado'] == 'Pendiente']
                self.assertEqual(pending, [])
        finally:
            monitor.stop()

    def test_audit_evidence_and_remediation_form(self):
        monitor = BandwidthMonitor()
        monitor.security._networks = [ipaddress.ip_network('192.168.1.0/24')]
        monitor.security.observe_device('192.168.1.10')
        report = run_audit('192.168.1.10', ports=())
        row = finding('192.168.1.10',80,'HTTP sin redirección','Media','HEAD / 200','Configurar HTTPS','http_transport:80')
        report['findings'] = [row]
        monitor.security.audit_reports['192.168.1.10'] = report
        diagnosis = dict(ok=False, path=None, interfaces=[], error='Prueba sin captura')
        try:
            with patch('capture.capture_diagnostics', return_value=diagnosis), patch('capture.BandwidthMonitor', return_value=monitor):
                app = AppTest.from_file('app.py').run(timeout=15)
                self.assertEqual(len(app.exception),0)
                app.selectbox(key=f"audit_state_{row['ID']}").select('En progreso')
                app.text_area(key=f"audit_note_{row['ID']}").set_value('Aplicar cambio y repetir auditoría')
                next(button for button in app.button if button.label == 'Guardar seguimiento').click().run()
                self.assertEqual(len(app.exception),0)
                updated = monitor.security.snapshot()['audits'][0]['findings'][0]
                self.assertEqual(updated['Gestion'],'En progreso')
                self.assertIn('repetir auditoría',updated['Nota'])
        finally:
            monitor.stop()

    def test_populated_security_panel_and_filters(self):
        monitor = BandwidthMonitor()
        monitor.security.observe_packet('192.168.1.10','1.1.1.1',50000,443,'tcp',1200)
        monitor.security.observe_dns('192.168.1.10','example.org',False)
        diagnosis = dict(ok=False, path=None, interfaces=[], error='Prueba sin captura')
        try:
            with patch('capture.capture_diagnostics',return_value=diagnosis), patch('capture.BandwidthMonitor',return_value=monitor):
                app = AppTest.from_file('app.py').run(timeout=15)
                self.assertEqual(len(app.exception),0)
                self.assertGreaterEqual(len(app.get('plotly_chart')),4)
                app.selectbox(key='security_host').select('192.168.1.10').run()
                app.text_input(key='dns_filter').set_value('example.org').run()
                self.assertEqual(len(app.exception),0)
                self.assertTrue(any('Dominio' in table.value and 'example.org' in table.value['Dominio'].values for table in app.dataframe))
        finally:
            monitor.stop()

    def test_empty_dashboard_and_diagnostic_error(self):
        diagnosis = dict(ok=False, path=None, interfaces=[], error="Falta TShark (prueba)")
        with patch('capture.capture_diagnostics', return_value=diagnosis):
            app = AppTest.from_file('app.py').run(timeout=15)
            self.assertEqual(len(app.exception), 0)
            self.assertTrue(any('Falta TShark' in error.value for error in app.error))
            self.assertGreaterEqual(len(app.get('plotly_chart')), 3)
            start = next(button for button in app.button if 'Iniciar' in button.label)
            self.assertTrue(start.disabled)


if __name__ == '__main__':
    unittest.main()
