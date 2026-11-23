"""Persistencia, identidad y reconocimiento sin sondear equipos de la red."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from device_registry import DeviceRegistry, normalize_mac
from security import NetworkSecurity

NETWORKS = [dict(interface='test', ip='192.168.1.2', network='192.168.1.0/24')]


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'data' / 'devices.sqlite3'

    def engine(self):
        with patch('security.local_networks', return_value=NETWORKS):
            engine = NetworkSecurity(registry_path=self.path)
        engine._own = {'192.168.1.2'}
        return engine

    def test_lazy_creation_persistence_and_mac_identity_survives_dhcp(self):
        registry = DeviceRegistry(self.path)
        self.assertFalse(self.path.exists())
        registry.save('192.168.1.0/24', '192.168.1.10', '00:11:22:33:44:55', 'Televisión', 'Sala', True)
        reopened = DeviceRegistry(self.path)
        self.assertIsNone(reopened.error)
        self.assertEqual(reopened.get('192.168.1.0/24', '192.168.1.42', '00:11:22:33:44:55')['name'], 'Televisión')
        self.assertIsNone(reopened.get('192.168.1.0/24', '192.168.1.10', '00:11:22:33:44:66'))
        self.assertIsNone(reopened.get('192.168.2.0/24', '192.168.2.10', '00:11:22:33:44:55'))

    def test_invalid_mac_and_name_validation(self):
        self.assertEqual(normalize_mac('02-AA-BB-CC-DD-EE'), '02:aa:bb:cc:dd:ee')
        for mac in ('not a mac', 'ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00', '01:11:22:33:44:55'):
            self.assertEqual(normalize_mac(mac), '')
        registry = DeviceRegistry(self.path)
        with self.assertRaises(ValueError):
            registry.save('192.168.1.0/24', '192.168.1.10', '', '')
        with self.assertRaises(ValueError):
            registry.save('192.168.1.0/24', '192.168.2.10', '', 'Equipo')
        self.assertFalse(self.path.exists())

    def test_missing_mac_never_inherits_saved_mac_recognition(self):
        registry = DeviceRegistry(self.path)
        registry.save('192.168.1.0/24', '192.168.1.10', '00:11:22:33:44:55', 'PC', recognized=True)
        self.assertIsNone(registry.get('192.168.1.0/24', '192.168.1.10', ''))

    def test_corrupt_file_not_overwritten(self):
        self.path.parent.mkdir()
        self.path.write_bytes(b'not sqlite')
        registry = DeviceRegistry(self.path)
        self.assertIsNotNone(registry.error)
        with self.assertRaises(ValueError):
            registry.save('192.168.1.0/24', '192.168.1.10', '', 'PC')
        self.assertEqual(self.path.read_bytes(), b'not sqlite')

    def test_known_device_resolves_provisional_notice_but_not_mac_alert(self):
        engine = self.engine()
        engine.observe_device('192.168.1.10', '00:11:22:33:44:55')
        engine.save_device('192.168.1.10', 'Portátil', recognized=True)
        self.assertEqual(engine.snapshot()['alerts'][0]['Estado'], 'Reconocido')
        self.assertTrue(engine.clear())
        engine.observe_device('192.168.1.10')
        self.assertFalse(engine.snapshot()['devices'][0]['Reconocido'])
        engine.observe_device('192.168.1.10', '00:11:22:33:44:55')
        self.assertTrue(engine.snapshot()['devices'][0]['Reconocido'])
        self.assertEqual(engine.snapshot()['alerts'][0]['Estado'], 'Reconocido')
        engine.observe_device('192.168.1.10', '00:11:22:33:44:66')
        self.assertFalse(engine.snapshot()['devices'][0]['Reconocido'])
        self.assertEqual(engine.snapshot()['alerts'][0]['Regla'], 'Cambio de MAC')
        self.assertEqual(engine.snapshot()['alerts'][0]['Estado'], 'Pendiente')

    def test_save_forget_and_export_no_traffic_persistence(self):
        engine = self.engine()
        engine.observe_device('192.168.1.10', '00:11:22:33:44:55')
        engine.save_device('192.168.1.10', "PC 'salón' <personal>", recognized=True)
        exported = json.loads(engine.export_json())
        self.assertTrue(exported['devices'][0]['Reconocido'])
        self.assertEqual(len(exported['registry']), 1)
        record = engine.registry.list_records()[0]
        self.assertTrue(engine.registry.forget(record['network'], record['identity']))
        self.assertEqual(DeviceRegistry(self.path).list_records(), [])
        self.assertFalse(engine.snapshot()['devices'][0]['Reconocido'])

    def test_registry_limit(self):
        registry = DeviceRegistry(self.path)
        registry.MAX_RECORDS = 1
        registry.save('192.168.1.0/24', '192.168.1.10', '', 'PC')
        registry.save('192.168.1.0/24', '192.168.1.10', '', 'PC actualizado')
        with self.assertRaises(ValueError):
            registry.save('192.168.1.0/24', '192.168.1.11', '', 'Otra')


if __name__ == '__main__':
    unittest.main()
