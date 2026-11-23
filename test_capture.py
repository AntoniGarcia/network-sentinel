"""Pruebas sin drivers ni permisos de captura: python -m unittest -v."""
import asyncio
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from capture import BandwidthMonitor, capture_diagnostics


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.monitor = BandwidthMonitor()
        self.monitor._local_ips = {"10.0.0.2"}
        self.monitor._stop.clear()

    def tearDown(self):
        self.monitor.stop()

    def record(self, reverse=False, port=443, size=1000):
        args = ("1.1.1.1", "10.0.0.2", port, 50000) if reverse else ("10.0.0.2", "1.1.1.1", 50000, port)
        self.monitor._classify_and_record(*args, "tcp", size)

    def test_direction_rate_and_normalized_flow(self):
        self.record()
        self.record(True, size=2000)
        row = self.monitor.get_dataframe().iloc[0]
        self.assertEqual(row["Subida Bytes"], 1000)
        self.assertEqual(row["Descarga Bytes"], 2000)
        self.assertAlmostEqual(row["Bps"], 600)
        self.assertEqual(row["Conexiones activas"], 1)
        self.assertEqual(self.monitor.get_session_stats()["total_bytes"], 3000)

    def test_exact_process_precedes_dns_and_port(self):
        self.monitor._proc_map[("tcp", "10.0.0.2", 50000, "1.1.1.1", 443)] = "browser.exe"
        self.monitor._dns_map["1.1.1.1"] = ("example.com", time.monotonic() + 60)
        self.record()
        self.assertEqual(self.monitor.get_dataframe().iloc[0]["Aplicación"], "browser.exe")

    def test_expired_dns_falls_back(self):
        self.monitor._dns_map["1.1.1.1"] = ("expired.test", time.monotonic() - 1)
        self.record(True)
        self.assertEqual(self.monitor.get_dataframe().iloc[0]["Aplicación"], "HTTPS")

    def test_window_and_flows_expire_without_losing_totals(self):
        with patch("capture.time.monotonic", return_value=100):
            self.record()
        with patch("capture.time.monotonic", return_value=106):
            row = self.monitor.get_dataframe().iloc[0]
        self.assertEqual(row["Bps"], 0)
        self.assertEqual(row["Conexiones activas"], 0)
        self.assertEqual(row["Bytes"], 1000)

    def test_application_and_bucket_limits(self):
        self.monitor.MAX_APPS = 4
        for port in range(10000, 10050):
            self.record(port=port)
        self.assertLessEqual(len(self.monitor.get_dataframe()), 4)
        for entry in self.monitor._traffic.values():
            self.assertEqual(len(entry["buckets"]), 1)
        self.assertEqual(self.monitor.get_session_stats()["total_bytes"], 50000)

    def test_preflight_preserves_real_error(self):
        failed = SimpleNamespace(returncode=13, stderr="Unable to load Npcap (wpcap.dll)", stdout="")
        with patch("capture.tshark_path", return_value="tshark"), patch("capture.subprocess.run", return_value=failed):
            result = capture_diagnostics()
        self.assertFalse(result["ok"])
        self.assertIn("wpcap.dll", result["error"])
        self.assertNotIn("compatible", result["error"])

    def test_dns_multiple_answers_and_ttl(self):
        field = SimpleNamespace(all_fields=["1.1.1.1", "8.8.8.8"])
        dns = SimpleNamespace(flags_response="1", qry_name="example.com", a=field,
                              resp_ttl=SimpleNamespace(all_fields=["10", "20"]))
        self.monitor._handle_dns_packet(SimpleNamespace(dns=dns))
        self.assertEqual(len(self.monitor._dns_map), 2)
        self.assertLessEqual(self.monitor._dns_map["1.1.1.1"][1], time.monotonic() + 10)

    def test_capture_failure_stops_other_workers(self):
        class BrokenCapture:
            def __init__(self, **kwargs):
                raise RuntimeError("Device unavailable")
        self.monitor.stop()
        diagnosis = dict(ok=True, path="tshark", interfaces=[("fake0", "Fake")])
        with patch("capture.capture_diagnostics", return_value=diagnosis), patch("capture.ManagedLiveCapture", BrokenCapture), patch.object(self.monitor, "_refresh_proc_map"):
            self.monitor.start("fake0")
            deadline = time.monotonic() + 3
            while self.monitor.is_running() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertFalse(self.monitor.is_running())
            self.assertIn("Device unavailable", self.monitor.get_status()["last_error"])
            self.assertTrue(self.monitor.stop())
            self.assertFalse(self.monitor._threads)

    def test_idle_capture_stop_restart_and_reset(self):
        owners, closed = [], []
        class IdleCapture:
            def __init__(self, **kwargs):
                owners.append(asyncio.get_running_loop())
            async def packets_from_tshark(self, callback, close_tshark=False):
                await asyncio.Event().wait()
            async def close_async(self):
                closed.append(asyncio.get_running_loop())
        self.monitor.stop()
        diagnosis = dict(ok=True, path="tshark", interfaces=[("fake0", "Fake")])
        with patch("capture.capture_diagnostics", return_value=diagnosis), patch("capture.ManagedLiveCapture", IdleCapture), patch.object(self.monitor, "_refresh_proc_map"):
            for _ in range(2):
                self.assertTrue(self.monitor.start("fake0"))
                deadline = time.monotonic() + 3
                while len(owners) < (2 if not closed else 4) and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(self.monitor.stop())
                self.assertFalse(self.monitor._workers)
                self.assertFalse(self.monitor._threads)
        self.assertEqual(len(owners), 4)
        self.assertEqual(set(owners), set(closed))
        self.assertTrue(all(loop.is_closed() for loop in owners))
        self.assertTrue(self.monitor.reset())
        self.assertTrue(self.monitor.get_dataframe().empty)


if __name__ == "__main__":
    unittest.main()

