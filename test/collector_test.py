import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("collector", Path(__file__).resolve().parents[1] / "src/server-collector.py")
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class CollectorTests(unittest.TestCase):
    def test_named_upstreams_and_location_log_inheritance(self):
        text = """
        error_log /var/log/nginx/error.log;
        http {
          upstream backend { server 127.0.0.1:3000; server [::1]:3001; }
          server { server_name example.com;
            location / { proxy_pass http://backend/path; error_log /var/log/site/location.log; }
          }
        }
        """
        result = collector.discover(text, "example.com", "/usr/share/nginx")
        self.assertEqual(result["upstreams"], ["127.0.0.1:3000", "[::1]:3001"])
        self.assertEqual([item["path"] for item in result["logs"]], ["/var/log/nginx/error.log", "/var/log/site/location.log"])
        self.assertFalse(result["logs"][0]["siteScoped"])
        self.assertTrue(result["logs"][1]["siteScoped"])

    def test_remembered_service_survives_a_stopped_upstream(self):
        calls = []
        def fake_command(args):
            calls.append(args)
            if args[:2] == ["nginx", "-T"]:
                return {"code": 0, "stdout": "http { server { server_name example.com; location / { proxy_pass http://127.0.0.1:3000; } } }", "stderr": ""}
            if args == ["systemctl", "is-active", "app.service"]:
                return {"code": 3, "stdout": "failed\n", "stderr": ""}
            return {"code": 0, "stdout": "", "stderr": ""}
        with patch.object(collector, "command", side_effect=fake_command):
            report = collector.collect({"hostname": "example.com", "discoveredService": "app.service", "collectLogs": True})
        self.assertEqual(report["app"]["state"], "failed")
        self.assertTrue(any(call[0] == "journalctl" and call[-1] == "app.service" for call in calls))

    def test_running_process_does_not_invent_a_systemd_unit_state(self):
        def fake_command(args):
            if args[0] == "systemctl":
                return {"code": 1, "stdout": "", "stderr": "System has not been booted with systemd."}
            return {"code": 0, "stdout": "", "stderr": ""}
        with patch.object(collector, "command", side_effect=fake_command):
            report = collector.collect({"hostname": "example.com"})
        self.assertEqual(report["nginx"]["process"], "running")
        self.assertEqual(report["nginx"]["service"], "unavailable")

    def test_config_with_includes_quotes_and_disabled_access_log(self):
        text = """
        # configuration file /etc/nginx/nginx.conf:
        error_log /var/log/nginx/error.log;
        http { log_format main '$request {foo}'; access_log /var/log/nginx/access.log; }
        # configuration file /etc/nginx/conf.d/site.conf:
        server { server_name *.example.com; access_log off; error_log /var/log/site.log;
          location / { proxy_pass http://127.0.0.1:3000; } }
        """
        result = collector.discover(text, "app.example.com", "/usr/share/nginx")
        self.assertTrue(result["matched"])
        self.assertEqual([item["path"] for item in result["logs"]], ["/var/log/site.log"])
        self.assertEqual(result["upstreams"], ["http://127.0.0.1:3000"])

    def test_tail_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "error.log"
            path.write_text("old line\n" * 20000 + "last error\n")
            result = collector.tail_file(str(path))
            self.assertTrue(result["ok"])
            self.assertLessEqual(len(result["lines"]), 300)
            self.assertEqual(result["lines"][-1], "last error")
            self.assertFalse(collector.tail_file(directory)["ok"])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX only")
    def test_fifo_is_rejected_without_opening_it(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "pipe")
            os.mkfifo(path)
            self.assertFalse(collector.tail_file(path)["ok"])


if __name__ == "__main__":
    unittest.main()
