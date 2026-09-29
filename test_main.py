import csv
import tempfile
import unittest
from pathlib import Path

from Main import (
    MAX_HOSTS,
    MAX_PORTS,
    ScanInputError,
    parse_ports,
    parse_neighbor_host_output,
    resolve_monitor_scope,
    resolve_targets,
    validate_monitor_settings,
)
from soc_triage import AlertStore, normalize_severity


class ParsePortsTests(unittest.TestCase):
    def test_parses_and_deduplicates_ports(self):
        self.assertEqual(parse_ports("443, 80,443"), [80, 443])

    def test_rejects_invalid_port_values(self):
        for value in ("0", "65536", "abc", "80,"):
            with self.subTest(value=value), self.assertRaises(ScanInputError):
                parse_ports(value)

    def test_enforces_port_limit(self):
        value = ",".join(str(port) for port in range(1, MAX_PORTS + 2))
        with self.assertRaises(ScanInputError):
            parse_ports(value)


class ResolveTargetsTests(unittest.TestCase):
    def test_parses_single_ipv4_host(self):
        target, addresses = resolve_targets("192.0.2.10")
        self.assertEqual(target, "192.0.2.10")
        self.assertEqual([str(address) for address in addresses], ["192.0.2.10"])

    def test_parses_small_cidr(self):
        _, addresses = resolve_targets("192.0.2.0/30")
        self.assertEqual([str(address) for address in addresses], ["192.0.2.1", "192.0.2.2"])

    def test_rejects_ranges_over_host_limit(self):
        with self.assertRaises(ScanInputError):
            resolve_targets("10.0.0.0/16")

    def test_rejects_ipv6(self):
        with self.assertRaises(ScanInputError):
            resolve_targets("2001:db8::1")


class AlertStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.database_path = Path(self.temporary_directory.name) / "cases.sqlite3"
        self.store = AlertStore(self.database_path)

    def test_triage_updates_are_persisted_and_audited(self):
        case_id = self.store.add_alert({"title": "Suspicious PowerShell", "severity": "High"})
        self.store.update_triage(case_id, "Escalated", "True positive", "Verified in endpoint telemetry.")

        reopened_store = AlertStore(self.database_path)
        alert = reopened_store.get_alert(case_id)
        self.assertEqual(alert["status"], "Escalated")
        self.assertEqual(alert["disposition"], "True positive")
        self.assertEqual(alert["notes"], "Verified in endpoint telemetry.")
        self.assertEqual(len(reopened_store.get_history(case_id)), 2)

    def test_csv_import_maps_common_columns_and_skips_duplicate_event_ids(self):
        csv_path = Path(self.temporary_directory.name) / "alerts.csv"
        with csv_path.open("w", encoding="utf-8", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=("Alert ID", "Rule Name", "Risk Level", "Host Name", "User Name", "Message"))
            writer.writeheader()
            writer.writerow({"Alert ID": "evt-42", "Rule Name": "Unusual sign-in", "Risk Level": "High", "Host Name": "ws-01", "User Name": "analyst", "Message": "New location"})
            writer.writerow({"Alert ID": "evt-42", "Rule Name": "Unusual sign-in duplicate", "Risk Level": "High"})

        self.assertEqual(self.store.import_csv(csv_path), (1, 1))
        alert = self.store.list_alerts()[0]
        self.assertEqual(alert["source_event_id"], "evt-42")
        self.assertEqual(alert["hostname"], "ws-01")
        self.assertEqual(alert["username"], "analyst")
        self.assertEqual(alert["severity"], "High")

    def test_csv_import_requires_a_title_column(self):
        csv_path = Path(self.temporary_directory.name) / "bad.csv"
        csv_path.write_text("host,level\nws-01,high\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "title column"):
            self.store.import_csv(csv_path)

    def test_csv_export_contains_current_triage_values_and_safe_cells(self):
        case_id = self.store.add_alert({"title": "=HYPERLINK(\"https://example.invalid\")", "severity": "Critical"})
        self.store.update_triage(case_id, "In progress", "Undetermined", "Checking authentication logs.")
        csv_path = Path(self.temporary_directory.name) / "export.csv"

        self.assertEqual(self.store.export_csv(csv_path), 1)
        with csv_path.open("r", encoding="utf-8-sig", newline="") as csv_file:
            alert = next(csv.DictReader(csv_file))
        self.assertEqual(alert["status"], "In progress")
        self.assertEqual(alert["notes"], "Checking authentication logs.")
        self.assertTrue(alert["title"].startswith("'=HYPERLINK"))

    def test_common_severity_aliases(self):
        self.assertEqual(normalize_severity("P1"), "Critical")
        self.assertEqual(normalize_severity("sev 2"), "High")
        self.assertEqual(normalize_severity("not a severity"), "Unknown")

    def test_source_event_ids_are_scoped_to_their_product(self):
        self.store.add_alert({"title": "Endpoint alert", "source": "EDR", "source_event_id": "42"})
        self.store.add_alert({"title": "Identity alert", "source": "Identity", "source_event_id": "42"})
        self.assertEqual(len(self.store.list_alerts()), 2)

    def test_list_alerts_supports_multiple_status_and_severity_filters(self):
        self.store.add_alert({"title": "Low new", "severity": "Low"})
        high_case = self.store.add_alert({"title": "High working", "severity": "High"})
        self.store.update_triage(high_case, "In progress", "Undetermined", "Reviewing")
        critical_case = self.store.add_alert({"title": "Critical escalated", "severity": "Critical"})
        self.store.update_triage(critical_case, "Escalated", "Undetermined", "Escalated")

        results = self.store.list_alerts(status=["New", "Escalated"], severity=["Low", "Critical"])
        self.assertCountEqual([alert["title"] for alert in results], ["Low new", "Critical escalated"])

    def test_alert_pagination_and_count_share_the_same_filters(self):
        for index in range(7):
            self.store.add_alert({"title": f"Case {index}", "severity": "Medium"})

        first_page = self.store.list_alerts(severity=["Medium"], limit=3, offset=0)
        second_page = self.store.list_alerts(severity=["Medium"], limit=3, offset=3)
        last_page = self.store.list_alerts(severity=["Medium"], limit=3, offset=6)
        self.assertEqual((len(first_page), len(second_page), len(last_page)), (3, 3, 1))
        self.assertEqual(self.store.count_alerts(severity=["Medium"]), 7)

    def test_dashboard_summary_uses_case_statuses_and_severity(self):
        self.store.add_alert({"title": "Open urgent", "severity": "High"})
        closed_id = self.store.add_alert({"title": "Closed critical", "severity": "Critical"})
        self.store.update_triage(closed_id, "Closed", "False positive", "Benign test data")
        escalated_id = self.store.add_alert({"title": "Escalated medium", "severity": "Medium"})
        self.store.update_triage(escalated_id, "Escalated", "Undetermined", "Needs review")
        self.assertEqual(self.store.dashboard_summary(), (2, 1, 1, 1))

    def test_demo_alerts_are_synthetic_and_idempotent(self):
        self.assertEqual(self.store.add_demo_alerts(), (5, 0))
        self.assertEqual(self.store.add_demo_alerts(), (0, 5))
        alerts = self.store.list_alerts()
        self.assertEqual(len(alerts), 5)
        self.assertTrue(all(alert["source"] == "SOC Desk synthetic demo" for alert in alerts))
        self.assertTrue(all("Synthetic lab event:" in alert["description"] for alert in alerts))

    def test_first_monitor_cycle_establishes_baseline_without_new_device_alert(self):
        baseline, new_hosts, new_services, case_ids = self.store.record_monitor_cycle(
            "192.168.10.0/24", [("192.168.10.5", 80)]
        )
        self.assertTrue(baseline)
        self.assertEqual(new_hosts, [])
        self.assertEqual(new_services, [("192.168.10.5", 80)])
        self.assertEqual(case_ids, [])

    def test_empty_first_cycle_still_marks_scope_baselined(self):
        scope = "192.168.10.0/24"
        baseline, new_hosts, new_services, case_ids = self.store.record_monitor_cycle(scope, [])
        self.assertTrue(baseline)
        self.assertEqual((new_hosts, new_services, case_ids), ([], [], []))

        baseline, new_hosts, new_services, case_ids = self.store.record_monitor_cycle(
            scope, [("192.168.10.9", 80)]
        )
        self.assertFalse(baseline)
        self.assertEqual(new_hosts, ["192.168.10.9"])
        self.assertEqual(new_services, [("192.168.10.9", 80)])
        self.assertEqual(len(case_ids), 1)

    def test_neighbor_only_device_creates_a_review_case(self):
        baseline, new_hosts, new_services, case_ids = self.store.record_monitor_cycle(
            "192.168.10.0/24", [], ["192.168.10.12"]
        )
        self.assertTrue(baseline)
        self.assertEqual(new_hosts, [])
        self.assertEqual(new_services, [])
        self.assertEqual(case_ids, [])

        baseline, new_hosts, new_services, case_ids = self.store.record_monitor_cycle(
            "192.168.10.0/24", [], ["192.168.10.12", "192.168.10.13"]
        )
        self.assertFalse(baseline)
        self.assertEqual(new_hosts, ["192.168.10.13"])
        self.assertEqual(new_services, [])
        self.assertEqual(len(case_ids), 1)

    def test_later_monitor_cycles_create_device_and_flagged_service_cases_once(self):
        scope = "192.168.10.0/24"
        self.store.record_monitor_cycle(scope, [("192.168.10.5", 80)])
        baseline, new_hosts, new_services, case_ids = self.store.record_monitor_cycle(
            scope, [("192.168.10.5", 80), ("192.168.10.9", 445)]
        )
        self.assertFalse(baseline)
        self.assertEqual(new_hosts, ["192.168.10.9"])
        self.assertEqual(new_services, [("192.168.10.9", 445)])
        self.assertEqual(len(case_ids), 2)
        self.assertEqual(len(self.store.list_alerts()), 2)

        _, repeated_hosts, repeated_services, repeated_cases = self.store.record_monitor_cycle(
            scope, [("192.168.10.5", 80), ("192.168.10.9", 445)]
        )
        self.assertEqual(repeated_hosts, [])
        self.assertEqual(repeated_services, [])
        self.assertEqual(repeated_cases, [])


class MonitorSettingsTests(unittest.TestCase):
    def test_neighbor_output_is_validated_and_limited_to_scope(self):
        _, addresses = resolve_monitor_scope("192.168.10.0/30")
        output = "192.168.10.1\n192.168.10.2\n8.8.8.8\nnot-an-ip\n"
        self.assertEqual(parse_neighbor_host_output(output, addresses), ["192.168.10.1", "192.168.10.2"])

    def test_monitor_scope_must_be_private_and_within_host_limit(self):
        scope, addresses = resolve_monitor_scope("192.168.10.0/30")
        self.assertEqual(scope, "192.168.10.0/30")
        self.assertEqual(len(addresses), 2)
        for target in ("8.8.8.8", "2001:db8::1", "10.0.0.0/16"):
            with self.subTest(target=target), self.assertRaises(ScanInputError):
                resolve_monitor_scope(target)

    def test_monitor_interval_and_port_count_are_bounded(self):
        ports, interval = validate_monitor_settings("22,80,443", "300")
        self.assertEqual(ports, [22, 80, 443])
        self.assertEqual(interval, 300)
        for invalid_interval in ("299", "86401", "abc"):
            with self.subTest(interval=invalid_interval), self.assertRaises(ScanInputError):
                validate_monitor_settings("22", invalid_interval)


if __name__ == "__main__":
    unittest.main()