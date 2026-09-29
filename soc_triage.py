from __future__ import annotations

import csv
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator


SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational", "Unknown")
STATUSES = ("New", "In progress", "Escalated", "Closed")
DISPOSITIONS = ("Undetermined", "True positive", "False positive", "Benign positive", "Duplicate")
MAX_IMPORT_ROWS = 10000
FLAGGED_PORTS = {
	21: ("FTP", "High"),
	23: ("Telnet", "High"),
	445: ("SMB", "Medium"),
	1433: ("Microsoft SQL Server", "Medium"),
	1521: ("Oracle Database", "Medium"),
	3306: ("MySQL", "Medium"),
	3389: ("Remote Desktop", "Medium"),
	5432: ("PostgreSQL", "Medium"),
	5900: ("VNC", "Medium"),
}

FIELD_ALIASES = {
	"source_event_id": ("source_event_id", "alert_id", "event_id", "incident_id", "id"),
	"title": ("title", "alert_name", "name", "rule_name", "detection_name", "event_name"),
	"severity": ("severity", "risk", "risk_level", "priority"),
	"created_at": ("created_at", "timestamp", "time", "event_time", "detected_at", "first_seen"),
	"source": ("source", "source_product", "product", "detection_source", "tool"),
	"hostname": ("hostname", "host", "device_name", "computer_name", "asset"),
	"username": ("username", "user", "account", "user_name", "account_name"),
	"source_ip": ("source_ip", "src_ip", "sourceip", "client_ip", "ip_address"),
	"destination_ip": ("destination_ip", "dest_ip", "dst_ip", "destinationip", "remote_ip"),
	"description": ("description", "message", "details", "summary", "event_description"),
}


def utc_now() -> str:
	return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_data_directory() -> Path:
	local_app_data = os.environ.get("LOCALAPPDATA")
	if local_app_data:
		return Path(local_app_data) / "NetTier1" / "data"
	return Path.home() / ".local" / "share" / "NetTier1" / "data"


def normalize_severity(value: str) -> str:
	severity = value.strip().title()
	aliases = {
		"Info": "Informational", "Notice": "Informational", "Warning": "Medium",
		"Emergency": "Critical", "Sev 1": "Critical", "P1": "Critical",
		"Sev 2": "High", "P2": "High", "Sev 3": "Medium", "P3": "Medium",
		"Sev 4": "Low", "P4": "Low", "Severe": "High",
	}
	severity = aliases.get(severity, severity)
	return severity if severity in SEVERITIES else "Unknown"


def safe_csv_value(value: str) -> str:
	if value.startswith(("=", "+", "-", "@", "\t", "\r")):
		return "'" + value
	return value


def normalize_field(value: str) -> str:
	return "".join(character for character in value.casefold() if character.isalnum())


class AlertStore:
	"""Local SQLite store for alert triage records and an append-only action history."""

	def __init__(self, database_path: Path | str | None = None) -> None:
		self.database_path = Path(database_path) if database_path else get_data_directory() / "cases.sqlite3"
		self.database_path.parent.mkdir(parents=True, exist_ok=True)
		self._initialize()

	def _connect(self) -> sqlite3.Connection:
		connection = sqlite3.connect(self.database_path, timeout=10)
		connection.row_factory = sqlite3.Row
		return connection

	@contextmanager
	def _connection(self) -> Iterator[sqlite3.Connection]:
		connection = self._connect()
		try:
			with connection:
				yield connection
		finally:
			connection.close()

	def _initialize(self) -> None:
		with self._connection() as connection:
			connection.execute("PRAGMA journal_mode=WAL")
			connection.executescript(
				"""
				CREATE TABLE IF NOT EXISTS alerts (
					case_id TEXT PRIMARY KEY,
					source_event_id TEXT NOT NULL DEFAULT '',
					created_at TEXT NOT NULL,
					imported_at TEXT NOT NULL,
					title TEXT NOT NULL,
					severity TEXT NOT NULL,
					status TEXT NOT NULL,
					disposition TEXT NOT NULL,
					source TEXT NOT NULL,
					hostname TEXT NOT NULL,
					username TEXT NOT NULL,
					source_ip TEXT NOT NULL,
					destination_ip TEXT NOT NULL,
					description TEXT NOT NULL,
					notes TEXT NOT NULL DEFAULT ''
				);
				DROP INDEX IF EXISTS alerts_source_event_id;
				CREATE UNIQUE INDEX IF NOT EXISTS alerts_source_event_id
					ON alerts(source, source_event_id) WHERE source_event_id <> '';
				CREATE TABLE IF NOT EXISTS case_history (
					history_id INTEGER PRIMARY KEY AUTOINCREMENT,
					case_id TEXT NOT NULL,
					at TEXT NOT NULL,
					action TEXT NOT NULL,
					detail TEXT NOT NULL,
					FOREIGN KEY(case_id) REFERENCES alerts(case_id)
				);
				CREATE TABLE IF NOT EXISTS monitor_hosts (
					scope TEXT NOT NULL,
					host TEXT NOT NULL,
					first_seen TEXT NOT NULL,
					last_seen TEXT NOT NULL,
					PRIMARY KEY(scope, host)
				);
				CREATE TABLE IF NOT EXISTS monitor_scopes (
					scope TEXT PRIMARY KEY,
					baseline_at TEXT NOT NULL
				);
				CREATE TABLE IF NOT EXISTS monitor_services (
					scope TEXT NOT NULL,
					host TEXT NOT NULL,
					port INTEGER NOT NULL,
					first_seen TEXT NOT NULL,
					last_seen TEXT NOT NULL,
					PRIMARY KEY(scope, host, port)
				);
				CREATE INDEX IF NOT EXISTS alerts_queue_order
					ON alerts(status, severity, created_at DESC);
				"""
			)
			connection.execute(
				"INSERT OR IGNORE INTO monitor_scopes(scope, baseline_at) "
				"SELECT scope, MIN(first_seen) FROM monitor_hosts GROUP BY scope"
			)
			schema_version = connection.execute("PRAGMA user_version").fetchone()[0]
			if schema_version < 1:
				connection.execute("DROP INDEX IF EXISTS alerts_source_event_id")
				connection.execute(
					"CREATE UNIQUE INDEX IF NOT EXISTS alerts_source_product_event "
					"ON alerts(source, source_event_id) WHERE source_event_id <> ''"
				)
				connection.execute("PRAGMA user_version = 1")

	def _insert_alert(self, connection: sqlite3.Connection, values: dict[str, str]) -> str:
		title = values.get("title", "").strip()
		if not title:
			raise ValueError("An alert title is required.")
		case_id = uuid.uuid4().hex[:12].upper()
		created_at = values.get("created_at", "").strip() or utc_now()
		alert = {
			"case_id": case_id,
			"source_event_id": values.get("source_event_id", "").strip(),
			"created_at": created_at,
			"imported_at": utc_now(),
			"title": title,
			"severity": normalize_severity(values.get("severity", "Unknown")),
			"status": "New",
			"disposition": "Undetermined",
			"source": values.get("source", "").strip() or "Manual entry",
			"hostname": values.get("hostname", "").strip(),
			"username": values.get("username", "").strip(),
			"source_ip": values.get("source_ip", "").strip(),
			"destination_ip": values.get("destination_ip", "").strip(),
			"description": values.get("description", "").strip(),
			"notes": "",
		}
		connection.execute(
			"INSERT INTO alerts VALUES (:case_id, :source_event_id, :created_at, :imported_at, "
			":title, :severity, :status, :disposition, :source, :hostname, :username, "
			":source_ip, :destination_ip, :description, :notes)",
			alert,
		)
		connection.execute(
			"INSERT INTO case_history(case_id, at, action, detail) VALUES (?, ?, ?, ?)",
			(case_id, utc_now(), "Created", f"Alert added from {alert['source']}"),
		)
		return case_id

	def add_alert(self, values: dict[str, str]) -> str:
		with self._connection() as connection:
			return self._insert_alert(connection, values)

	def add_demo_alerts(self) -> tuple[int, int]:
		"""Insert a small, repeatable set of clearly synthetic SOC practice alerts."""
		now = datetime.now(timezone.utc)
		demo_alerts = (
			("DEMO-001", "High", "Successful sign-in after repeated failures", "FIN-LT-04", "j.smith.lab", "198.51.100.24", "192.0.2.80", "Synthetic lab event: several failed sign-ins were followed by a successful sign-in from a new source address. Validate identity-provider logs, MFA result, user confirmation, and source context."),
			("DEMO-002", "Critical", "Office application launched encoded PowerShell", "WS-017", "a.kolev.lab", "203.0.113.45", "192.0.2.17", "Synthetic lab event: endpoint telemetry reports an Office process starting PowerShell with an encoded command. Review the process tree, command line, file origin, child processes, and containment status in the source EDR."),
			("DEMO-003", "Medium", "Endpoint protection quarantined a downloaded file", "ENG-WS-09", "m.petrov.lab", "192.0.2.55", "203.0.113.81", "Synthetic lab event: an endpoint product quarantined a downloaded file. Confirm the detection name, hash, download origin, action result, and whether related execution occurred."),
			("DEMO-004", "Medium", "Unusual DNS query volume from application host", "SRV-APP-02", "svc-app.lab", "192.0.2.60", "203.0.113.10", "Synthetic lab event: a resolver alert reports a short burst of uncommon DNS queries. Compare query names and timing with application behavior, proxy records, and the asset owner's change window."),
			("DEMO-005", "Low", "Privileged account used during a change window", "SRV-DB-01", "admin.lab", "192.0.2.91", "192.0.2.20", "Synthetic lab event: an administrative sign-in overlaps a documented maintenance window. Verify the change ticket, approved account, source host, and expected actions before deciding whether to close or escalate."),
		)
		added = skipped = 0
		with self._connection() as connection:
			for index, (event_id, severity, title, hostname, username, source_ip, destination_ip, description) in enumerate(demo_alerts):
				values = {
					"source_event_id": event_id,
					"created_at": (now - timedelta(minutes=index * 17)).isoformat(timespec="seconds"),
					"title": title,
					"severity": severity,
					"source": "SOC Desk synthetic demo",
					"hostname": hostname,
					"username": username,
					"source_ip": source_ip,
					"destination_ip": destination_ip,
					"description": description,
				}
				try:
					self._insert_alert(connection, values)
				except sqlite3.IntegrityError:
					skipped += 1
				else:
					added += 1
		return added, skipped

	def record_monitor_cycle(
		self,
		scope: str,
		observed_services: list[tuple[str, int]],
		observed_hosts: list[str] | None = None,
	) -> tuple[bool, list[str], list[tuple[str, int]], list[str]]:
		"""Persist observed hosts/services and create cases for new or flagged findings."""
		now = utc_now()
		new_hosts: list[str] = []
		new_services: list[tuple[str, int]] = []
		case_ids: list[str] = []
		hosts = sorted({host for host, _port in observed_services} | set(observed_hosts or []))
		with self._connection() as connection:
			baseline = connection.execute(
				"SELECT 1 FROM monitor_scopes WHERE scope = ?", (scope,)
			).fetchone() is None
			if baseline:
				connection.execute(
					"INSERT INTO monitor_scopes(scope, baseline_at) VALUES (?, ?)", (scope, now)
				)
			for host in hosts:
				known = connection.execute(
					"SELECT 1 FROM monitor_hosts WHERE scope = ? AND host = ?", (scope, host)
				).fetchone()
				if known is None:
					new_hosts.append(host)
					connection.execute(
						"INSERT INTO monitor_hosts(scope, host, first_seen, last_seen) VALUES (?, ?, ?, ?)",
						(scope, host, now, now),
					)
				else:
					connection.execute(
						"UPDATE monitor_hosts SET last_seen = ? WHERE scope = ? AND host = ?",
						(now, scope, host),
					)
			for host, port in sorted(set(observed_services)):
				known = connection.execute(
					"SELECT 1 FROM monitor_services WHERE scope = ? AND host = ? AND port = ?",
					(scope, host, port),
				).fetchone()
				if known is None:
					new_services.append((host, port))
					connection.execute(
						"INSERT INTO monitor_services(scope, host, port, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
						(scope, host, port, now, now),
					)
				else:
					connection.execute(
						"UPDATE monitor_services SET last_seen = ? WHERE scope = ? AND host = ? AND port = ?",
						(now, scope, host, port),
					)

			for host in new_hosts if not baseline else ():
				case_ids.append(self._insert_alert(connection, {
					"source_event_id": f"monitor-device:{scope}:{host}",
					"title": f"New device observed on monitored network: {host}",
					"severity": "Low",
					"source": "SOC Desk network monitor",
					"hostname": host,
					"description": f"{host} was not in the prior observation baseline for {scope}. It was seen responding on a selected TCP port or in the Windows IPv4 neighbor cache. Neighbor entries can be stale; verify this asset in approved inventory. This is not proof of suspicious activity.",
				}))
			for host, port in new_services:
				if port not in FLAGGED_PORTS:
					continue
				service, severity = FLAGGED_PORTS[port]
				case_ids.append(self._insert_alert(connection, {
					"source_event_id": f"monitor-service:{scope}:{host}:{port}",
					"title": f"Review exposed {service} service on {host}",
					"severity": severity,
					"source": "SOC Desk network monitor",
					"hostname": host,
					"destination_ip": host,
					"description": f"TCP port {port} ({service}) responded on {host} in {scope}. This is an exposure heuristic, not a confirmed vulnerability; verify business need, asset ownership, and access controls.",
				}))
		return baseline, new_hosts if not baseline else [], new_services, case_ids

	def import_csv(self, csv_path: Path | str) -> tuple[int, int]:
		added = skipped = 0
		with Path(csv_path).open("r", encoding="utf-8-sig", newline="") as csv_file:
			reader = csv.DictReader(csv_file)
			if not reader.fieldnames:
				raise ValueError("The CSV file is empty or has no header row.")
			column_map = {normalize_field(name): name for name in reader.fieldnames if name}
			mapping = {
				field: next(
					(column_map[normalize_field(alias)] for alias in aliases if normalize_field(alias) in column_map),
					None,
				)
				for field, aliases in FIELD_ALIASES.items()
			}
			if not mapping["title"]:
				raise ValueError("Could not find an alert title column (for example: title, alert_name, or rule_name).")
			with self._connection() as connection:
				for row_number, row in enumerate(reader, start=1):
					if row_number > MAX_IMPORT_ROWS:
						raise ValueError(f"Imports are limited to {MAX_IMPORT_ROWS} rows at a time.")
					values = {
						field: (row.get(column) or "").strip() if column else ""
						for field, column in mapping.items()
					}
					if not values["title"]:
						skipped += 1
						continue
					try:
						self._insert_alert(connection, values)
					except sqlite3.IntegrityError:
						skipped += 1
					else:
						added += 1
		return added, skipped

	def list_alerts(
		self,
		search: str = "",
		status: str | list[str] = "All",
		severity: str | list[str] = "All",
		limit: int | None = None,
		offset: int = 0,
	) -> list[dict[str, str]]:
		where, parameters = self._alert_filters(search, status, severity)
		pagination = ""
		if limit is not None:
			if limit < 1:
				raise ValueError("Page size must be a positive integer.")
			pagination = " LIMIT ? OFFSET ?"
			parameters.extend((limit, max(0, offset)))
		with self._connection() as connection:
			rows = connection.execute(
				f"SELECT * FROM alerts {where} ORDER BY "
				"CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 "
				"WHEN 'Low' THEN 3 ELSE 4 END, created_at DESC"
				f"{pagination}",
				parameters,
			).fetchall()
		return [dict(row) for row in rows]

	@staticmethod
	def _alert_filters(
		search: str,
		status: str | list[str],
		severity: str | list[str],
	) -> tuple[str, list[str]]:
		conditions = []
		parameters: list[str] = []
		status_values = [status] if isinstance(status, str) else status
		severity_values = [severity] if isinstance(severity, str) else severity
		status_values = [] if not status_values or "All" in status_values else status_values
		severity_values = [] if not severity_values or "All" in severity_values else severity_values
		if status_values:
			conditions.append(f"status IN ({', '.join('?' for _ in status_values)})")
			parameters.extend(status_values)
		if severity_values:
			conditions.append(f"severity IN ({', '.join('?' for _ in severity_values)})")
			parameters.extend(severity_values)
		if search.strip():
			conditions.append("(title LIKE ? OR hostname LIKE ? OR username LIKE ? OR source_ip LIKE ? OR destination_ip LIKE ? OR source_event_id LIKE ?)")
			parameters.extend([f"%{search.strip()}%"] * 6)
		where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
		return where, parameters

	def count_alerts(
		self,
		search: str = "",
		status: str | list[str] = "All",
		severity: str | list[str] = "All",
	) -> int:
		where, parameters = self._alert_filters(search, status, severity)
		with self._connection() as connection:
			return connection.execute(f"SELECT COUNT(*) FROM alerts {where}", parameters).fetchone()[0]

	def dashboard_summary(self) -> tuple[int, int, int, int]:
		with self._connection() as connection:
			row = connection.execute(
				"SELECT "
				"COALESCE(SUM(status <> 'Closed'), 0), "
				"COALESCE(SUM(status <> 'Closed' AND severity IN ('Critical', 'High')), 0), "
				"COALESCE(SUM(status = 'Escalated'), 0), "
				"COALESCE(SUM(status = 'Closed'), 0) FROM alerts"
			).fetchone()
		return tuple(row)

	def dashboard_alerts(self, limit: int = 8) -> list[dict[str, str]]:
		return self.list_alerts(
			status=["New", "In progress", "Escalated"], limit=limit, offset=0
		)

	def get_alert(self, case_id: str) -> dict[str, str] | None:
		with self._connection() as connection:
			row = connection.execute("SELECT * FROM alerts WHERE case_id = ?", (case_id,)).fetchone()
		return dict(row) if row else None

	def get_history(self, case_id: str) -> list[dict[str, str]]:
		with self._connection() as connection:
			rows = connection.execute(
				"SELECT at, action, detail FROM case_history WHERE case_id = ? ORDER BY history_id",
				(case_id,),
			).fetchall()
		return [dict(row) for row in rows]

	def update_triage(self, case_id: str, status: str, disposition: str, notes: str) -> None:
		if status not in STATUSES:
			raise ValueError("Choose a valid case status.")
		if disposition not in DISPOSITIONS:
			raise ValueError("Choose a valid triage disposition.")
		with self._connection() as connection:
			current = connection.execute("SELECT * FROM alerts WHERE case_id = ?", (case_id,)).fetchone()
			if current is None:
				raise ValueError("This case no longer exists.")
			connection.execute(
				"UPDATE alerts SET status = ?, disposition = ?, notes = ? WHERE case_id = ?",
				(status, disposition, notes.strip(), case_id),
			)
			changes = []
			if current["status"] != status:
				changes.append(f"Status: {current['status']} -> {status}")
			if current["disposition"] != disposition:
				changes.append(f"Disposition: {current['disposition']} -> {disposition}")
			if current["notes"] != notes.strip():
				changes.append("Analyst notes updated")
			if changes:
				connection.execute(
					"INSERT INTO case_history(case_id, at, action, detail) VALUES (?, ?, ?, ?)",
					(case_id, utc_now(), "Triage updated", "; ".join(changes)),
				)

	def export_csv(self, csv_path: Path | str) -> int:
		alerts = self.list_alerts()
		fieldnames = (
			"case_id", "source_event_id", "created_at", "imported_at", "title", "severity",
			"status", "disposition", "source", "hostname", "username", "source_ip",
			"destination_ip", "description", "notes",
		)
		with Path(csv_path).open("w", encoding="utf-8-sig", newline="") as csv_file:
			writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
			writer.writeheader()
			writer.writerows({key: safe_csv_value(value) for key, value in alert.items()} for alert in alerts)
		return len(alerts)