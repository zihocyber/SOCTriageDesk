from __future__ import annotations

import csv
import ipaddress
import os
import platform
import queue
import socket
import sqlite3
import subprocess
import threading
import tkinter as tk
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections.abc import Callable
from tkinter import font as tkfont
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from soc_triage import AlertStore, DISPOSITIONS, FLAGGED_PORTS, SEVERITIES, STATUSES, get_data_directory


APP_NAME = "NetTier1"
MAX_HOSTS = 256
MAX_PORTS = 64
MAX_WORKERS = 64
MAX_MONITOR_PORTS = 16
MIN_MONITOR_INTERVAL = 300
MAX_MONITOR_INTERVAL = 86400
QUEUE_PAGE_SIZE = 100
CONNECT_TIMEOUT = 0.4
DEFAULT_PORTS = "21,22,23,25,53,80,110,139,143,443,445,3306,3389,5432,5900,8080,8443"
DEFAULT_MONITOR_PORTS = "21,22,23,80,443,445,3389,3306,5432,5900"
SERVICE_NAMES = {
	21: "FTP",
	22: "SSH",
	23: "Telnet",
	25: "SMTP",
	53: "DNS",
	80: "HTTP",
	110: "POP3",
	139: "NetBIOS",
	143: "IMAP",
	443: "HTTPS",
	445: "SMB",
	3306: "MySQL",
	3389: "RDP",
	5432: "PostgreSQL",
	5900: "VNC",
	8080: "HTTP alternate",
	8443: "HTTPS alternate",
}


class ScanInputError(ValueError):
	pass


def resolve_monitor_scope(value: str) -> tuple[str, list[ipaddress.IPv4Address]]:
	"""Accept only a bounded RFC1918 CIDR or private IPv4 host for monitoring."""
	target = value.strip()
	try:
		network = ipaddress.ip_network(target, strict=False)
	except ValueError as exc:
		raise ScanInputError("Enter a private IPv4 address or CIDR (for example, 192.168.1.0/24).") from exc
	if not isinstance(network, ipaddress.IPv4Network):
		raise ScanInputError("The monitor supports private IPv4 scopes only.")
	private_ranges = (
		ipaddress.ip_network("10.0.0.0/8"),
		ipaddress.ip_network("172.16.0.0/12"),
		ipaddress.ip_network("192.168.0.0/16"),
	)
	if not any(network.subnet_of(private_range) for private_range in private_ranges):
		raise ScanInputError("The monitor is restricted to RFC1918 private IPv4 ranges.")
	host_count = network.num_addresses if network.prefixlen >= 31 else network.num_addresses - 2
	if host_count > MAX_HOSTS:
		raise ScanInputError(f"Monitor scopes are limited to {MAX_HOSTS} hosts.")
	return network.with_prefixlen, list(network.hosts())


def validate_monitor_settings(ports_value: str, interval_value: str) -> tuple[list[int], int]:
	ports = parse_ports(ports_value)
	if len(ports) > MAX_MONITOR_PORTS:
		raise ScanInputError(f"Scheduled checks are limited to {MAX_MONITOR_PORTS} ports.")
	try:
		interval = int(interval_value)
	except ValueError as exc:
		raise ScanInputError("Enter the monitor interval in whole seconds.") from exc
	if interval < MIN_MONITOR_INTERVAL or interval > MAX_MONITOR_INTERVAL:
		raise ScanInputError("Monitor interval must be between 300 seconds (5 minutes) and 86400 seconds (24 hours).")
	return ports, interval


def parse_ports(value: str) -> list[int]:
	"""Parse a comma-separated list of TCP ports, rejecting oversized input."""
	pieces = [piece.strip() for piece in value.split(",")]
	if not pieces or any(not piece for piece in pieces):
		raise ScanInputError("Enter TCP ports as comma-separated numbers.")

	try:
		ports = sorted({int(piece) for piece in pieces})
	except ValueError as exc:
		raise ScanInputError("Ports must be whole numbers separated by commas.") from exc

	if any(port < 1 or port > 65535 for port in ports):
		raise ScanInputError("TCP ports must be between 1 and 65535.")
	if len(ports) > MAX_PORTS:
		raise ScanInputError(f"Choose no more than {MAX_PORTS} unique ports per scan.")
	return ports


def resolve_targets(value: str) -> tuple[str, list[ipaddress.IPv4Address]]:
	"""Resolve an IPv4 address, IPv4 CIDR, or hostname within the host cap."""
	target = value.strip()
	if not target:
		raise ScanInputError("Enter an IPv4 address, IPv4 CIDR, or hostname.")

	try:
		network = ipaddress.ip_network(target, strict=False)
	except ValueError:
		try:
			records = socket.getaddrinfo(target, None, socket.AF_INET, socket.SOCK_STREAM)
		except socket.gaierror as exc:
			raise ScanInputError(f"Could not resolve an IPv4 address for '{target}'.") from exc
		addresses = sorted({ipaddress.IPv4Address(record[4][0]) for record in records})
		if not addresses:
			raise ScanInputError(f"No IPv4 addresses were found for '{target}'.")
		if len(addresses) > MAX_HOSTS:
			raise ScanInputError(f"The target resolves to more than {MAX_HOSTS} addresses.")
		return target, addresses

	if not isinstance(network, ipaddress.IPv4Network):
		raise ScanInputError("Only IPv4 targets are supported.")

	host_count = network.num_addresses if network.prefixlen >= 31 else network.num_addresses - 2
	if host_count > MAX_HOSTS:
		raise ScanInputError(f"The target includes {host_count} hosts; the limit is {MAX_HOSTS}.")
	return target, list(network.hosts())


def get_log_directory() -> Path:
	local_app_data = os.environ.get("LOCALAPPDATA")
	if local_app_data:
		return Path(local_app_data) / APP_NAME / "logs"
	return Path.home() / ".local" / "share" / APP_NAME / "logs"


def check_tcp_port(address: ipaddress.IPv4Address, port: int) -> bool:
	try:
		with socket.create_connection((str(address), port), timeout=CONNECT_TIMEOUT):
			return True
	except OSError:
		return False


def read_local_neighbor_hosts(
	scope: str,
	addresses: list[ipaddress.IPv4Address],
) -> list[str]:
	"""Read recently resolved IPv4 peers from Windows without capturing traffic."""
	if os.name != "nt":
		return []
	command = (
		"Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
		"Where-Object { $_.State -in @('Reachable','Stale','Delay','Probe') } | "
		"ForEach-Object { $_.IPAddress }"
	)
	try:
		result = subprocess.run(
			["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
			capture_output=True,
			text=True,
			encoding="utf-8",
			errors="replace",
			timeout=5,
			check=False,
			creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
		)
	except (OSError, subprocess.TimeoutExpired):
		return []
	if result.returncode != 0:
		return []
	return parse_neighbor_host_output(result.stdout, addresses)


def parse_neighbor_host_output(
	output: str,
	addresses: list[ipaddress.IPv4Address],
) -> list[str]:
	allowed = {str(address) for address in addresses}
	neighbors = set()
	for line in output.splitlines():
		try:
			address = str(ipaddress.IPv4Address(line.strip()))
		except ipaddress.AddressValueError:
			continue
		if address in allowed:
			neighbors.add(address)
	return sorted(neighbors, key=ipaddress.IPv4Address)


def write_scan_log(
	target: str,
	ports: list[int],
	addresses: list[ipaddress.IPv4Address],
	open_services: list[tuple[str, int]],
	started: datetime,
	finished: datetime,
	status: str,
	error: str | None,
	neighbor_hosts: list[str] | None = None,
) -> Path:
	log_directory = get_log_directory()
	log_directory.mkdir(parents=True, exist_ok=True)
	log_path = log_directory / f"scan_{started.strftime('%Y%m%d_%H%M%S_%f')}.logs"

	open_by_host: dict[str, list[int]] = {str(address): [] for address in addresses}
	for host, port in open_services:
		open_by_host.setdefault(host, []).append(port)

	lines = [
		f"{APP_NAME} authorized network scan",
		f"Status: {status}",
		f"Target: {target}",
		f"Started: {started.astimezone().isoformat(timespec='seconds')}",
		f"Finished: {finished.astimezone().isoformat(timespec='seconds')}",
		f"Hosts selected: {len(addresses)}",
		f"TCP ports checked: {', '.join(map(str, ports))}",
		f"Windows neighbor-cache hosts observed: {', '.join(neighbor_hosts or []) or 'none/unavailable'}",
		"",
		"Results:",
	]
	for host in sorted(open_by_host, key=ipaddress.IPv4Address):
		host_ports = sorted(open_by_host[host])
		if host_ports:
			services = ", ".join(
				f"{port}/{SERVICE_NAMES.get(port, 'unknown')}" for port in host_ports
			)
			lines.append(f"{host}: {services}")
		elif neighbor_hosts and host in neighbor_hosts:
			lines.append(f"{host}: seen in Windows neighbor cache; no selected TCP ports responded")
		else:
			lines.append(f"{host}: no selected TCP ports responded")
	if error:
		lines.extend(("", f"Error: {error}"))
	lines.extend(("", "Note: A failed connection does not distinguish a closed port from filtering or an unavailable host."))
	log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
	return log_path


def run_scan(
	target: str,
	addresses: list[ipaddress.IPv4Address],
	ports: list[int],
	cancellation: threading.Event,
	events: queue.Queue,
) -> None:
	started = datetime.now().astimezone()
	open_services: list[tuple[str, int]] = []
	error = None
	status = "Completed"
	total = len(addresses) * len(ports)
	completed = 0

	try:
		with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, total)) as executor:
			futures = {
				executor.submit(check_tcp_port, address, port): (str(address), port)
				for address in addresses
				for port in ports
			}
			cancellation_handled = False
			for future in as_completed(futures):
				if cancellation.is_set() and not cancellation_handled:
					cancellation_handled = True
					for pending in futures:
						pending.cancel()
				if future.cancelled():
					continue
				host, port = futures[future]
				try:
					if future.result():
						open_services.append((host, port))
				except Exception as exc:
					error = f"A connection check failed: {exc}"
				completed += 1
				if completed % 32 == 0 or completed == total:
					events.put(("progress", completed, total))
		if cancellation.is_set():
			status = "Cancelled"
	except Exception as exc:
		status = "Failed"
		error = str(exc)

	finished = datetime.now().astimezone()
	try:
		log_path = write_scan_log(
			target, ports, addresses, open_services, started, finished, status, error
		)
	except OSError as exc:
		log_path = None
		error = f"Could not write the .logs file: {exc}"

	events.put(("scan_done", status, open_services, log_path, error))


def run_monitor(
	scope: str,
	addresses: list[ipaddress.IPv4Address],
	ports: list[int],
	interval: int,
	stop_event: threading.Event,
	events: queue.Queue,
) -> None:
	"""Run low-rate TCP observations until stopped; this does not capture packets."""
	try:
		store = AlertStore()
	except (OSError, sqlite3.Error) as exc:
		events.put(("monitor_failed", f"Could not open the local case database: {exc}"))
		events.put(("monitor_stopped",))
		return
	while not stop_event.is_set():
		events.put(("monitor_cycle_started",))
		started = datetime.now().astimezone()
		open_services: list[tuple[str, int]] = []
		error = None
		status = "Completed"
		jobs = len(addresses) * len(ports)
		try:
			with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, jobs)) as executor:
				futures = {
					executor.submit(check_tcp_port, address, port): (str(address), port)
					for address in addresses
					for port in ports
				}
				for future in as_completed(futures):
					if stop_event.is_set():
						for pending in futures:
							pending.cancel()
						break
					if future.cancelled():
						continue
					if future.result():
						open_services.append(futures[future])
			if stop_event.is_set():
				status = "Cancelled"
		except Exception as exc:
			status = "Failed"
			error = str(exc)

		new_hosts: list[str] = []
		new_services: list[tuple[str, int]] = []
		case_ids: list[str] = []
		neighbor_hosts = read_local_neighbor_hosts(scope, addresses) if status == "Completed" else []
		observed_hosts = {host for host, _port in open_services} | set(neighbor_hosts)
		baseline = False
		if status == "Completed":
			try:
				baseline, new_hosts, new_services, case_ids = store.record_monitor_cycle(
					scope, open_services, neighbor_hosts
				)
			except (OSError, sqlite3.Error) as exc:
				status = "Failed"
				error = f"Could not save monitor observations: {exc}"

		finished = datetime.now().astimezone()
		try:
			log_path = write_scan_log(
				scope, ports, addresses, open_services, started, finished, status, error, neighbor_hosts
			)
		except OSError as exc:
			log_path = None
			error = f"Could not write the .logs file: {exc}"
		events.put(("monitor_cycle", status, baseline, len(observed_hosts), new_hosts, new_services, case_ids, log_path, error))
		if stop_event.wait(interval):
			break
	events.put(("monitor_stopped",))


class AnimatedButton(tk.Canvas):
	"""Small Canvas button with per-widget animation and mouse/keyboard support."""

	def __init__(
		self,
		master: tk.Misc,
		text: str,
		command: Callable[[], None],
		colors: dict[str, str],
		accent: bool = False,
		state: str = "normal",
		anchor: str = "center",
		background: str | None = None,
		dropdown: bool = False,
		height: int = 42,
		checked: bool = False,
	) -> None:
		self._label = text
		self._command = command
		self._colors = colors
		self._accent = accent
		self._anchor = anchor
		self._canvas_background = background or colors["canvas"]
		self._dropdown = dropdown
		self._checked = checked
		self._menu_open = False
		self._enabled = state != "disabled"
		self._hovered = False
		self._pressed = False
		self._focused = False
		self._animation_job: str | None = None
		self._font = tkfont.Font(
			root=master,
			family="Segoe UI",
			size=10,
			weight="bold" if accent else "normal",
		)
		width = max(82, self._font.measure(text) + (48 if dropdown else 30))
		super().__init__(
			master,
			width=width,
			height=height,
			background=self._canvas_background,
			borderwidth=0,
			highlightthickness=0,
			takefocus=True,
			cursor="hand2",
		)
		self._current_color = self._target_color()
		self.bind("<Configure>", lambda _event: self._draw())
		self.bind("<Enter>", self._on_enter)
		self.bind("<Leave>", self._on_leave)
		self.bind("<ButtonPress-1>", self._on_press)
		self.bind("<ButtonRelease-1>", self._on_release)
		self.bind("<FocusIn>", self._on_focus_in)
		self.bind("<FocusOut>", self._on_focus_out)
		self.bind("<KeyPress-space>", self._on_key_press)
		self.bind("<KeyRelease-space>", self._on_key_release)
		self.bind("<KeyPress-Return>", self._on_key_press)
		self.bind("<KeyRelease-Return>", self._on_key_release)
		self.bind("<Destroy>", self._on_destroy)
		super().configure(takefocus=self._enabled, cursor="hand2" if self._enabled else "arrow")
		self._draw()

	@property
	def _base_color(self) -> str:
		return self._colors["accent"] if self._accent else self._colors["raised"]

	def configure(self, cnf=None, **kwargs):
		state = kwargs.pop("state", None)
		text = kwargs.pop("text", None)
		command = kwargs.pop("command", None)
		if state is not None:
			self._enabled = state != "disabled"
			self._pressed = False
			kwargs.setdefault("takefocus", self._enabled)
			kwargs.setdefault("cursor", "hand2" if self._enabled else "arrow")
		if text is not None:
			self._label = text
			self.configure(width=max(82, self._font.measure(text) + (48 if self._dropdown else 30)))
		if command is not None:
			self._command = command
		result = super().configure(cnf, **kwargs)
		if hasattr(self, "_colors"):
			self._animate()
		return result

	config = configure

	def _target_color(self) -> str:
		if not self._enabled:
			return self._colors["disabled"]
		if self._pressed:
			return self._colors["accent_pressed"] if self._accent else self._colors["pressed"]
		if self._hovered:
			return self._colors["accent_hover"] if self._accent else self._colors["hover"]
		return self._base_color

	def _animate(self) -> None:
		if self._animation_job:
			try:
				self.after_cancel(self._animation_job)
			except tk.TclError:
				pass
			self._animation_job = None
		start_color = self._current_color
		target_color = self._target_color()
		started = time.perf_counter()
		duration = 0.14

		def frame() -> None:
			if not self.winfo_exists():
				return
			progress = min(1.0, (time.perf_counter() - started) / duration)
			eased = progress * progress * (3 - 2 * progress)
			self._current_color = self._blend(start_color, target_color, eased)
			self._draw()
			if progress < 1.0:
				self._animation_job = self.after(16, frame)
			else:
				self._animation_job = None

		frame()

	def _draw(self) -> None:
		if not hasattr(self, "_colors") or not self.winfo_exists():
			return
		self.delete("all")
		width = max(1, self.winfo_width())
		height = max(1, self.winfo_height())
		if width <= 1 or height <= 1:
			return
		inset = 1
		radius = 9
		pressed_offset = 1 if self._pressed and self._enabled else 0
		left, top = inset, inset + pressed_offset
		right, bottom = width - inset, height - 4 + pressed_offset
		if not self._pressed:
			self._rounded_rectangle(1, 3, width - 1, height - 1, radius, self._colors["shadow"])
		outline = self._colors["accent"] if self._enabled and (self._focused or self._hovered) else self._colors["border"]
		text_color = self._colors["text"] if self._enabled and not self._accent else "#ffffff"
		if not self._enabled:
			text_color = self._colors["muted"]
		self._rounded_rectangle(left, top, right, bottom, radius, self._current_color, outline)
		text_x = width // 2 if self._anchor == "center" else 18
		text_anchor = "center" if self._anchor == "center" else "w"
		if self._checked:
			center_y = (top + bottom) // 2
			mark_fill = self._colors["accent"]
			self.create_oval(13, center_y - 6, 25, center_y + 6, fill=mark_fill, outline="")
			self.create_line(16, center_y, 19, center_y + 3, 23, center_y - 3, fill="#ffffff", width=1.5, capstyle="round", joinstyle="round")
			text_x = 35
			text_anchor = "w"
		self.create_text(text_x, (top + bottom) // 2, text=self._label, fill=text_color, font=self._font, anchor=text_anchor)
		if self._dropdown:
			center_x = width - 17
			center_y = (top + bottom) // 2
			vertical = -3 if self._menu_open else 3
			self.create_line(
				center_x - 4, center_y - vertical / 2,
				center_x, center_y + vertical / 2,
				center_x + 4, center_y - vertical / 2,
				fill=text_color, width=1.7, capstyle="round", joinstyle="round",
			)

	def _rounded_rectangle(self, left: int, top: int, right: int, bottom: int, radius: int, fill: str, outline: str = "") -> None:
		points = (
			left + radius, top, right - radius, top, right, top,
			right, top + radius, right, bottom - radius, right, bottom,
			right - radius, bottom, left + radius, bottom, left, bottom,
			left, bottom - radius, left, top + radius, left, top,
		)
		self.create_polygon(points, smooth=True, splinesteps=12, fill=fill, outline=outline, width=1 if outline else 0)

	@staticmethod
	def _blend(start: str, end: str, amount: float) -> str:
		start_rgb = tuple(int(start[index:index + 2], 16) for index in (1, 3, 5))
		end_rgb = tuple(int(end[index:index + 2], 16) for index in (1, 3, 5))
		return "#" + "".join(f"{round(first + (second - first) * amount):02x}" for first, second in zip(start_rgb, end_rgb))

	def _on_enter(self, _event=None) -> None:
		self._hovered = True
		self._animate()

	def _on_leave(self, _event=None) -> None:
		self._hovered = False
		self._pressed = False
		self._animate()

	def _on_press(self, _event=None) -> None:
		if self._enabled:
			self.focus_set()
			self._pressed = True
			self._animate()

	def _on_release(self, event) -> None:
		was_pressed = self._pressed and self._enabled
		inside = 0 <= event.x <= self.winfo_width() and 0 <= event.y <= self.winfo_height()
		self._pressed = False
		self._hovered = inside
		self._animate()
		if was_pressed and inside:
			self._command()

	def _on_focus_in(self, _event=None) -> None:
		self._focused = True
		self._draw()

	def _on_focus_out(self, _event=None) -> None:
		self._focused = False
		self._draw()

	def _on_key_press(self, _event=None) -> str:
		if self._enabled:
			self._pressed = True
			self._animate()
		return "break"

	def _on_key_release(self, _event=None) -> str:
		if self._enabled and self._pressed:
			self._pressed = False
			self._animate()
			self._command()
		return "break"

	def _on_destroy(self, _event=None) -> None:
		if self._animation_job:
			try:
				self.after_cancel(self._animation_job)
			except tk.TclError:
				pass

	def set_accent(self, accent: bool) -> None:
		if self._accent != accent:
			self._accent = accent
			self._animate()

	def set_menu_open(self, is_open: bool) -> None:
		self._menu_open = is_open
		self._draw()

	def set_checked(self, checked: bool) -> None:
		self._checked = checked
		self._draw()


class AnimatedDropdown(tk.Frame):
	"""App-styled dropdown that slides open and optionally supports multi-select."""

	_open_dropdown: AnimatedDropdown | None = None

	def __init__(
		self,
		master: tk.Misc,
		label: str,
		options: tuple[str, ...],
		selected: list[str],
		colors: dict[str, str],
		on_change: Callable[[list[str]], None],
		multiple: bool = False,
		all_option: bool = True,
		background: str | None = None,
	) -> None:
		self.label = label
		self.options = options
		self.selected = list(selected)
		self.colors = colors
		self.on_change = on_change
		self.multiple = multiple
		self.all_option = all_option
		self.committed = list(selected)
		self.popup: tk.Toplevel | None = None
		self.popup_frame: tk.Frame | None = None
		self.popup_rows: dict[str, AnimatedButton] = {}
		self.popup_job: str | None = None
		self.popup_height = 0
		self.popup_x = 0
		self.popup_y = 0
		self.popup_above = False
		self.is_closing = False
		self.outside_binding: str | None = None
		surface = background or colors["canvas"]
		super().__init__(master, background=surface, borderwidth=0, highlightthickness=0)
		self.button = AnimatedButton(
			self, self._display_value(), self.toggle, colors,
			anchor="w", background=surface, dropdown=True,
		)
		self.button.pack(fill="x", expand=True)
		self.bind("<Destroy>", self._on_destroy)

	def _display_value(self) -> str:
		if not self.multiple:
			return f"{self.label}: {self.selected[0] if self.selected else 'Select'}"
		if not self.selected:
			return f"{self.label}: Choose"
		if self.all_option and "All" in self.selected:
			return f"{self.label}: All"
		if len(self.selected) == 1:
			return f"{self.label}: {self.selected[0]}"
		return f"{self.label}: {len(self.selected)} selected"

	def set_values(self, selected: list[str]) -> None:
		self.selected = list(selected)
		self.committed = list(selected)
		self.button.configure(text=self._display_value())
		self._refresh_rows()

	def toggle(self) -> None:
		if self.popup:
			if self.is_closing:
				self._animate_popup(opening=True)
			else:
				self.close()
			return
		if AnimatedDropdown._open_dropdown and AnimatedDropdown._open_dropdown is not self:
			AnimatedDropdown._open_dropdown.close()
		self._open()

	def _open(self) -> None:
		self.selected = list(self.committed)
		self.button.configure(text=self._display_value())
		popup = tk.Toplevel(self.winfo_toplevel())
		popup.withdraw()
		popup.overrideredirect(True)
		popup.configure(background=self.colors["panel"])
		popup.transient(self.winfo_toplevel())
		frame = tk.Frame(
			popup,
			background=self.colors["panel"],
			highlightbackground=self.colors["border"],
			highlightthickness=1,
			padx=5,
			pady=5,
		)
		frame.pack(fill="both", expand=True)
		self.popup = popup
		self.popup_frame = frame
		self.popup_rows = {}
		for option in self.options:
			row = AnimatedButton(
				frame,
				self._option_label(option),
				lambda value=option: self._choose(value),
				self.colors,
				accent=option in self.selected,
				anchor="w",
				background=self.colors["panel"],
				height=32,
				checked=self.multiple and option in self.selected,
			)
			row.pack(fill="x", pady=1)
			self.popup_rows[option] = row
		if self.multiple:
			tk.Frame(frame, height=1, background=self.colors["border"]).pack(fill="x", pady=(5, 4))
			apply_button = AnimatedButton(
				frame, "Apply selection", self._apply, self.colors, accent=True,
				background=self.colors["panel"],
				height=36,
			)
			apply_button.pack(fill="x", pady=(0, 1))
		popup.bind("<Escape>", lambda _event: self.close())
		self.outside_binding = self.winfo_toplevel().bind("<Button-1>", self._on_outside_click, add="+")
		popup.update_idletasks()
		self.popup_height = min(frame.winfo_reqheight() + 2, popup.winfo_screenheight() - 32)
		self.popup_x = max(8, min(self.winfo_rootx(), popup.winfo_screenwidth() - self.winfo_width() - 8))
		below_y = self.winfo_rooty() + self.winfo_height() + 4
		self.popup_above = below_y + self.popup_height > popup.winfo_screenheight() - 12
		self.popup_y = max(8, self.winfo_rooty() - self.popup_height - 4) if self.popup_above else below_y
		width = max(self.winfo_width(), 190)
		popup.geometry(f"{width}x1+{self.popup_x}+{self.popup_y}")
		popup.deiconify()
		popup.lift()
		popup.update_idletasks()
		self.button.set_menu_open(True)
		self.is_closing = False
		AnimatedDropdown._open_dropdown = self
		self._animate_popup(opening=True)

	def _option_label(self, option: str) -> str:
		return option

	def _refresh_rows(self) -> None:
		for option, row in self.popup_rows.items():
			row.configure(text=self._option_label(option))
			row.set_accent(option in self.selected)
			row.set_checked(self.multiple and option in self.selected)

	def _choose(self, option: str) -> None:
		if self.multiple:
			if self.all_option and option == "All":
				self.selected = ["All"]
			else:
				if self.all_option:
					self.selected = [value for value in self.selected if value != "All"]
				if option in self.selected:
					self.selected.remove(option)
				else:
					self.selected.append(option)
				if not self.selected and self.all_option:
					self.selected = ["All"]
			self._refresh_rows()
			self.button.configure(text=self._display_value())
		else:
			self.selected = [option]
			self.committed = list(self.selected)
			self.button.configure(text=self._display_value())
			self.on_change(list(self.selected))
			self.close()

	def _apply(self) -> None:
		self.committed = list(self.selected)
		self.on_change(list(self.selected))
		self.close()

	def _animate_popup(self, opening: bool) -> None:
		popup = self.popup
		if not popup or not popup.winfo_exists():
			return
		if self.popup_job:
			try:
				popup.after_cancel(self.popup_job)
			except tk.TclError:
				pass
			self.popup_job = None
		start_height = popup.winfo_height()
		end_height = self.popup_height if opening else 1
		started = time.perf_counter()
		self.is_closing = not opening

		def frame() -> None:
			if not popup.winfo_exists():
				return
			progress = min(1.0, (time.perf_counter() - started) / 0.16)
			eased = progress * progress * (3 - 2 * progress)
			height = max(1, round(start_height + (end_height - start_height) * eased))
			y = self.popup_y + self.popup_height - height if self.popup_above else self.popup_y
			popup.geometry(f"{popup.winfo_width()}x{height}+{self.popup_x}+{y}")
			if progress < 1.0:
				self.popup_job = popup.after(16, frame)
			else:
				self.popup_job = None
				if not opening:
					popup.destroy()
					self.popup = None
					self.popup_frame = None
					self.popup_rows.clear()
					self._remove_outside_binding()
					self.is_closing = False
					self.button.set_menu_open(False)
					if AnimatedDropdown._open_dropdown is self:
						AnimatedDropdown._open_dropdown = None

		frame()

	def close(self) -> None:
		if not self.popup or self.is_closing:
			return
		if self.multiple:
			self.selected = list(self.committed)
			self.button.configure(text=self._display_value())
		self._animate_popup(opening=False)

	def _on_outside_click(self, event) -> None:
		if self.popup and event.widget.winfo_toplevel() is not self.popup:
			self.close()

	def _remove_outside_binding(self) -> None:
		if self.outside_binding:
			try:
				self.winfo_toplevel().unbind("<Button-1>", self.outside_binding)
			except tk.TclError:
				pass
			self.outside_binding = None

	def _on_destroy(self, _event=None) -> None:
		self._remove_outside_binding()
		if self.popup and self.popup.winfo_exists():
			self.popup.destroy()
		if AnimatedDropdown._open_dropdown is self:
			AnimatedDropdown._open_dropdown = None


class SmoothScrollbar(tk.Canvas):
	"""Minimal drag scrollbar that avoids the platform's legacy arrow chrome."""

	def __init__(self, master: tk.Misc, command: Callable[..., None], colors: dict[str, str]) -> None:
		self.command = command
		self.colors = colors
		self.first = 0.0
		self.last = 1.0
		self.drag_offset: float | None = None
		super().__init__(master, width=14, background=colors["canvas"], borderwidth=0, highlightthickness=0, takefocus=False)
		self.bind("<Configure>", lambda _event: self._draw())
		self.bind("<Button-1>", self._on_press)
		self.bind("<B1-Motion>", self._on_drag)
		self.bind("<ButtonRelease-1>", self._on_release)
		self.bind("<Enter>", lambda _event: self.configure(cursor="hand2"))
		self.bind("<Leave>", lambda _event: self.configure(cursor="arrow"))

	def set(self, first: str, last: str) -> None:
		self.first = max(0.0, min(1.0, float(first)))
		self.last = max(self.first, min(1.0, float(last)))
		self._draw()

	def _thumb_bounds(self) -> tuple[float, float]:
		height = max(1, self.winfo_height())
		thumb_height = max(34, (self.last - self.first) * height)
		thumb_height = min(height, thumb_height)
		travel = height - thumb_height
		top = self.first / max(0.0001, 1 - (self.last - self.first)) * travel
		return top, top + thumb_height

	def _draw(self) -> None:
		if not self.winfo_exists():
			return
		self.delete("all")
		width = max(1, self.winfo_width())
		height = max(1, self.winfo_height())
		center = width // 2
		self.create_line(center, 7, center, height - 7, fill=self.colors["scroll_rail"], width=4, capstyle="round")
		top, bottom = self._thumb_bounds()
		thumb = self.colors["scroll_thumb_hover"] if self.drag_offset is not None else self.colors["scroll_thumb"]
		self.create_line(center, top + 17, center, max(top + 17, bottom - 17), fill=thumb, width=6, capstyle="round", tags="thumb")
		self.create_oval(center - 3, top + 14, center + 3, top + 20, fill=thumb, outline="", tags="thumb")
		self.create_oval(center - 3, bottom - 20, center + 3, bottom - 14, fill=thumb, outline="", tags="thumb")

	def _on_press(self, event) -> None:
		top, bottom = self._thumb_bounds()
		if top <= event.y <= bottom:
			self.drag_offset = event.y - top
			self._draw()
		else:
			self.command("scroll", -1 if event.y < top else 1, "pages")

	def _on_drag(self, event) -> None:
		if self.drag_offset is None:
			return
		height = max(1, self.winfo_height())
		thumb_height = self._thumb_bounds()[1] - self._thumb_bounds()[0]
		travel = max(1, height - thumb_height)
		top = max(0.0, min(travel, event.y - self.drag_offset))
		self.command("moveto", top / travel)

	def _on_release(self, _event=None) -> None:
		self.drag_offset = None
		self._draw()


class SmoothTreeview(ttk.Treeview):
	"""Treeview with eased wheel scrolling and a restrained active-row tint."""

	def __init__(self, master: tk.Misc, colors: dict[str, str], **kwargs) -> None:
		self._colors = colors
		self._scroll_target: float | None = None
		self._scroll_job: str | None = None
		self._hovered_item = ""
		super().__init__(master, **kwargs)
		self.tag_configure("ui-hover", background=colors["hover"])
		self.bind("<MouseWheel>", self._on_mousewheel, add="+")
		self.bind("<Button-4>", lambda _event: self._scroll_lines(-3), add="+")
		self.bind("<Button-5>", lambda _event: self._scroll_lines(3), add="+")
		self.bind("<Motion>", self._on_motion, add="+")
		self.bind("<Leave>", self._clear_hover, add="+")
		self.bind("<<TreeviewSelect>>", self._clear_hover, add="+")
		self.bind("<Destroy>", self._cancel_scroll, add="+")

	def _on_mousewheel(self, event) -> str:
		steps = -event.delta / 120 * 3
		if event.delta and steps:
			self._scroll_lines(steps)
		return "break"

	def _scroll_lines(self, steps: float) -> None:
		first, last = self.yview()
		visible_fraction = max(0.001, last - first)
		visible_rows = max(1, self.winfo_height() // 32)
		row_fraction = visible_fraction / visible_rows
		base = self._scroll_target if self._scroll_job else first
		self._scroll_target = max(0.0, min(1.0 - visible_fraction, base + steps * row_fraction))
		if self._scroll_job:
			try:
				self.after_cancel(self._scroll_job)
			except tk.TclError:
				pass
		self._animate_scroll()

	def _animate_scroll(self) -> None:
		start = self.yview()[0]
		target = self._scroll_target if self._scroll_target is not None else start
		started = time.perf_counter()
		duration = 0.12

		def frame() -> None:
			if not self.winfo_exists():
				return
			progress = min(1.0, (time.perf_counter() - started) / duration)
			eased = progress * progress * (3 - 2 * progress)
			current_target = self._scroll_target if self._scroll_target is not None else target
			self.yview_moveto(start + (current_target - start) * eased)
			if progress < 1.0:
				self._scroll_job = self.after(16, frame)
			else:
				self._scroll_job = None
				self._scroll_target = None
				self.yview_moveto(current_target)

		frame()

	def _on_motion(self, event) -> None:
		item = self.identify_row(event.y)
		if item == self._hovered_item:
			return
		self._remove_hover_tag()
		if item and item not in self.selection():
			tags = tuple(tag for tag in self.item(item, "tags") if tag != "ui-hover") + ("ui-hover",)
			self.item(item, tags=tags)
			self._hovered_item = item

	def _remove_hover_tag(self) -> None:
		if self._hovered_item and self.exists(self._hovered_item):
			tags = tuple(tag for tag in self.item(self._hovered_item, "tags") if tag != "ui-hover")
			self.item(self._hovered_item, tags=tags)
		self._hovered_item = ""

	def _clear_hover(self, _event=None) -> None:
		self._remove_hover_tag()

	def _cancel_scroll(self, _event=None) -> None:
		if self._scroll_job:
			try:
				self.after_cancel(self._scroll_job)
			except tk.TclError:
				pass
			self._scroll_job = None


class NetTier1App:
	def __init__(self, root: tk.Tk) -> None:
		self.root = root
		self.store = AlertStore()
		self.events: queue.Queue = queue.Queue()
		self.cancellation = threading.Event()
		self.worker: threading.Thread | None = None
		self.monitor_stop_event = threading.Event()
		self.monitor_worker: threading.Thread | None = None
		self.selected_case_id: str | None = None
		self.refresh_job: str | None = None
		self.queue_page = 0
		self.queue_total = 0
		self.page_animation_job: str | None = None
		self.current_page: str | None = None
		self.cursor_busy = False
		self.scan_busy = False
		self.monitor_cycle_busy = False
		self.csv_busy = False
		self.csv_worker: threading.Thread | None = None
		self.sound_enabled = tk.BooleanVar(value=True)

		root.title("SOC Desk | Alert Triage")
		root.geometry("1240x800")
		root.minsize(900, 620)
		root.protocol("WM_DELETE_WINDOW", self.close)
		self._configure_style()
		self._build_layout()
		self.root.bind_all("<Motion>", self._update_cursor, add="+")
		self.refresh_all()
		self.root.after(100, self._process_events)

	def _configure_style(self) -> None:
		style = ttk.Style(self.root)
		if "clam" in style.theme_names():
			style.theme_use("clam")
		self.colors = {
			"canvas": "#0a0b10",
			"panel": "#12131b",
			"raised": "#1b1c27",
			"border": "#302d40",
			"text": "#f4f2fb",
			"muted": "#aaa5ba",
			"accent": "#8b6be0",
			"accent_active": "#a58bf0",
			"accent_hover": "#a58bf0",
			"accent_pressed": "#694bb8",
			"hover": "#292638",
			"pressed": "#15151f",
			"disabled": "#272631",
			"shadow": "#06070a",
			"selection": "#40305f",
			"scroll_rail": "#171720",
			"scroll_thumb": "#4a4558",
			"scroll_thumb_hover": "#9a82db",
		}
		self.root.configure(background=self.colors["canvas"])
		style.configure("TFrame", background=self.colors["canvas"])
		style.configure("TLabel", background=self.colors["canvas"], foreground=self.colors["text"], font=("Segoe UI", 10))
		style.configure("Title.TLabel", font=("Segoe UI", 22, "bold"), foreground="#ffffff")
		style.configure("Section.TLabel", font=("Segoe UI", 12, "bold"), foreground=self.colors["text"])
		style.configure("Muted.TLabel", foreground=self.colors["muted"])
		style.configure("Metric.TLabel", font=("Segoe UI", 22, "bold"), foreground=self.colors["text"])
		style.configure("Card.Muted.TLabel", background=self.colors["panel"], foreground=self.colors["muted"])
		style.configure("Card.Metric.TLabel", background=self.colors["panel"], font=("Segoe UI", 22, "bold"), foreground=self.colors["accent"])
		style.configure("TButton", padding=(11, 7), font=("Segoe UI", 10), background=self.colors["raised"], foreground=self.colors["text"], bordercolor=self.colors["border"])
		style.map("TButton", background=[("active", self.colors["border"])], foreground=[("disabled", self.colors["muted"])])
		style.configure("Accent.TButton", background=self.colors["accent"], foreground="#100d18", font=("Segoe UI", 10, "bold"))
		style.map("Accent.TButton", background=[("active", self.colors["accent_active"]), ("disabled", self.colors["border"])])
		style.configure("TEntry", fieldbackground=self.colors["panel"], foreground=self.colors["text"], insertcolor=self.colors["text"], bordercolor=self.colors["border"], relief="flat", padding=(9, 7))
		style.configure("TCombobox", fieldbackground=self.colors["panel"], foreground=self.colors["text"], background=self.colors["raised"], arrowcolor=self.colors["accent"])
		style.map("TCombobox", fieldbackground=[("readonly", self.colors["panel"])], foreground=[("readonly", self.colors["text"])])
		style.configure("TNotebook", background=self.colors["canvas"], borderwidth=0)
		style.configure("TNotebook.Tab", padding=(16, 10), font=("Segoe UI", 10, "bold"), background=self.colors["canvas"], foreground=self.colors["muted"])
		style.map("TNotebook.Tab", background=[("selected", self.colors["panel"]), ("active", self.colors["raised"])], foreground=[("selected", self.colors["accent"])])
		style.configure("Sidebar.TFrame", background=self.colors["panel"])
		style.configure("SidebarBrand.TLabel", background=self.colors["panel"], foreground=self.colors["text"], font=("Segoe UI", 13, "bold"))
		style.configure("SidebarMeta.TLabel", background=self.colors["panel"], foreground=self.colors["muted"], font=("Segoe UI", 8, "bold"))
		style.configure("Dark.TCheckbutton", background=self.colors["canvas"], foreground=self.colors["muted"], font=("Segoe UI", 9))
		style.map("Dark.TCheckbutton", background=[("active", self.colors["canvas"])], foreground=[("selected", self.colors["text"])])
		style.configure("Treeview", rowheight=32, font=("Segoe UI", 10), background=self.colors["panel"], fieldbackground=self.colors["panel"], foreground=self.colors["text"], bordercolor=self.colors["panel"], relief="flat", borderwidth=0)
		style.map("Treeview", background=[("selected", self.colors["selection"])], foreground=[("selected", "#ffffff")])
		style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"), background=self.colors["raised"], foreground=self.colors["muted"], bordercolor=self.colors["raised"], relief="flat", borderwidth=0, padding=(8, 7))
		style.map("Treeview.Heading", background=[("active", self.colors["hover"])], foreground=[("active", self.colors["text"])])
		style.configure("Card.TFrame", background=self.colors["panel"], relief="flat")
		style.configure("TLabelframe", background=self.colors["canvas"], foreground=self.colors["muted"], bordercolor=self.colors["border"])
		style.configure("TLabelframe.Label", background=self.colors["canvas"], foreground=self.colors["accent"])
		style.configure("Horizontal.TProgressbar", troughcolor=self.colors["raised"], background=self.colors["accent"])

	def _button(
		self,
		parent: tk.Misc,
		text: str,
		command: Callable[[], None],
		accent: bool = False,
		state: str = "normal",
		anchor: str = "center",
		background: str | None = None,
	) -> AnimatedButton:
		return AnimatedButton(parent, text, command, self.colors, accent=accent, state=state, anchor=anchor, background=background)

	def _entry(self, parent: tk.Misc, textvariable=None, width: int | None = None) -> tk.Entry:
		options = {
			"textvariable": textvariable,
			"font": ("Segoe UI", 10),
			"background": self.colors["panel"],
			"foreground": self.colors["text"],
			"insertbackground": self.colors["accent_active"],
			"selectbackground": self.colors["selection"],
			"selectforeground": "#ffffff",
			"relief": "flat",
			"borderwidth": 0,
			"highlightthickness": 1,
			"highlightbackground": self.colors["border"],
			"highlightcolor": self.colors["accent"],
			"disabledbackground": self.colors["panel"],
			"disabledforeground": self.colors["muted"],
		}
		if width is not None:
			options["width"] = width
		return tk.Entry(parent, **options)

	def _build_layout(self) -> None:
		outer = ttk.Frame(self.root, padding=(24, 18))
		outer.pack(fill="both", expand=True)
		header = ttk.Frame(outer)
		header.pack(fill="x", pady=(0, 14))
		title_block = ttk.Frame(header)
		title_block.pack(side="left")
		ttk.Label(title_block, text="SOC Desk", style="Title.TLabel").pack(anchor="w")
		ttk.Label(
			title_block,
			text="Alert triage workspace | Local case records | Analyst-controlled actions",
			style="Muted.TLabel",
		).pack(anchor="w", pady=(2, 0))
		self._button(header, "Open data folder", self.open_data_folder).pack(side="right", anchor="s")

		body = ttk.Frame(outer)
		body.pack(fill="both", expand=True)
		sidebar = ttk.Frame(body, style="Sidebar.TFrame", width=196, padding=(12, 16))
		sidebar.pack(side="left", fill="y", padx=(0, 12))
		sidebar.pack_propagate(False)
		ttk.Label(sidebar, text="SOC DESK", style="SidebarBrand.TLabel").pack(anchor="w", padx=8)
		ttk.Label(sidebar, text="ANALYST WORKSPACE", style="SidebarMeta.TLabel").pack(anchor="w", padx=8, pady=(3, 24))
		self.work_area = ttk.Frame(body, padding=14)
		self.work_area.pack(side="left", fill="both", expand=True)
		self.dashboard_tab = ttk.Frame(self.work_area, padding=8)
		self.alerts_tab = ttk.Frame(self.work_area, padding=8)
		self.network_tab = ttk.Frame(self.work_area, padding=8)
		self.monitor_tab = ttk.Frame(self.work_area, padding=8)
		self.guide_tab = ttk.Frame(self.work_area, padding=8)
		self.pages = {
			"overview": self.dashboard_tab,
			"alerts": self.alerts_tab,
			"network": self.network_tab,
			"monitor": self.monitor_tab,
			"guide": self.guide_tab,
		}
		self.nav_buttons = {}
		for key, label in (
			("overview", "Overview"),
			("alerts", "Alert queue"),
			("network", "Network review"),
			("monitor", "Local monitor"),
			("guide", "Shift guide"),
		):
			button = self._button(sidebar, label, lambda page=key: self.show_page(page), anchor="w", background=self.colors["panel"])
			button.pack(fill="x", pady=3)
			self.nav_buttons[key] = button
		ttk.Frame(sidebar, style="Sidebar.TFrame").pack(fill="both", expand=True)
		ttk.Label(sidebar, text="LOCAL CASEBOOK", style="SidebarMeta.TLabel").pack(anchor="w", padx=8, pady=(10, 2))
		self._build_dashboard()
		self._build_alerts_tab()
		self._build_network_tab()
		self._build_monitor_tab()
		self._build_guide_tab()
		for page in self.pages.values():
			page.place(relx=0, rely=0, relwidth=1, relheight=1)
		self.show_page("overview")
		accent_rule = tk.Frame(header, height=2, background=self.colors["accent"])
		accent_rule.pack(side="bottom", fill="x", pady=(12, 0))

	def show_page(self, page_name: str) -> None:
		page = self.pages.get(page_name)
		if page is None or self.current_page == page_name:
			return
		if self.page_animation_job:
			self.root.after_cancel(self.page_animation_job)
			self.page_animation_job = None
		for name, existing_page in self.pages.items():
			if name != page_name:
				existing_page.place_forget()
		page.place(x=12, y=0, relwidth=1, relheight=1)
		page.tkraise()
		started = time.perf_counter()
		duration = 0.16

		def slide_in() -> None:
			if not page.winfo_exists():
				return
			progress = min(1.0, (time.perf_counter() - started) / duration)
			eased = progress * progress * (3 - 2 * progress)
			page.place_configure(x=round(12 * (1 - eased)), y=0, relwidth=1, relheight=1)
			if progress < 1.0:
				self.page_animation_job = self.root.after(16, slide_in)
			else:
				self.page_animation_job = None

		self.current_page = page_name
		slide_in()
		for name, button in self.nav_buttons.items():
			button.set_accent(name == page_name)

	def _build_dashboard(self) -> None:
		ttk.Label(self.dashboard_tab, text="Shift overview", style="Section.TLabel").pack(anchor="w")
		ttk.Label(
			self.dashboard_tab,
			text="A local triage workbench. Import approved alerts or opt in to bounded, scheduled TCP observations.",
			style="Muted.TLabel",
		).pack(anchor="w", pady=(3, 16))
		metrics = ttk.Frame(self.dashboard_tab)
		metrics.pack(fill="x", pady=(0, 18))
		self.metric_vars = {}
		for column, (key, label) in enumerate((("open", "Open cases"), ("urgent", "Critical / high"), ("escalated", "Escalated"), ("closed", "Closed"))):
			card = ttk.Frame(metrics, style="Card.TFrame", padding=(16, 12))
			card.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 10, 0))
			metrics.columnconfigure(column, weight=1)
			ttk.Label(card, text=label, style="Card.Muted.TLabel").pack(anchor="w")
			variable = tk.StringVar(value="0")
			self.metric_vars[key] = variable
			ttk.Label(card, textvariable=variable, style="Card.Metric.TLabel").pack(anchor="w", pady=(4, 0))

		section = ttk.Frame(self.dashboard_tab)
		section.pack(fill="x", pady=(0, 8))
		ttk.Label(section, text="Priority review", style="Section.TLabel").pack(side="left")
		self._button(section, "Open alert queue", lambda: self.show_page("alerts")).pack(side="right")
		columns = ("severity", "title", "host", "status", "case")
		self.dashboard_queue = SmoothTreeview(self.dashboard_tab, self.colors, columns=columns, show="headings", height=9)
		for column, label, width in (("severity", "Severity", 110), ("title", "Alert", 390), ("host", "Host", 190), ("status", "Status", 130), ("case", "Case", 110)):
			self.dashboard_queue.heading(column, text=label)
			self.dashboard_queue.column(column, width=width, anchor="w")
		self.dashboard_queue.pack(fill="x", expand=False)
		self.dashboard_queue.bind("<Double-1>", self._open_selected_dashboard_case)
		ttk.Label(
			self.dashboard_tab,
			text=f"Case database: {get_data_directory() / 'cases.sqlite3'}",
			style="Muted.TLabel",
		).pack(anchor="w", pady=(14, 0))

	def _build_alerts_tab(self) -> None:
		toolbar = ttk.Frame(self.alerts_tab)
		toolbar.pack(fill="x", pady=(0, 12))
		ttk.Label(toolbar, text="Cases", style="Section.TLabel").pack(side="left")
		self.import_button = self._button(toolbar, "Import CSV", self.import_alerts)
		self.import_button.pack(side="right")
		self.export_button = self._button(toolbar, "Export CSV", self.export_alerts)
		self.export_button.pack(side="right", padx=(0, 8))
		self._button(toolbar, "Load demo cases", self.load_demo_alerts).pack(side="right", padx=(0, 8))
		self._button(toolbar, "New alert", self.new_alert, accent=True).pack(side="right", padx=(0, 8))

		filters = ttk.Frame(self.alerts_tab)
		filters.pack(fill="x", pady=(0, 10))
		ttk.Label(filters, text="Search").pack(side="left")
		self.search_var = tk.StringVar()
		search_entry = self._entry(filters, textvariable=self.search_var, width=34)
		search_entry.pack(side="left", padx=(7, 16))
		self.status_filter = ["All"]
		self.severity_filter = ["All"]
		self.status_dropdown = AnimatedDropdown(
			filters, "Status", ("All", *STATUSES), self.status_filter, self.colors,
			self._set_status_filter, multiple=True,
		)
		self.status_dropdown.pack(side="left", padx=(0, 8))
		self.severity_dropdown = AnimatedDropdown(
			filters, "Severity", ("All", *SEVERITIES), self.severity_filter, self.colors,
			self._set_severity_filter, multiple=True,
		)
		self.severity_dropdown.pack(side="left")
		self.search_var.trace_add("write", self._schedule_queue_refresh)

		queue_frame = ttk.Frame(self.alerts_tab)
		queue_frame.pack(fill="both", expand=True)
		columns = ("case", "time", "severity", "status", "title", "host", "source")
		self.alert_queue = SmoothTreeview(queue_frame, self.colors, columns=columns, show="headings", height=10, selectmode="browse")
		for column, label, width in (
			("case", "Case", 105), ("time", "Detected", 150), ("severity", "Severity", 105),
			("status", "Status", 115), ("title", "Alert", 300), ("host", "Host", 150), ("source", "Source", 145),
		):
			self.alert_queue.heading(column, text=label)
			self.alert_queue.column(column, width=width, anchor="w")
		queue_scroll = SmoothScrollbar(queue_frame, self.alert_queue.yview, self.colors)
		self.alert_queue.configure(yscrollcommand=queue_scroll.set)
		self.alert_queue.pack(side="left", fill="both", expand=True)
		queue_scroll.pack(side="right", fill="y")
		self.alert_queue.bind("<<TreeviewSelect>>", self._select_alert)
		pager = ttk.Frame(self.alerts_tab)
		pager.pack(fill="x", pady=(7, 0))
		self.queue_page_var = tk.StringVar(value="0 cases")
		ttk.Label(pager, textvariable=self.queue_page_var, style="Muted.TLabel").pack(side="left")
		self.queue_next_button = self._button(pager, "Next", self._next_queue_page, state="disabled")
		self.queue_next_button.pack(side="right")
		self.queue_previous_button = self._button(pager, "Previous", self._previous_queue_page, state="disabled")
		self.queue_previous_button.pack(side="right", padx=(0, 6))

		detail = ttk.LabelFrame(self.alerts_tab, text="Analyst triage", padding=12)
		detail.pack(fill="x", pady=(12, 0))
		self.alert_context = tk.StringVar(value="Select a case to review its event details and triage history.")
		ttk.Label(detail, textvariable=self.alert_context, style="Muted.TLabel", wraplength=1050, justify="left").pack(anchor="w", fill="x", pady=(0, 8))
		editor = ttk.Frame(detail)
		editor.pack(fill="x", expand=True)
		left = ttk.Frame(editor)
		left.pack(side="left", fill="both", expand=True)
		ttk.Label(left, text="Analyst notes / evidence", style="Muted.TLabel").pack(anchor="w")
		self.notes_text = tk.Text(left, height=4, wrap="word", font=("Segoe UI", 10), relief="solid", borderwidth=1, background=self.colors["panel"], foreground=self.colors["text"], insertbackground=self.colors["accent"], selectbackground=self.colors["selection"], highlightbackground=self.colors["border"], highlightcolor=self.colors["accent"])
		self.notes_text.pack(fill="both", expand=True, pady=(4, 0))
		right = ttk.Frame(editor, padding=(14, 0, 0, 0))
		right.pack(side="left", fill="y")
		ttk.Label(right, text="Status").grid(row=0, column=0, sticky="w")
		self.case_status = tk.StringVar(value=STATUSES[0])
		self.case_status_dropdown = AnimatedDropdown(
			right, "Status", STATUSES, [STATUSES[0]], self.colors,
			lambda selected: self.case_status.set(selected[0]),
		)
		self.case_status_dropdown.grid(row=1, column=0, sticky="ew", pady=(3, 8))
		ttk.Label(right, text="Disposition").grid(row=2, column=0, sticky="w")
		self.case_disposition = tk.StringVar(value=DISPOSITIONS[0])
		self.case_disposition_dropdown = AnimatedDropdown(
			right, "Disposition", DISPOSITIONS, [DISPOSITIONS[0]], self.colors,
			lambda selected: self.case_disposition.set(selected[0]),
		)
		self.case_disposition_dropdown.grid(row=3, column=0, sticky="ew", pady=(3, 8))
		self._button(right, "Save triage", self.save_triage, accent=True).grid(row=4, column=0, sticky="ew")
		self.history_var = tk.StringVar(value="History appears after selecting a case.")
		ttk.Label(detail, textvariable=self.history_var, style="Muted.TLabel", wraplength=1050, justify="left").pack(anchor="w", fill="x", pady=(8, 0))

	def _build_network_tab(self) -> None:
		outer = self.network_tab
		ttk.Label(outer, text="Authorized network review", style="Section.TLabel").pack(anchor="w")
		ttk.Label(
			outer,
			text="One-time TCP service exposure check. It cannot confirm a vulnerability or inspect network traffic.",
			style="Muted.TLabel",
		).pack(anchor="w", pady=(3, 14))

		form = ttk.Frame(outer)
		form.pack(fill="x", pady=(0, 14))
		ttk.Label(form, text="IPv4 host, CIDR, or hostname").grid(row=0, column=0, sticky="w")
		ttk.Label(form, text="TCP ports").grid(row=0, column=1, sticky="w", padx=(12, 0))
		self.target_var = tk.StringVar()
		self.ports_var = tk.StringVar(value=DEFAULT_PORTS)
		self.target_entry = self._entry(form, textvariable=self.target_var)
		self.target_entry.grid(row=1, column=0, sticky="ew", pady=(5, 0))
		self._entry(form, textvariable=self.ports_var, width=40).grid(
			row=1, column=1, sticky="ew", padx=(12, 0), pady=(5, 0)
		)
		port_options = tuple(f"{port} {name}" for port, name in SERVICE_NAMES.items())
		self.scan_port_dropdown = AnimatedDropdown(
			form, "Common ports", port_options, [], self.colors,
			self._set_scan_port_presets, multiple=True, all_option=False,
		)
		self.scan_port_dropdown.grid(row=2, column=1, sticky="ew", padx=(12, 0), pady=(8, 0))
		ttk.Label(form, text="Optional presets; you can also edit the port list above.", style="Muted.TLabel").grid(
			row=2, column=0, sticky="w", pady=(8, 0)
		)
		form.columnconfigure(0, weight=3)
		form.columnconfigure(1, weight=2)

		actions = ttk.Frame(outer)
		actions.pack(fill="x", pady=(0, 12))
		self.scan_button = self._button(actions, "Start scan", self.start_scan, accent=True)
		self.scan_button.pack(side="left")
		self.stop_button = self._button(actions, "Stop", self.stop_scan, state="disabled")
		self.stop_button.pack(side="left", padx=(8, 0))
		self._button(actions, "Open logs folder", self.open_log_folder).pack(side="right")

		results_frame = ttk.Frame(outer)
		results_frame.pack(fill="both", expand=True)
		columns = ("host", "port", "service", "state")
		self.results = SmoothTreeview(results_frame, self.colors, columns=columns, show="headings")
		for column, title, width in (
			("host", "Host", 220),
			("port", "Port", 100),
			("service", "Service", 220),
			("state", "State", 120),
		):
			self.results.heading(column, text=title)
			self.results.column(column, width=width, anchor="w")
		scrollbar = SmoothScrollbar(results_frame, self.results.yview, self.colors)
		self.results.configure(yscrollcommand=scrollbar.set)
		self.results.pack(side="left", fill="both", expand=True)
		scrollbar.pack(side="right", fill="y")

		footer = ttk.Frame(outer)
		footer.pack(fill="x", pady=(12, 0))
		self.status_var = tk.StringVar(value="Ready")
		ttk.Label(footer, textvariable=self.status_var, style="Muted.TLabel").pack(side="left")
		self.progress = ttk.Progressbar(footer, mode="determinate", length=180)
		self.progress.pack(side="right")
		self.target_entry.focus_set()

	def _build_monitor_tab(self) -> None:
		ttk.Label(self.monitor_tab, text="Scheduled local-network observations", style="Section.TLabel").pack(anchor="w")
		ttk.Label(
			self.monitor_tab,
			text="Active TCP checks on an explicitly entered private IPv4 scope. Keep this app open; stop monitoring before leaving.",
			style="Muted.TLabel",
			wraplength=1050,
		).pack(anchor="w", pady=(4, 8))
		ttk.Label(
			self.monitor_tab,
			text="On Windows, each cycle also checks the OS IPv4 neighbor cache, which can reveal peers even when selected TCP ports are closed. Cache entries can be stale, so verify devices. Other systems rely on TCP replies. This is not packet capture and misses brief traffic between cycles. Findings are leads, not proof of suspicious activity or CVEs.",
			style="Muted.TLabel",
			wraplength=1050,
		).pack(anchor="w", pady=(0, 16))

		form = ttk.Frame(self.monitor_tab)
		form.pack(fill="x", pady=(0, 12))
		ttk.Label(form, text="Authorized private IPv4 CIDR").grid(row=0, column=0, sticky="w")
		ttk.Label(form, text="TCP ports (max 16)").grid(row=0, column=1, sticky="w", padx=(12, 0))
		ttk.Label(form, text="Interval in seconds (300-86400)").grid(row=0, column=2, sticky="w", padx=(12, 0))
		self.monitor_scope_var = tk.StringVar()
		self.monitor_ports_var = tk.StringVar(value=DEFAULT_MONITOR_PORTS)
		self.monitor_interval_var = tk.StringVar(value=str(MIN_MONITOR_INTERVAL))
		self._entry(form, textvariable=self.monitor_scope_var).grid(row=1, column=0, sticky="ew", pady=(5, 0))
		self._entry(form, textvariable=self.monitor_ports_var).grid(row=1, column=1, sticky="ew", padx=(12, 0), pady=(5, 0))
		self._entry(form, textvariable=self.monitor_interval_var, width=12).grid(row=1, column=2, sticky="ew", padx=(12, 0), pady=(5, 0))
		monitor_port_options = tuple(f"{port} {name}" for port, name in list(SERVICE_NAMES.items())[:MAX_MONITOR_PORTS])
		selected_monitor_ports = [option for option in monitor_port_options if int(option.split(" ", 1)[0]) in parse_ports(DEFAULT_MONITOR_PORTS)]
		self.monitor_port_dropdown = AnimatedDropdown(
			form, "Monitor port presets", monitor_port_options, selected_monitor_ports, self.colors,
			self._set_monitor_port_presets, multiple=True, all_option=False,
		)
		self.monitor_port_dropdown.grid(row=2, column=1, sticky="ew", padx=(12, 0), pady=(8, 0))
		form.columnconfigure(0, weight=2)
		form.columnconfigure(1, weight=2)
		form.columnconfigure(2, weight=1)

		actions = ttk.Frame(self.monitor_tab)
		actions.pack(fill="x", pady=(0, 14))
		self.monitor_start_button = self._button(actions, "Start monitoring", self.start_monitor, accent=True)
		self.monitor_start_button.pack(side="left")
		self.monitor_stop_button = self._button(actions, "Stop monitoring", self.stop_monitor, state="disabled")
		self.monitor_stop_button.pack(side="left", padx=(8, 0))
		ttk.Checkbutton(
			actions, text="Alert sound", variable=self.sound_enabled, style="Dark.TCheckbutton"
		).pack(side="right", padx=(8, 0))
		self.monitor_status_var = tk.StringVar(value="Stopped | No devices are monitored until you start a scan.")
		ttk.Label(self.monitor_tab, textvariable=self.monitor_status_var, style="Muted.TLabel", wraplength=1050).pack(anchor="w", pady=(0, 12))

		ttk.Label(self.monitor_tab, text="Observations create review cases in Alert queue", style="Section.TLabel").pack(anchor="w", pady=(4, 8))
		columns = ("time", "finding", "host", "severity", "case")
		findings_frame = ttk.Frame(self.monitor_tab)
		findings_frame.pack(fill="both", expand=True)
		self.monitor_findings = SmoothTreeview(findings_frame, self.colors, columns=columns, show="headings", height=8)
		for column, label, width in (("time", "First seen", 180), ("finding", "Review lead", 440), ("host", "Host", 170), ("severity", "Severity", 110), ("case", "Case", 110)):
			self.monitor_findings.heading(column, text=label)
			self.monitor_findings.column(column, width=width, anchor="w")
		monitor_scroll = SmoothScrollbar(findings_frame, self.monitor_findings.yview, self.colors)
		self.monitor_findings.configure(yscrollcommand=monitor_scroll.set)
		self.monitor_findings.pack(side="left", fill="both", expand=True)
		monitor_scroll.pack(side="right", fill="y")
		self.monitor_findings.bind("<Double-1>", lambda _event: self.show_page("alerts"))

	def _build_guide_tab(self) -> None:
		ttk.Label(self.guide_tab, text="Tier 1 shift workflow", style="Section.TLabel").pack(anchor="w")
		guide = tk.Text(self.guide_tab, wrap="word", font=("Segoe UI", 10), relief="flat", background=self.colors["panel"], foreground=self.colors["text"], insertbackground=self.colors["accent"], selectbackground=self.colors["selection"], padx=16, pady=14)
		guide.pack(fill="both", expand=True, pady=(10, 12))
		guide.insert("1.0", """PURPOSE AND LIMITS
SOC Desk is a portfolio and training workbench. It does not connect to a SIEM, EDR, ticketing system, identity provider, or threat-intelligence service. Import only alert exports your employer permits. A CSV import is a copy; it does not acknowledge or close the source alert.

KEY RESPONSIBILITIES
Monitor the queue assigned by your team; validate detections against source evidence; identify affected hosts, accounts, and timeframes; correlate relevant endpoint, network, and authentication activity; document findings and uncertainty; escalate suspected incidents using the playbook and SLA; and hand off concise next steps. Follow team procedures and keep the source SIEM/ticketing system authoritative.

REQUIRED ENTRY-LEVEL SKILLS
Basic Windows/Linux event-log familiarity; TCP/IP, DNS, and common network-service fundamentals; navigation of SIEM/EDR alerts; authentication and identity concepts; careful evidence handling; clear written communication; structured troubleshooting; and sound judgement about when to escalate. Learn the organization's severity model, asset criticality, playbooks, and escalation contacts before taking independent action.

START OF SHIFT
1. Confirm your assigned queue, severity definitions, escalation contacts, SLAs, and approved evidence-handling process with your team.
2. Import an approved CSV export from the SIEM/EDR, or create a practice alert. Check that timestamps, source, host, user, and network indicators mapped correctly.
3. Sort urgent cases first, then review source context and asset/user criticality in your organization's authoritative tools.

LOCAL NETWORK OBSERVATIONS
The Local monitor tab performs scheduled TCP connection checks against an explicitly entered private IPv4 scope (up to 256 hosts, 16 chosen ports, no more often than every 5 minutes). The first completed scan establishes a baseline; later observations of responding hosts and selected ports can create review cases. The app must stay open and the computer/network must remain available. Each scan cycle writes a .logs report.

This is not packet capture: it cannot report every connection or brief traffic between scan cycles, and hosts that do not respond on selected TCP ports may be missed. It does not detect arbitrary network traffic, identify a connecting device from traffic alone, or confirm vulnerabilities/CVEs. FTP, Telnet, SMB, database, remote desktop, and VNC ports are heuristically flagged for review; context and authorization matter. A new-device notification is a lead to verify against approved asset inventory, not proof of malicious activity. The in-app popup is not an operating-system or 24/7 service notification.

TRIAGE EACH ALERT
1. Validate the alert and timeframe. Compare the detection with raw events and surrounding activity in the source platform.
2. Identify the affected host, user, source/destination IPs, detection source, and relevant evidence. Record concise observations and where evidence was verified.
3. Correlate with approved sources such as EDR process trees, authentication logs, DNS/proxy records, asset inventory, change records, and known maintenance windows.
4. Set a disposition only when supported by evidence. Keep uncertainty explicit; a suspicious-looking indicator alone is not proof of compromise.
5. Escalate suspected compromise, active impact, privileged-account activity, lateral movement, data access/exfiltration, or cases near an SLA using the team's playbook. Include what happened, when, affected assets/accounts, evidence, actions taken, and what remains unknown.
6. Close only when policy permits and the source system of record is updated. This local casebook does not close the original SIEM alert.

HANDOFF AND DATA HANDLING
Use notes to record timestamp/time zone, evidence source, key observations, decisions, outstanding questions, and the next owner/action. Keep notes factual and professional. Do not place secrets, credentials, unnecessary personal data, or restricted production telemetry in this local database unless your employer explicitly approves it. The SQLite database is not encrypted; follow retention, access-control, and incident-record policies. Exported case CSVs may contain sensitive information.

PORTFOLIO USE
For a CV/demo, use fabricated or sanitized alerts and clearly label them as synthetic. Describe the project accurately as a local CSV-based triage casebook with an audit history and bounded authorized TCP observations, not as a SIEM/SOAR, packet monitor, or vulnerability scanner. Never upload real employer data or run network checks without written authorization and an approved scope.""")
		guide.configure(state="disabled")

	def refresh_all(self) -> None:
		self._refresh_queue()
		self._refresh_dashboard()

	def _schedule_queue_refresh(self, *_args) -> None:
		self.queue_page = 0
		if self.refresh_job:
			self.root.after_cancel(self.refresh_job)
		self.refresh_job = self.root.after(180, self._refresh_queue)

	def _previous_queue_page(self) -> None:
		if self.queue_page > 0:
			self.queue_page -= 1
			self._refresh_queue()

	def _next_queue_page(self) -> None:
		if (self.queue_page + 1) * QUEUE_PAGE_SIZE < self.queue_total:
			self.queue_page += 1
			self._refresh_queue()

	def _set_status_filter(self, selected: list[str]) -> None:
		self.status_filter = selected
		self._schedule_queue_refresh()

	def _set_severity_filter(self, selected: list[str]) -> None:
		self.severity_filter = selected
		self._schedule_queue_refresh()

	def _set_scan_port_presets(self, selected: list[str]) -> None:
		if selected:
			ports = sorted({int(option.split(" ", 1)[0]) for option in selected})
			self.ports_var.set(",".join(map(str, ports)))

	def _set_monitor_port_presets(self, selected: list[str]) -> None:
		if selected:
			ports = sorted({int(option.split(" ", 1)[0]) for option in selected})
			self.monitor_ports_var.set(",".join(map(str, ports)))

	def _refresh_queue(self) -> None:
		self.refresh_job = None
		if not hasattr(self, "alert_queue"):
			return
		search = self.search_var.get()
		self.queue_total = self.store.count_alerts(search, self.status_filter, self.severity_filter)
		last_page = max(0, (self.queue_total - 1) // QUEUE_PAGE_SIZE)
		self.queue_page = min(self.queue_page, last_page)
		for item in self.alert_queue.get_children():
			self.alert_queue.delete(item)
		alerts = self.store.list_alerts(
			search,
			self.status_filter,
			self.severity_filter,
			limit=QUEUE_PAGE_SIZE,
			offset=self.queue_page * QUEUE_PAGE_SIZE,
		)
		for alert in alerts:
			self.alert_queue.insert(
				"", "end", iid=alert["case_id"],
				values=(alert["case_id"], alert["created_at"], alert["severity"], alert["status"],
					alert["title"], alert["hostname"] or "-", alert["source"]),
			)
		if self.selected_case_id in self.alert_queue.get_children():
			self.alert_queue.selection_set(self.selected_case_id)
		if self.queue_total:
			first = self.queue_page * QUEUE_PAGE_SIZE + 1
			last = min(first + QUEUE_PAGE_SIZE - 1, self.queue_total)
			pages = last_page + 1
			self.queue_page_var.set(f"{first}-{last} of {self.queue_total} | Page {self.queue_page + 1}/{pages}")
		else:
			self.queue_page_var.set("0 cases")
		self.queue_previous_button.configure(state="normal" if self.queue_page > 0 else "disabled")
		self.queue_next_button.configure(
			state="normal" if (self.queue_page + 1) * QUEUE_PAGE_SIZE < self.queue_total else "disabled"
		)

	def _refresh_dashboard(self) -> None:
		open_count, urgent_count, escalated_count, closed_count = self.store.dashboard_summary()
		self.metric_vars["open"].set(str(open_count))
		self.metric_vars["urgent"].set(str(urgent_count))
		self.metric_vars["escalated"].set(str(escalated_count))
		self.metric_vars["closed"].set(str(closed_count))
		for item in self.dashboard_queue.get_children():
			self.dashboard_queue.delete(item)
		for alert in self.store.dashboard_alerts(limit=8):
			self.dashboard_queue.insert("", "end", iid=alert["case_id"], values=(
				alert["severity"], alert["title"], alert["hostname"] or "-", alert["status"], alert["case_id"]
			))

	def _select_alert(self, _event=None) -> None:
		selection = self.alert_queue.selection()
		if not selection:
			return
		self.selected_case_id = selection[0]
		alert = self.store.get_alert(self.selected_case_id)
		if not alert:
			return
		self.alert_context.set(
			f"{alert['title']} | {alert['severity']} | {alert['source']} | Detected {alert['created_at']}\n"
			f"Host: {alert['hostname'] or '-'} | User: {alert['username'] or '-'} | "
			f"Source IP: {alert['source_ip'] or '-'} | Destination IP: {alert['destination_ip'] or '-'}\n"
			f"Details: {alert['description'] or 'No description supplied'} | Source event ID: {alert['source_event_id'] or '-'}"
		)
		self.case_status.set(alert["status"])
		self.case_status_dropdown.set_values([alert["status"]])
		self.case_disposition.set(alert["disposition"])
		self.case_disposition_dropdown.set_values([alert["disposition"]])
		self.notes_text.delete("1.0", "end")
		self.notes_text.insert("1.0", alert["notes"])
		history = self.store.get_history(self.selected_case_id)
		self.history_var.set("History: " + " | ".join(
			f"{entry['at']} {entry['action']}: {entry['detail']}" for entry in history[-4:]
		))

	def _open_selected_dashboard_case(self, _event=None) -> None:
		selection = self.dashboard_queue.selection()
		if selection:
			self.show_page("alerts")
			self._refresh_queue()
			if selection[0] in self.alert_queue.get_children():
				self.alert_queue.selection_set(selection[0])
				self.alert_queue.see(selection[0])
				self._select_alert()

	def import_alerts(self) -> None:
		if self.csv_worker and self.csv_worker.is_alive():
			return
		path = filedialog.askopenfilename(
			parent=self.root, title="Import approved alert CSV", filetypes=(("CSV files", "*.csv"), ("All files", "*.*"))
		)
		if not path:
			return
		self._start_csv_operation("import", path)

	def load_demo_alerts(self) -> None:
		try:
			added, skipped = self.store.add_demo_alerts()
		except (OSError, sqlite3.Error) as exc:
			messagebox.showerror("Could not load demo cases", str(exc), parent=self.root)
			return
		self.queue_page = 0
		self.refresh_all()
		self._show_toast("Synthetic demo data", f"Added {added} case(s); skipped {skipped} already loaded.")

	def export_alerts(self) -> None:
		if self.csv_worker and self.csv_worker.is_alive():
			return
		path = filedialog.asksaveasfilename(
			parent=self.root, title="Export triage cases", defaultextension=".csv",
			initialfile="soc_triage_cases.csv", filetypes=(("CSV files", "*.csv"),),
		)
		if not path:
			return
		self._start_csv_operation("export", path)

	def _start_csv_operation(self, operation: str, path: str) -> None:
		self.import_button.configure(state="disabled")
		self.export_button.configure(state="disabled")
		self.csv_busy = True
		self._set_busy_cursor(True, "csv")
		self.csv_worker = threading.Thread(
			target=self._run_csv_operation,
			args=(operation, path),
			name=f"csv-{operation}",
			daemon=True,
		)
		self.csv_worker.start()

	def _run_csv_operation(self, operation: str, path: str) -> None:
		try:
			result = self.store.import_csv(path) if operation == "import" else self.store.export_csv(path)
			error = None
		except (OSError, UnicodeError, ValueError, csv.Error, sqlite3.Error) as exc:
			result = None
			error = str(exc)
		self.events.put(("csv_io_done", operation, result, error))

	def new_alert(self) -> None:
		dialog = tk.Toplevel(self.root)
		dialog.title("Create practice alert")
		dialog.transient(self.root)
		dialog.grab_set()
		dialog.geometry("540x560")
		frame = ttk.Frame(dialog, padding=20)
		frame.pack(fill="both", expand=True)
		fields = {}
		for row, (key, label) in enumerate((("title", "Alert title *"), ("source", "Detection source"), ("source_event_id", "Source event ID"), ("hostname", "Host"), ("username", "User"), ("source_ip", "Source IP"), ("destination_ip", "Destination IP"))):
			ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=4)
			entry = self._entry(frame, width=48)
			entry.grid(row=row, column=1, sticky="ew", pady=4)
			fields[key] = entry
		severity_row = len(fields)
		ttk.Label(frame, text="Severity").grid(row=severity_row, column=0, sticky="w", pady=4)
		severity = tk.StringVar(value="Medium")
		severity_dropdown = AnimatedDropdown(
			frame, "Severity", SEVERITIES[:-1], ["Medium"], self.colors,
			lambda selected: severity.set(selected[0]),
		)
		severity_dropdown.grid(row=severity_row, column=1, sticky="ew", pady=4)
		ttk.Label(frame, text="Event details").grid(row=severity_row + 1, column=0, sticky="nw", pady=4)
		description = tk.Text(frame, height=5, wrap="word", font=("Segoe UI", 10), background=self.colors["panel"], foreground=self.colors["text"], insertbackground=self.colors["accent"], selectbackground=self.colors["selection"])
		description.grid(row=severity_row + 1, column=1, sticky="ew", pady=4)
		frame.columnconfigure(1, weight=1)

		def save() -> None:
			values = {key: entry.get() for key, entry in fields.items()}
			values["severity"] = severity.get()
			values["description"] = description.get("1.0", "end").strip()
			try:
				self.store.add_alert(values)
			except (ValueError, sqlite3.IntegrityError) as exc:
				messagebox.showerror("Could not create alert", str(exc), parent=dialog)
				return
			self.refresh_all()
			dialog.destroy()

		create_button = self._button(frame, "Create case", save, accent=True)
		create_button.grid(row=severity_row + 2, column=1, sticky="e", pady=(12, 0))
		fields["title"].focus_set()

	def save_triage(self) -> None:
		if not self.selected_case_id:
			messagebox.showinfo("Select a case", "Choose an alert from the queue first.", parent=self.root)
			return
		try:
			self.store.update_triage(
				self.selected_case_id,
				self.case_status.get(),
				self.case_disposition.get(),
				self.notes_text.get("1.0", "end").strip(),
			)
		except ValueError as exc:
			messagebox.showerror("Could not save triage", str(exc), parent=self.root)
			return
		case_id = self.selected_case_id
		self.refresh_all()
		if case_id in self.alert_queue.get_children():
			self.alert_queue.selection_set(case_id)
			self._select_alert()

	def open_data_folder(self) -> None:
		folder = get_data_directory()
		folder.mkdir(parents=True, exist_ok=True)
		try:
			if os.name == "nt":
				os.startfile(folder)
			elif platform.system() == "Darwin":
				subprocess.Popen(["open", str(folder)])
			else:
				subprocess.Popen(["xdg-open", str(folder)])
		except (OSError, AttributeError) as exc:
			messagebox.showerror("Could not open data folder", str(exc), parent=self.root)

	def _update_cursor(self, event) -> None:
		widget = event.widget
		if self.cursor_busy:
			cursor = "watch"
		elif isinstance(widget, (AnimatedButton, SmoothScrollbar, ttk.Treeview)) and getattr(widget, "_enabled", True):
			cursor = "hand2"
		elif widget.winfo_class() in ("TEntry", "Entry", "Text"):
			cursor = "xterm"
		else:
			cursor = "arrow"
		try:
			if widget.cget("cursor") != cursor:
				widget.configure(cursor=cursor)
		except tk.TclError:
			pass

	def _set_busy_cursor(self, busy: bool, source: str = "scan") -> None:
		if source == "monitor":
			self.monitor_cycle_busy = busy
		elif source == "csv":
			self.csv_busy = busy
		else:
			self.scan_busy = busy
		self.cursor_busy = self.scan_busy or self.monitor_cycle_busy or self.csv_busy
		cursor = "watch" if self.cursor_busy else "arrow"
		for widget in (self.root, self.results, self.dashboard_queue, self.alert_queue, self.monitor_findings):
			try:
				widget.configure(cursor=cursor)
			except tk.TclError:
				pass

	def _play_alert_sound(self) -> None:
		if not self.sound_enabled.get():
			return
		if os.name == "nt":
			try:
				import winsound
			except ImportError:
				self.root.bell()
				return
			def play_tone() -> None:
				try:
					winsound.Beep(784, 75)
					winsound.Beep(1046, 105)
				except (OSError, RuntimeError):
					pass
			threading.Thread(target=play_tone, name="alert-tone", daemon=True).start()
		else:
			self.root.bell()

	def start_monitor(self) -> None:
		if self.monitor_worker and self.monitor_worker.is_alive():
			return
		try:
			scope, addresses = resolve_monitor_scope(self.monitor_scope_var.get())
			ports, interval = validate_monitor_settings(
				self.monitor_ports_var.get(), self.monitor_interval_var.get()
			)
		except ScanInputError as exc:
			messagebox.showerror("Check monitor settings", str(exc), parent=self.root)
			return
		if not messagebox.askyesno(
			"Confirm authorized scope",
			f"Start scheduled TCP checks against {scope}? Only continue if you own or are explicitly authorized to monitor this network.",
			parent=self.root,
		):
			return
		self.monitor_stop_event = threading.Event()
		self.monitor_start_button.configure(state="disabled")
		self.monitor_stop_button.configure(state="normal")
		self.monitor_status_var.set(f"Starting | {scope} | {len(addresses)} host(s), {len(ports)} ports, every {interval} seconds.")
		self.monitor_worker = threading.Thread(
			target=run_monitor,
			args=(scope, addresses, ports, interval, self.monitor_stop_event, self.events),
			name="scheduled-network-monitor",
			daemon=True,
		)
		self.monitor_worker.start()

	def stop_monitor(self) -> None:
		self.monitor_stop_event.set()
		self.monitor_stop_button.configure(state="disabled")
		self.monitor_status_var.set("Stopping after the current connection check...")

	def _show_toast(self, title: str, detail: str) -> None:
		toast = tk.Toplevel(self.root)
		toast.overrideredirect(True)
		toast.configure(background=self.colors["panel"], highlightthickness=1, highlightbackground=self.colors["accent"])
		label = tk.Label(
			toast,
			text=f"{title}\n{detail}",
			justify="left",
			anchor="w",
			wraplength=340,
			padx=16,
			pady=12,
			background=self.colors["panel"],
			foreground=self.colors["text"],
			font=("Segoe UI", 10),
		)
		label.pack(fill="both")
		self.root.update_idletasks()
		label.update_idletasks()
		x = self.root.winfo_rootx() + self.root.winfo_width() - 390
		y = self.root.winfo_rooty() + 28
		height = max(78, min(190, label.winfo_reqheight() + 4))
		toast.geometry(f"370x{height}+{max(0, x)}+{max(0, y)}")
		toast.attributes("-topmost", True)
		try:
			toast.attributes("-alpha", 0.0)
		except tk.TclError:
			toast.after(4500, toast.destroy)
			return
		self._animate_opacity(
			toast,
			start=0.0,
			end=0.97,
			duration=0.18,
			on_complete=lambda: toast.after(
				3200,
				lambda: self._animate_opacity(toast, 0.97, 0.0, 0.2, toast.destroy),
			),
		)

	def _animate_opacity(
		self,
		window: tk.Toplevel,
		start: float,
		end: float,
		duration: float,
		on_complete: Callable[[], None] | None = None,
	) -> None:
		started = time.perf_counter()

		def frame() -> None:
			if not window.winfo_exists():
				return
			progress = min(1.0, (time.perf_counter() - started) / duration)
			eased = progress * progress * (3 - 2 * progress)
			opacity = start + (end - start) * eased
			try:
				window.attributes("-alpha", opacity)
			except tk.TclError:
				window.destroy()
				return
			if progress < 1.0:
				window.after(16, frame)
			elif on_complete:
				on_complete()

		frame()

	def start_scan(self) -> None:
		if self.worker and self.worker.is_alive():
			return
		try:
			target, addresses = resolve_targets(self.target_var.get())
			ports = parse_ports(self.ports_var.get())
		except ScanInputError as exc:
			messagebox.showerror("Check scan inputs", str(exc), parent=self.root)
			return

		self.cancellation = threading.Event()
		self._set_busy_cursor(True, "scan")
		self.progress.configure(maximum=max(1, len(addresses) * len(ports)), value=0)
		self.status_var.set(f"Scanning {len(addresses)} host(s) across {len(ports)} port(s)...")
		self.scan_button.configure(state="disabled")
		self.stop_button.configure(state="normal")
		for item in self.results.get_children():
			self.results.delete(item)

		self.worker = threading.Thread(
			target=run_scan,
			args=(target, addresses, ports, self.cancellation, self.events),
			name="network-scan",
			daemon=False,
		)
		self.worker.start()

	def stop_scan(self) -> None:
		self.cancellation.set()
		self.stop_button.configure(state="disabled")
		self.status_var.set("Stopping after active connection checks finish...")

	def _process_events(self) -> None:
		try:
			while True:
				event = self.events.get_nowait()
				if event[0] == "progress":
					_, completed, total = event
					self.progress.configure(maximum=max(1, total), value=completed)
				elif event[0] == "csv_io_done":
					_, operation, result, error = event
					self.csv_worker = None
					self.csv_busy = False
					self._set_busy_cursor(False, "csv")
					self.import_button.configure(state="normal")
					self.export_button.configure(state="normal")
					if error:
						messagebox.showerror(f"{operation.title()} failed", error, parent=self.root)
					elif operation == "import":
						added, skipped = result
						self.queue_page = 0
						self.refresh_all()
						self._show_toast("Import complete", f"Added {added} alert(s); skipped {skipped} empty or duplicate row(s).")
					else:
						self._show_toast("Export complete", f"Exported {result} case(s). Handle the file under your organization's data policy.")
				elif event[0] == "monitor_cycle":
					self._set_busy_cursor(False, "monitor")
					_, status, baseline, host_count, new_hosts, new_services, case_ids, log_path, error = event
					log_note = f" | Log: {log_path}" if log_path else " | Log unavailable"
					if status == "Completed":
						prefix = "Baseline recorded" if baseline else "Monitor cycle complete"
						self.monitor_status_var.set(
							f"{prefix} | {host_count} device(s) observed via TCP/cache | {len(case_ids)} review case(s) | Next check in {self.monitor_interval_var.get()}s{log_note}"
						)
					else:
						self.monitor_status_var.set(f"Monitor cycle {status.lower()}: {error or 'no additional detail.'}{log_note}")
					for case_id in case_ids:
						alert = self.store.get_alert(case_id)
						if alert:
							self.monitor_findings.insert(
								"", "end", iid=case_id, values=(alert["created_at"], alert["title"], alert["hostname"], alert["severity"], case_id)
							)
					self.refresh_all()
					flagged = [(host, port) for host, port in new_services if port in FLAGGED_PORTS]
					notices = []
					if not baseline and new_hosts:
						notices.append(f"New device: {', '.join(new_hosts[:4])}")
					if flagged:
						host, port = flagged[0]
						service = FLAGGED_PORTS[port][0]
						notices.append(f"Review {service} on {host}:{port}")
					if notices:
						notices.append("Review the alert queue; these are leads, not proof of a vulnerability.")
						self._show_toast("Monitor review items", "\n".join(notices))
						self._play_alert_sound()
				elif event[0] == "monitor_cycle_started":
					self._set_busy_cursor(True, "monitor")
				elif event[0] == "monitor_stopped":
					self._set_busy_cursor(False, "monitor")
					self.monitor_start_button.configure(state="normal")
					self.monitor_stop_button.configure(state="disabled")
					self.monitor_status_var.set("Stopped | Existing observations and review cases are retained.")
				elif event[0] == "monitor_failed":
					self._set_busy_cursor(False, "monitor")
					self.monitor_status_var.set(f"Monitor stopped: {event[1]}")
					messagebox.showerror("Monitor could not start", event[1], parent=self.root)
				elif event[0] == "scan_done":
					self._set_busy_cursor(False, "scan")
					_, status, open_services, log_path, error = event
					for host, port in sorted(
						open_services,
						key=lambda result: (ipaddress.IPv4Address(result[0]), result[1]),
					):
						self.results.insert(
							"",
							"end",
							values=(host, port, SERVICE_NAMES.get(port, "Unknown"), "Responded"),
						)
					self.progress.configure(value=self.progress.cget("maximum"))
					if log_path:
						self.status_var.set(f"{status} | {len(open_services)} open service(s) | Log: {log_path}")
					else:
						self.status_var.set(f"{status} | .logs file could not be created")
					self.scan_button.configure(state="normal")
					self.stop_button.configure(state="disabled")
					if error:
						messagebox.showwarning("Scan finished with a note", error, parent=self.root)
					elif not open_services:
						messagebox.showinfo(
							"Scan finished",
							"No selected TCP ports responded. Filtered, closed, and unavailable hosts are not distinguished.",
							parent=self.root,
						)
		except queue.Empty:
			pass
		self.root.after(100, self._process_events)

	def open_log_folder(self) -> None:
		folder = get_log_directory()
		folder.mkdir(parents=True, exist_ok=True)
		try:
			if os.name == "nt":
				os.startfile(folder)
			elif platform.system() == "Darwin":
				subprocess.Popen(["open", str(folder)])
			else:
				subprocess.Popen(["xdg-open", str(folder)])
		except (OSError, AttributeError) as exc:
			messagebox.showerror("Could not open logs folder", str(exc), parent=self.root)

	def close(self) -> None:
		self.cancellation.set()
		self.monitor_stop_event.set()
		self.root.destroy()


def main() -> None:
	root = tk.Tk()
	NetTier1App(root)
	root.mainloop()


if __name__ == "__main__":
	main()
