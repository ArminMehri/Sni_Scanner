import sys
import asyncio
import socket
import ssl
import re
import csv
import ipaddress
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from PyQt5 import QtWidgets, QtCore
from aiohttp import ClientSession, ClientTimeout


APP_TITLE = "SNI CHECKER • HTTP Alive Scanner"
USER_AGENT = "SNI-Checker-ArminMehri/3.0"
DEFAULT_PORT = 443


# ===============================
#   INPUT / PARSE HELPERS
# ===============================
def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except Exception:
        return False


def clean_host(value: str) -> str:
    value = value.strip().lower()
    value = value.replace("https://", "").replace("http://", "")
    value = value.split("/", 1)[0]
    value = value.split(":", 1)[0] if not is_ip(value) else value
    return value.strip()


@dataclass(frozen=True)
class Target:
    raw: str
    sni: str
    connect_ip: Optional[str] = None
    port: int = DEFAULT_PORT

    @property
    def display(self) -> str:
        if self.connect_ip and self.connect_ip != self.sni:
            return f"{self.sni} -> {self.connect_ip}"
        return self.sni


def parse_target_line(line: str) -> Optional[Target]:
    """
    Supported domains.txt formats:
        example.com
        1.1.1.1
        example.com 1.1.1.1
        example.com,1.1.1.1
        example.com | 1.1.1.1
        example.com:443 1.1.1.1
    """
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return None

    normalized = raw.replace(",", " ").replace("|", " ").replace("\t", " ")
    parts = [p.strip() for p in normalized.split() if p.strip()]

    sni = None
    forced_ip = None
    port = DEFAULT_PORT

    for part in parts:
        part = part.strip()
        host_part = clean_host(part)

        # Optional port on first host-like token: example.com:8443
        if ":" in part and not is_ip(part):
            before_port, after_port = part.rsplit(":", 1)
            if after_port.isdigit():
                port = int(after_port)
                host_part = clean_host(before_port)

        if is_ip(host_part):
            forced_ip = host_part
        elif "." in host_part:
            sni = host_part

    if sni is None and forced_ip:
        sni = forced_ip

    if not sni:
        return None

    return Target(raw=raw, sni=sni, connect_ip=forced_ip, port=port)


# ===============================
#   HTTP / CDN HELPERS
# ===============================
def parse_http_response(data: bytes) -> Tuple[Optional[int], Dict[str, str]]:
    try:
        text = data.decode("iso-8859-1", errors="ignore")
        head = text.split("\r\n\r\n", 1)[0]
        first_line = head.split("\r\n", 1)[0]
        match = re.search(r"HTTP/\d(?:\.\d)?\s+(\d+)", first_line)
        status = int(match.group(1)) if match else None

        headers: Dict[str, str] = {}
        for line in head.split("\r\n")[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()

        return status, headers
    except Exception:
        return None, {}


def status_is_ok(status: Optional[int]) -> bool:
    # 1xx/2xx/3xx are considered alive. 401/403 means the website is alive too,
    # but for your current table style we keep HTTP OK stricter: under 400.
    return status is not None and 100 <= status < 400


def detect_cdn(headers: Dict[str, str], rdns: str = "") -> str:
    haystack = " ".join([
        headers.get("server", ""),
        headers.get("via", ""),
        headers.get("x-cache", ""),
        headers.get("x-served-by", ""),
        headers.get("x-cache-hits", ""),
        headers.get("cf-ray", ""),
        headers.get("cf-cache-status", ""),
        headers.get("x-amz-cf-pop", ""),
        headers.get("x-amz-cf-id", ""),
        headers.get("x-vercel-id", ""),
        headers.get("x-nf-request-id", ""),
        headers.get("x-github-request-id", ""),
        rdns or "",
    ]).lower()

    cdn_checks = [
        ("Cloudflare", ["cloudflare", "cf-ray", "cf-cache-status"]),
        ("Amazon CloudFront", ["cloudfront", "x-amz-cf", "cloudfront.net"]),
        ("Fastly", ["fastly", "x-served-by", "fastly.net"]),
        ("Akamai", ["akamai", "edgesuite", "edgekey", "akamaiedge"]),
        ("Google", ["google", "ghs", "googleusercontent", "1e100.net"]),
        ("Netlify", ["netlify", "x-nf-request-id"]),
        ("Vercel", ["vercel", "x-vercel-id"]),
        ("GitHub Pages", ["github", "github.io", "x-github-request-id"]),
        ("BunnyCDN", ["bunny", "bunnycdn"]),
        ("Azure/Microsoft", ["azure", "microsoft", "azurefd", "trafficmanager"]),
        ("ArvanCloud", ["arvan", "arvancloud"]),
        ("DerakCloud", ["derak"]),
        ("Imperva/Incapsula", ["imperva", "incapsula"]),
        ("Cloudflare Pages", ["pages.dev"]),
    ]

    for cdn_name, needles in cdn_checks:
        if any(needle in haystack for needle in needles):
            return cdn_name

    server = headers.get("server", "").strip()
    if server:
        return server[:80]
    if rdns:
        return rdns[:80]
    return "-"


# ===============================
#   SCANNER THREAD (ASYNC)
# ===============================
class ScannerThread(QtCore.QThread):
    result_signal = QtCore.pyqtSignal(dict)
    stats_signal = QtCore.pyqtSignal(int, int, int)
    log_signal = QtCore.pyqtSignal(str)
    finished_signal = QtCore.pyqtSignal()

    def __init__(self, lines, concurrency, timeout, enable_asn=True):
        super().__init__()
        self.lines = lines
        self.concurrency = max(1, min(int(concurrency), 500))
        self.timeout = max(1, int(timeout))
        self.enable_asn = enable_asn
        self.running = True
        self.asn_cache: Dict[str, str] = {}

    def stop(self):
        self.running = False

    async def resolve_ip(self, target: Target) -> str:
        if target.connect_ip:
            return target.connect_ip
        if is_ip(target.sni):
            return target.sni

        loop = asyncio.get_running_loop()
        infos = await asyncio.wait_for(
            loop.getaddrinfo(target.sni, target.port, family=socket.AF_INET, type=socket.SOCK_STREAM),
            timeout=self.timeout,
        )
        if not infos:
            raise RuntimeError("No A record found")
        return infos[0][4][0]

    async def reverse_dns(self, ip: str) -> str:
        try:
            loop = asyncio.get_running_loop()
            host, _, _ = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyaddr, ip),
                timeout=2,
            )
            return host or ""
        except Exception:
            return ""

    async def get_asn(self, ip: str, session: ClientSession, asn_sem: asyncio.Semaphore) -> str:
        if not self.enable_asn:
            return ""
        if ip in self.asn_cache:
            return self.asn_cache[ip]

        async with asn_sem:
            if ip in self.asn_cache:
                return self.asn_cache[ip]

            try:
                async with session.get(f"https://api.bgpview.io/ip/{ip}") as response:
                    if response.status != 200:
                        self.asn_cache[ip] = ""
                        return ""

                    data = await response.json(content_type=None)
                    prefixes = (data.get("data") or {}).get("prefixes") or []
                    if prefixes:
                        asn_data = prefixes[0].get("asn") or {}
                        asn_num = asn_data.get("asn")
                        asn_name = asn_data.get("name") or asn_data.get("description") or ""
                        value = f"AS{asn_num} {asn_name}".strip() if asn_num else asn_name
                        self.asn_cache[ip] = value[:120]
                        return self.asn_cache[ip]
            except Exception:
                pass

        self.asn_cache[ip] = ""
        return ""

    async def tcp_connect(self, ip: str, port: int) -> bool:
        reader = writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout,
            )
            return True
        finally:
            if writer:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    async def https_request(self, target: Target, ip: str) -> Tuple[bool, Optional[int], Dict[str, str], str]:
        headers: Dict[str, str] = {}
        status = None
        writer = None

        if is_ip(target.sni):
            # IP-only mode cannot be hostname-verified. We still test TLS reachability.
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            server_hostname = None
            host_header = target.sni
        else:
            ssl_ctx = ssl.create_default_context()
            server_hostname = target.sni
            host_header = target.sni

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    ip,
                    target.port,
                    ssl=ssl_ctx,
                    server_hostname=server_hostname,
                ),
                timeout=self.timeout,
            )

            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {host_header}\r\n"
                f"User-Agent: {USER_AGENT}\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n\r\n"
            )
            writer.write(request.encode("ascii", errors="ignore"))
            await asyncio.wait_for(writer.drain(), timeout=self.timeout)
            data = await asyncio.wait_for(reader.read(16384), timeout=self.timeout)
            status, headers = parse_http_response(data)
            return True, status, headers, ""
        except ssl.SSLCertVerificationError as exc:
            return False, status, headers, f"TLS CERT: {str(exc).splitlines()[0][:80]}"
        except ssl.SSLError as exc:
            return False, status, headers, f"TLS: {str(exc).splitlines()[0][:80]}"
        except asyncio.TimeoutError:
            return False, status, headers, "HTTPS timeout"
        except ConnectionRefusedError:
            return False, status, headers, "HTTPS refused"
        except Exception as exc:
            return False, status, headers, f"HTTPS {type(exc).__name__}"
        finally:
            if writer:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    async def http_request(self, target: Target, ip: str) -> Tuple[Optional[int], Dict[str, str]]:
        headers: Dict[str, str] = {}
        writer = None
        host_header = target.sni
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 80),
                timeout=self.timeout,
            )
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {host_header}\r\n"
                f"User-Agent: {USER_AGENT}\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n\r\n"
            )
            writer.write(request.encode("ascii", errors="ignore"))
            await asyncio.wait_for(writer.drain(), timeout=self.timeout)
            data = await asyncio.wait_for(reader.read(16384), timeout=self.timeout)
            status, headers = parse_http_response(data)
            return status, headers
        except Exception:
            return None, headers
        finally:
            if writer:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    async def check(self, line: str, sem: asyncio.Semaphore, session: ClientSession, asn_sem: asyncio.Semaphore) -> dict:
        async with sem:
            target = parse_target_line(line)

            result = {
                "domain": line.strip() or "-",
                "ip": "-",
                "tcp": "❌",
                "https": "❌",
                "ok": "❌",
                "cdn": "-",
                "status": "-",
                "error": "",
            }

            if not target:
                result["cdn"] = "ERR: invalid input"
                result["error"] = "invalid input"
                return result

            result["domain"] = target.display

            try:
                ip = await self.resolve_ip(target)
                result["ip"] = ip
            except Exception as exc:
                result["cdn"] = "ERR: DNS/resolve"
                result["error"] = f"resolve: {type(exc).__name__}"
                return result

            rdns_task = asyncio.create_task(self.reverse_dns(result["ip"]))

            try:
                if await self.tcp_connect(result["ip"], target.port):
                    result["tcp"] = "✅"
            except Exception as exc:
                result["error"] = f"tcp: {type(exc).__name__}"

            https_ok, https_status, https_headers, https_error = await self.https_request(target, result["ip"])
            rdns = await rdns_task

            if https_ok:
                result["https"] = "✅"
                result["status"] = str(https_status) if https_status else "TLS OK"
                if status_is_ok(https_status):
                    result["ok"] = "✅"
                result["cdn"] = detect_cdn(https_headers, rdns)
            else:
                http_status, http_headers = await self.http_request(target, result["ip"])
                result["status"] = str(http_status) if http_status else "-"
                if status_is_ok(http_status):
                    result["ok"] = "✅"
                    result["cdn"] = detect_cdn(http_headers, rdns)
                else:
                    detected = detect_cdn({}, rdns)
                    result["cdn"] = detected if detected != "-" else https_error or "-"
                    result["error"] = https_error

            asn = await self.get_asn(result["ip"], session, asn_sem)
            if asn:
                current = result["cdn"]
                result["cdn"] = f"{asn} | {current}" if current and current != "-" else asn

            return result

    async def run_scan(self):
        valid_lines = [line.strip() for line in self.lines if line.strip() and not line.strip().startswith("#")]
        total = len(valid_lines)
        done = 0
        alive = 0

        sem = asyncio.Semaphore(self.concurrency)
        asn_sem = asyncio.Semaphore(6)
        timeout = ClientTimeout(total=max(4, self.timeout))

        async with ClientSession(timeout=timeout) as session:
            tasks = [self.check(line, sem, session, asn_sem) for line in valid_lines]

            for coro in asyncio.as_completed(tasks):
                if not self.running:
                    break

                result = await coro
                done += 1
                if result["ok"] == "✅":
                    alive += 1

                self.result_signal.emit(result)
                self.stats_signal.emit(total, done, alive)

        self.finished_signal.emit()

    def run(self):
        try:
            asyncio.run(self.run_scan())
        except Exception as exc:
            self.log_signal.emit(f"Scanner crashed: {type(exc).__name__}: {exc}")
            self.finished_signal.emit()


# ===============================
#           MAIN UI
# ===============================
class Window(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle(APP_TITLE)
        self.resize(1120, 680)
        self.results = []
        self.thread = None

        self.layout = QtWidgets.QVBoxLayout()
        self.setLayout(self.layout)

        title = QtWidgets.QLabel(APP_TITLE)
        title.setStyleSheet("color:#00ff9c;font-size:18pt;font-weight:bold;")
        title.setAlignment(QtCore.Qt.AlignCenter)

        signature = QtWidgets.QLabel("|   By :  ArminMehri   |")
        signature.setStyleSheet("color:#00ff9c;font-size:9pt;")
        signature.setAlignment(QtCore.Qt.AlignCenter)

        self.layout.addWidget(title)
        self.layout.addWidget(signature)

        top = QtWidgets.QHBoxLayout()
        self.start_btn = QtWidgets.QPushButton("START")
        self.stop_btn = QtWidgets.QPushButton("STOP")
        self.export_btn = QtWidgets.QPushButton("EXPORT ALIVE")
        self.export_csv_btn = QtWidgets.QPushButton("EXPORT CSV")
        self.optimize_btn = QtWidgets.QPushButton("AUTO OPTIMIZE")

        top.addWidget(self.start_btn)
        top.addWidget(self.stop_btn)
        top.addWidget(self.export_btn)
        top.addWidget(self.export_csv_btn)
        top.addWidget(self.optimize_btn)
        self.layout.addLayout(top)

        form = QtWidgets.QHBoxLayout()
        self.file_input = QtWidgets.QLineEdit("domains.txt")
        self.conc_input = QtWidgets.QLineEdit("80")
        self.timeout_input = QtWidgets.QLineEdit("8")
        self.asn_checkbox = QtWidgets.QCheckBox("ASN Lookup")
        self.asn_checkbox.setChecked(True)

        form.addWidget(QtWidgets.QLabel("Domains File"))
        form.addWidget(self.file_input)
        form.addWidget(QtWidgets.QLabel("Concurrency"))
        form.addWidget(self.conc_input)
        form.addWidget(QtWidgets.QLabel("Timeout"))
        form.addWidget(self.timeout_input)
        form.addWidget(self.asn_checkbox)
        self.layout.addLayout(form)

        self.hint = QtWidgets.QLabel("Input: domain.com  |  1.1.1.1  |  domain.com 1.1.1.1  ← SNI + IP mode")
        self.hint.setStyleSheet("color:#7cffc9;font-size:9pt;")
        self.layout.addWidget(self.hint)

        self.stats = QtWidgets.QLabel("Total: 0 | Done: 0 | Alive: 0")
        self.stats.setStyleSheet("font-size:12pt;")
        self.layout.addWidget(self.stats)

        search_layout = QtWidgets.QHBoxLayout()
        search_label = QtWidgets.QLabel("🔍 Search:")
        self.search_box = QtWidgets.QLineEdit()
        self.search_box.setPlaceholderText("type domain, IP, status, ASN/CDN...")
        self.search_box.textChanged.connect(self.filter_table)
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_box)
        self.layout.addLayout(search_layout)

        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "Domain/SNI", "IP", "TCP", "HTTPS", "HTTP OK", "Status", "ASN/CDN"
        ])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSortingEnabled(True)
        self.layout.addWidget(self.table)

        self.start_btn.clicked.connect(self.start_scan)
        self.stop_btn.clicked.connect(self.stop_scan)
        self.export_btn.clicked.connect(self.export_results)
        self.export_csv_btn.clicked.connect(self.export_csv)
        self.optimize_btn.clicked.connect(self.auto_optimize)

    def filter_table(self, text):
        text = text.lower().strip()
        for row in range(self.table.rowCount()):
            match = not text
            for col in range(self.table.columnCount()):
                item = self.table.item(row, col)
                if item and text in item.text().lower():
                    match = True
                    break
            self.table.setRowHidden(row, not match)

    def set_running_ui(self, running: bool):
        self.start_btn.setEnabled(not running)
        self.optimize_btn.setEnabled(not running)
        self.stop_btn.setEnabled(running)

    def auto_optimize(self):
        file_name = self.file_input.text().strip()
        try:
            with open(file_name, encoding="utf-8") as file:
                lines = [line.strip() for line in file if line.strip()]
        except Exception:
            QtWidgets.QMessageBox.warning(self, "Error", "File not found!")
            return

        original_count = len(lines)
        optimized = []
        seen = set()

        for line in lines:
            target = parse_target_line(line)
            if not target:
                continue
            key = target.display.lower()
            if key in seen:
                continue
            seen.add(key)
            optimized.append(target.raw)

        with open(file_name, "w", encoding="utf-8") as file:
            for item in optimized:
                file.write(item + "\n")

        QtWidgets.QMessageBox.information(
            self,
            "Optimized ✔",
            f"Removed duplicates and invalid lines.\n\nBefore: {original_count}\nAfter:  {len(optimized)}",
        )

    def start_scan(self):
        file_name = self.file_input.text().strip()

        try:
            with open(file_name, encoding="utf-8") as file:
                lines = [line.strip() for line in file if line.strip()]
        except Exception:
            QtWidgets.QMessageBox.warning(self, "Error", "File not found!")
            return

        try:
            concurrency = int(self.conc_input.text().strip())
            timeout = int(self.timeout_input.text().strip())
        except ValueError:
            QtWidgets.QMessageBox.warning(self, "Error", "Concurrency and timeout must be numbers!")
            return

        if concurrency > 500:
            concurrency = 500
            self.conc_input.setText("500")

        self.results.clear()
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self.stats.setText("Total: 0 | Done: 0 | Alive: 0")

        self.thread = ScannerThread(
            lines=lines,
            concurrency=concurrency,
            timeout=timeout,
            enable_asn=self.asn_checkbox.isChecked(),
        )
        self.thread.result_signal.connect(self.add_result)
        self.thread.stats_signal.connect(self.update_stats)
        self.thread.log_signal.connect(self.show_log)
        self.thread.finished_signal.connect(self.scan_finished)

        self.set_running_ui(True)
        self.thread.start()

    def stop_scan(self):
        if self.thread:
            self.thread.stop()
            self.stats.setText(self.stats.text() + " | Stopping...")

    def add_result(self, result):
        row = self.table.rowCount()
        self.table.insertRow(row)

        values = [
            result.get("domain", "-"),
            result.get("ip", "-"),
            result.get("tcp", "❌"),
            result.get("https", "❌"),
            result.get("ok", "❌"),
            result.get("status", "-"),
            result.get("cdn", "-"),
        ]

        for col, value in enumerate(values):
            item = QtWidgets.QTableWidgetItem(str(value))
            item.setTextAlignment(QtCore.Qt.AlignCenter if col in [2, 3, 4, 5] else QtCore.Qt.AlignVCenter)
            if value == "✅":
                item.setForeground(QtCore.Qt.green)
            elif value == "❌":
                item.setForeground(QtCore.Qt.red)
            self.table.setItem(row, col, item)

        self.results.append(result)

    def update_stats(self, total, done, alive):
        self.stats.setText(f"Total: {total} | Done: {done} | Alive: {alive}")

    def show_log(self, message):
        QtWidgets.QMessageBox.warning(self, "Scanner Log", message)

    def scan_finished(self):
        self.set_running_ui(False)
        self.table.setSortingEnabled(True)

    def export_results(self):
        try:
            with open("alive.txt", "w", encoding="utf-8") as file:
                for result in self.results:
                    if result.get("ok") == "✅":
                        file.write(
                            f'{result.get("domain", "-")} {result.get("ip", "-")} '
                            f'{result.get("status", "-")} {result.get("cdn", "-")}\n'
                        )
            QtWidgets.QMessageBox.information(self, "Saved", "Exported to alive.txt")
        except Exception as exc:
            QtWidgets.QMessageBox.warning(self, "Error", f"Export failed: {exc}")

    def export_csv(self):
        try:
            with open("results.csv", "w", encoding="utf-8-sig", newline="") as file:
                writer = csv.writer(file)
                writer.writerow(["Domain/SNI", "IP", "TCP", "HTTPS", "HTTP OK", "Status", "ASN/CDN", "Error"])
                for result in self.results:
                    writer.writerow([
                        result.get("domain", "-"),
                        result.get("ip", "-"),
                        result.get("tcp", "❌"),
                        result.get("https", "❌"),
                        result.get("ok", "❌"),
                        result.get("status", "-"),
                        result.get("cdn", "-"),
                        result.get("error", ""),
                    ])
            QtWidgets.QMessageBox.information(self, "Saved", "Exported to results.csv")
        except Exception as exc:
            QtWidgets.QMessageBox.warning(self, "Error", f"CSV export failed: {exc}")


# ===============================
#   DARK STYLE
# ===============================
dark_style = """
QWidget {
    background-color: #0f0f0f;
    color: #00ff9c;
    font-family: Consolas;
    font-size: 11pt;
}

QLineEdit, QTableWidget {
    background-color: #151515;
    border: 1px solid #00ff9c;
    selection-background-color: #00ff9c;
    selection-color: #000000;
}

QCheckBox {
    color: #00ff9c;
}

QPushButton {
    background-color: #00ff9c;
    color: #000000;
    border-radius: 4px;
    padding: 6px;
    font-weight:bold;
}

QPushButton:hover {
    background-color: #00cc7a;
}

QPushButton:disabled {
    background-color: #235142;
    color: #9a9a9a;
}

QHeaderView::section {
    background-color: #151515;
    color: #00ff9c;
    border: 1px solid #00ff9c;
    padding: 5px;
}

QTableWidget::item:selected {
    background-color: #00ff9c;
    color: #000000;
}
"""


def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setStyleSheet(dark_style)
    window = Window()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
