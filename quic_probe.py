#!/usr/bin/env python3
"""
quic_probe.py — UDP/QUIC (Hysteria2) DPI probe
Part of dpi_check — https://github.com/...

Usage: quic_probe.py <host> <port> [sni] [--no-color]
Requires: pip install aioquic
"""

import asyncio
import socket
import ssl
import subprocess
import sys
import time
from datetime import datetime, timezone

try:
    from aioquic.asyncio import connect
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import HandshakeCompleted, ConnectionTerminated
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import HeadersReceived
except ImportError:
    print("Error: aioquic not installed. Run: pip install aioquic")
    sys.exit(1)


# ── Colors ────────────────────────────────────────────────────
class Colors:
    def __init__(self, enabled: bool = True):
        if enabled:
            self.R    = '\033[0;31m'
            self.G    = '\033[0;32m'
            self.Y    = '\033[1;33m'
            self.C    = '\033[0;36m'
            self.W    = '\033[1;37m'
            self.DIM  = '\033[2m'
            self.BOLD = '\033[1m'
            self.NC   = '\033[0m'
        else:
            self.R = self.G = self.Y = self.C = self.W = ''
            self.DIM = self.BOLD = self.NC = ''

    def pass_sym(self):   return f"{self.G}✓{self.NC}"
    def warn_sym(self):   return f"{self.Y}~{self.NC}"
    def fail_sym(self):   return f"{self.R}✗{self.NC}"
    def info_sym(self):   return f"{self.C}•{self.NC}"


# ── Scoring ───────────────────────────────────────────────────
class Score:
    def __init__(self):
        self.pts = 0
        self.max = 0

    def add(self, verdict: str):
        if verdict == 'pass':   self.pts += 2; self.max += 2
        elif verdict == 'warn': self.pts += 1; self.max += 2
        elif verdict == 'fail': self.max += 2

    def pct(self) -> int:
        return int(self.pts * 100 / self.max) if self.max else 0


# ── Row printer ───────────────────────────────────────────────
def print_row(c: Colors, sc: Score, num: int, label: str, detail: str, verdict: str):
    sym = {'pass': c.pass_sym(), 'warn': c.warn_sym(),
           'fail': c.fail_sym(), 'info': c.info_sym()}.get(verdict, c.info_sym())
    sc.add(verdict)
    detail = (detail[:34] + '…') if len(detail) > 35 else detail
    print(f"  {c.DIM}[{num:2d}]{c.NC}  {c.W}{label:<22}{c.NC}  {c.DIM}→{c.NC}  {detail:<36}  {sym}")


def div(c: Colors):
    print(f"  {c.DIM}{'─' * 63}{c.NC}")

def header(c: Colors, text: str):
    pad = '═' * (55 - len(text))
    print(f"\n{c.C}  ══ {text} {c.DIM}{pad}{c.NC}")
    print()


# ── QUIC protocol handler ─────────────────────────────────────
class ProbeProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.handshake_done = asyncio.Event()
        self.terminated     = asyncio.Event()
        self.term_reason    = None
        self.cert_info      = {}
        self.handshake_time = None
        self._t0            = time.monotonic()

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.handshake_time = time.monotonic() - self._t0
            self._extract_cert()
            self.handshake_done.set()
        elif isinstance(event, ConnectionTerminated):
            self.term_reason = f"code={event.error_code}"
            if event.reason_phrase:
                self.term_reason += f" ({event.reason_phrase})"
            self.terminated.set()
            self.handshake_done.set()

    def _extract_cert(self):
        try:
            raw = self._quic.tls._peer_certificate
            if not raw:
                return
            from cryptography import x509
            cert = x509.load_der_x509_certificate(raw)
            cn = cert.subject.get_attributes_for_oid(
                x509.NameOID.COMMON_NAME)
            issuer_o = cert.issuer.get_attributes_for_oid(
                x509.NameOID.ORGANIZATION_NAME)
            self.cert_info = {
                'cn':       cn[0].value if cn else '?',
                'issuer':   issuer_o[0].value if issuer_o else '?',
                'not_after': cert.not_valid_after_utc,
            }
        except Exception:
            pass


async def _connect(host: str, port: int, sni: str | None, timeout: int) -> ProbeProtocol | None:
    config = QuicConfiguration(
        is_client=True,
        verify_mode=ssl.CERT_NONE,
        alpn_protocols=["h3"],
        server_name=sni,
    )
    try:
        async with connect(host, port, configuration=config,
                           create_protocol=ProbeProtocol) as client:
            try:
                await asyncio.wait_for(client.handshake_done.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                return None   # timeout — server didn't respond
            return client
    except ConnectionRefusedError:
        return False   # port closed
    except Exception:
        return None


# ── Individual probes ─────────────────────────────────────────
async def probe_udp_reachability(c: Colors, sc: Score, host: str, port: int):
    """nmap UDP scan"""
    num = 1
    try:
        result = subprocess.run(
            ["nmap", "-sU", "-p", str(port), "--open", host],
            capture_output=True, text=True, timeout=30
        )
        line = next((l for l in result.stdout.splitlines()
                     if f"{port}/udp" in l), "")
        state = line.split()[1] if len(line.split()) >= 2 else "unknown"
        detail = f"{port}/udp {state}" if line else f"{port}/udp no response"
        verdict = "pass" if "open" in state else "warn"
        print_row(c, sc, num, "UDP port scan", detail, verdict)
    except Exception as e:
        print_row(c, sc, num, "UDP port scan", f"nmap error: {e}", "warn")


def probe_raw_udp(c: Colors, sc: Score, host: str, port: int):
    """Send junk bytes, check if server drops silently"""
    num = 2
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(b'\x00' * 32, (host, port))
        data, _ = sock.recvfrom(4096)
        detail = f"got {len(data)}B response: {data[:12].hex()}…"
        print_row(c, sc, num, "Raw UDP (junk)", detail, "fail")
    except socket.timeout:
        print_row(c, sc, num, "Raw UDP (junk)", "no response — server drops invalid QUIC", "pass")
    except Exception as e:
        print_row(c, sc, num, "Raw UDP (junk)", str(e), "warn")
    finally:
        sock.close()


async def probe_quic_handshake(c: Colors, sc: Score, host: str, port: int,
                                sni: str, timeout: int):
    """Full QUIC handshake with target SNI"""
    num = 3
    client = await _connect(host, port, sni, timeout)
    if client is None:
        print_row(c, sc, num, "QUIC handshake", f"timeout ({timeout}s) — no response", "fail")
        return
    if client is False:
        print_row(c, sc, num, "QUIC handshake", "connection refused (port closed)", "fail")
        return
    t = f"{client.handshake_time:.3f}s" if client.handshake_time else "?"
    if client.term_reason:
        if client.handshake_time:
            # TLS handshake completed, server closed after (no auth) — server is alive
            print_row(c, sc, num, "QUIC handshake", f"TLS ok in {t}, closed after (no auth)", "warn")
        else:
            # Terminated before TLS handshake finished
            print_row(c, sc, num, "QUIC handshake", f"terminated before TLS: {client.term_reason}", "fail")
        return
    print_row(c, sc, num, "QUIC handshake", f"success in {t}, ALPN=h3", "pass")


async def probe_certificate(c: Colors, sc: Score, host: str, port: int,
                             sni: str, timeout: int):
    """Extract and evaluate TLS cert from QUIC handshake"""
    num = 4
    client = await _connect(host, port, sni, timeout)
    if not client or client is False:
        print_row(c, sc, num, "TLS certificate", "could not connect", "fail")
        return
    # cert_info is populated from HandshakeCompleted even if server later terminates

    ci = client.cert_info
    if not ci:
        # Try: terminated connection might still have cert if handshake_time is set
        if client.handshake_time:
            print_row(c, sc, num, "TLS certificate", "handshake ok, cert not extractable (self-signed?)", "warn")
        else:
            print_row(c, sc, num, "TLS certificate", "no cert returned", "fail")
        return

    cn       = ci.get('cn', '?')
    issuer   = ci.get('issuer', '?')
    exp      = ci.get('not_after')
    days_left = (exp - datetime.now(timezone.utc)).days if exp else 0

    detail = f"CN={cn}, {issuer[:14]}, {days_left}d"
    # Legitimate CA?
    legit_cas = ('let', 'digicert', 'sectigo', 'globalsign', 'comodo', 'zerossl', 'google')
    if any(ca in issuer.lower() for ca in legit_cas):
        print_row(c, sc, num, "TLS certificate", detail, "pass")
    elif 'self' in issuer.lower() or issuer == cn:
        print_row(c, sc, num, "TLS certificate", f"{detail} (self-signed!)", "warn")
    else:
        print_row(c, sc, num, "TLS certificate", detail, "warn")


async def probe_mismatched_sni(c: Colors, sc: Score, host: str, port: int, timeout: int):
    """QUIC handshake with foreign SNI (google.com)"""
    num = 5
    client = await _connect(host, port, "google.com", timeout)
    if client is None:
        print_row(c, sc, num, "Mismatched SNI", "timeout — server ignores foreign SNI", "pass")
    elif client is False:
        print_row(c, sc, num, "Mismatched SNI", "connection refused", "warn")
    elif client and client.term_reason:
        t = f"{client.handshake_time:.3f}s" if client.handshake_time else "?"
        print_row(c, sc, num, "Mismatched SNI", f"reset in {t}: {client.term_reason}", "warn")
    elif client:
        t = f"{client.handshake_time:.3f}s" if client.handshake_time else "?"
        print_row(c, sc, num, "Mismatched SNI",
                  f"handshake ok in {t} (accepts any SNI)", "warn")
    else:
        print_row(c, sc, num, "Mismatched SNI", "no response", "warn")


async def probe_no_sni(c: Colors, sc: Score, host: str, port: int, timeout: int):
    """QUIC handshake without SNI"""
    num = 6
    client = await _connect(host, port, None, timeout)
    if client is None:
        print_row(c, sc, num, "No SNI probe", "timeout — server requires SNI", "pass")
    elif client is False:
        print_row(c, sc, num, "No SNI probe", "connection refused", "warn")
    elif client and client.term_reason:
        print_row(c, sc, num, "No SNI probe", f"reset: {client.term_reason}", "pass")
    elif client:
        t = f"{client.handshake_time:.3f}s" if client.handshake_time else "?"
        print_row(c, sc, num, "No SNI probe", f"handshake ok in {t} (no SNI needed)", "warn")
    else:
        print_row(c, sc, num, "No SNI probe", "no response", "warn")


async def probe_http3(c: Colors, sc: Score, host: str, port: int,
                      sni: str, timeout: int):
    """HTTP/3 GET / over QUIC"""
    num = 7
    config = QuicConfiguration(
        is_client=True, verify_mode=ssl.CERT_NONE,
        alpn_protocols=["h3"], server_name=sni,
    )
    status = None
    try:
        async with connect(host, port, configuration=config,
                           create_protocol=ProbeProtocol) as client:
            await asyncio.wait_for(client.handshake_done.wait(), timeout=timeout)
            if client.term_reason:
                print_row(c, sc, num, "HTTP/3 fallback",
                          f"terminated before H3: {client.term_reason}", "info")
                return
            h3 = H3Connection(client._quic)
            sid = client._quic.get_next_available_stream_id()
            h3.send_headers(sid, [
                (b":method", b"GET"), (b":scheme", b"https"),
                (b":authority", sni.encode()), (b":path", b"/"),
                (b"user-agent", b"Mozilla/5.0"),
            ])
            client._quic.send_stream_data(sid, b"", end_stream=True)
            client.transmit()
            deadline = asyncio.get_event_loop().time() + timeout
            while asyncio.get_event_loop().time() < deadline:
                for ev in h3.handle_event(None):
                    if isinstance(ev, HeadersReceived):
                        for name, val in ev.headers:
                            if name == b":status":
                                status = val.decode()
                await asyncio.sleep(0.1)
                if status:
                    break
    except asyncio.TimeoutError:
        pass
    except Exception:
        pass

    if status:
        print_row(c, sc, num, "HTTP/3 fallback", f"HTTP/3 {status}", "pass")
    else:
        print_row(c, sc, num, "HTTP/3 fallback",
                  "no H3 response (normal — H2 auth layer)", "info")


async def probe_port_hopping(c: Colors, sc: Score, host: str, timeout: int):
    """Spot-check a few ports in common hopping range"""
    num = 8
    test_ports = [20000, 30000, 40000, 49999]
    open_count = 0
    for p in test_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        try:
            sock.sendto(b'\x00' * 16, (host, p))
            sock.recvfrom(256)
            open_count += 1
        except socket.timeout:
            open_count += 1   # silence = open|filtered (normal)
        except Exception:
            pass
        finally:
            sock.close()
    detail = f"spot-check ports {test_ports[0]},{test_ports[-1]} (UDP)"
    print_row(c, sc, num, "Port hopping range", detail, "info")


# ── Summary ───────────────────────────────────────────────────
def print_summary(c: Colors, sc: Score):
    pct   = sc.pct()
    bar   = '█' * (pct * 24 // 100) + '░' * (24 - pct * 24 // 100)
    if pct >= 90:  grade = f"{c.G}{c.BOLD}EXCELLENT{c.NC}"; label = "passes DPI inspection"
    elif pct >= 75: grade = f"{c.G}GOOD{c.NC}";             label = "minor fingerprint risks"
    elif pct >= 55: grade = f"{c.Y}AVERAGE{c.NC}";          label = "several issues detected"
    else:           grade = f"{c.R}POOR{c.NC}";             label = "high fingerprint risk"

    print()
    div(c)
    print(f"\n  {c.BOLD}Masquerade Score:{c.NC} {c.BOLD}{pct}%{c.NC}  {c.DIM}{bar}{c.NC}  {grade}")
    print(f"  {c.DIM}{sc.pts}/{sc.max} pts — {label}{c.NC}\n")


# ── Main ──────────────────────────────────────────────────────
async def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    flags = [a for a in sys.argv[1:] if a.startswith('--')]

    if len(args) < 2:
        print(f"Usage: {sys.argv[0]} <host> <port> [sni] [--no-color]")
        sys.exit(1)

    host    = args[0]
    port    = int(args[1])
    sni     = args[2] if len(args) > 2 else host
    timeout = 5

    use_color = '--no-color' not in flags
    c  = Colors(use_color and sys.stdout.isatty() or use_color)
    sc = Score()

    header(c, "UDP / QUIC CHECKS")

    await probe_udp_reachability(c, sc, host, port)
    probe_raw_udp(c, sc, host, port)
    await probe_quic_handshake(c, sc, host, port, sni, timeout)
    await probe_certificate(c, sc, host, port, sni, timeout)
    await probe_mismatched_sni(c, sc, host, port, timeout)
    await probe_no_sni(c, sc, host, port, timeout)
    await probe_http3(c, sc, host, port, sni, timeout)
    await probe_port_hopping(c, sc, host, timeout)

    print_summary(c, sc)


if __name__ == "__main__":
    asyncio.run(main())
