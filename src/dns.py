#!/usr/bin/env python3
"""Loopback-only upstream for dnsmasq. Commit RR lifetimes before replying."""
import concurrent.futures
import fcntl
import ipaddress
import json
import math
import socket
import socketserver
import struct
import subprocess
import threading
import time
from pathlib import Path

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

POLICY = Path("/etc/vpnctl/policy.json")
RUNTIME = Path("/run/vpnctl")
mutex = threading.Lock()
expiry = {}
generation = None


def action(name, rules):
    host = name.lower().rstrip(".")
    for rule in rules:
        pattern = rule["match"].lower()
        suffix = pattern.removeprefix("*.")
        if host.endswith("." + suffix) or (host == suffix and not pattern.startswith("*.")):
            return rule["action"]
    return None


def records(answer):
    chain = answer.resolve_chaining()
    rr = chain.answer
    if rr and rr.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
        for item in rr:
            yield ipaddress.ip_address(item.address), min(rr.ttl, chain.minimum_ttl, 300)


def classify(answer):
    global generation
    with mutex, (RUNTIME / "dns.lock").open() as guard:
        fcntl.flock(guard, fcntl.LOCK_SH)
        policy = json.loads(POLICY.read_text())
        rules = [dict(match=m, action="direct") for m in policy["directDomains"]]
        runtime = RUNTIME / "domains.json"
        stamp = (POLICY.stat().st_ino, runtime.stat().st_ino if runtime.exists() else None)
        if stamp != generation:
            expiry.clear()
            generation = stamp
        if runtime.exists():
            layer = json.loads(runtime.read_text())
            if layer["owner"] == policy["policyUser"]:
                rules += layer["rules"]
        name = answer.question[0].name.to_text()
        route = action(name, rules)
        if not route:
            return
        now = time.monotonic()
        for key in list(expiry):
            if expiry[key] <= now:
                del expiry[key]
        commands = []
        for ip, ttl in records(answer):
            if ttl == 0:
                continue
            setname = ("domains" if route == "direct" else "domainvpn") + str(ip.version)
            key = (setname, ip)
            # Shared addresses retain the longest still-valid DNS lease.
            end = max(now + ttl, expiry.get(key, 0))
            commands.extend((f"destroy element inet vpnctl {setname} {{ {ip} }}",
                             f"add element inet vpnctl {setname} {{ {ip} timeout {math.ceil(end-now)}s }}"))
            if len(expiry) < 16384 or key in expiry:
                expiry[key] = end
        if commands:
            subprocess.run(["nft", "-f", "-"], input="\n".join(commands)+"\n",
                           text=True, check=True, timeout=2, stdout=subprocess.DEVNULL)


def resolve(wire):
    query = dns.message.from_wire(wire)
    if len(query.question) != 1 or query.flags & dns.flags.QR or query.opcode() != 0:
        raise ValueError("invalid DNS query")
    for host in json.loads(POLICY.read_text())["upstreams"]:
        try:
            result, _ = dns.query.udp_with_fallback(query, host, timeout=3)
            if result.rcode() == dns.rcode.NOERROR:
                classify(result)
            return result
        except (dns.exception.DNSException, OSError, subprocess.SubprocessError):
            continue
    result = dns.message.make_response(query)
    result.set_rcode(dns.rcode.SERVFAIL)
    return result


class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        wire, sock = self.request
        result = resolve(wire)
        size = min(4096, max(512, dns.message.from_wire(wire).payload))
        sock.sendto(result.to_wire(max_size=size, prefer_truncation=True), self.client_address)


class TCP(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(4)
        header = self.rfile.read(2)
        if len(header) == 2:
            wire = self.rfile.read(struct.unpack("!H", header)[0])
            reply = resolve(wire).to_wire()
            self.wfile.write(struct.pack("!H", len(reply)) + reply)


class Pool:
    slots = threading.BoundedSemaphore(16)
    pool = concurrent.futures.ThreadPoolExecutor(16)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return

        def work():
            try:
                self.finish_request(request, address)
            except (ValueError, OSError, dns.exception.DNSException):
                pass
            finally:
                self.shutdown_request(request)
                self.slots.release()
        self.pool.submit(work)


class UDPServer(Pool, socketserver.UDPServer):
    max_packet_size = 65535


class TCPServer(Pool, socketserver.TCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    address = ("127.0.0.1", 53071)
    with UDPServer(address, UDP) as udp, TCPServer(address, TCP) as tcp:
        threading.Thread(target=tcp.serve_forever, daemon=True).start()
        udp.serve_forever()
