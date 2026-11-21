#!/usr/bin/env python3
"""Resolve only OpenVPN transport peers before starting the client."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket

import dns.message
import dns.query
import dns.flags
import dns.rdatatype


def bootstrap(host, nameservers, families):
    result = []
    for server in nameservers:
        for family in families:
            query = dns.message.make_query(host, family)
            try:
                with socket.socket(socket.AF_INET6 if ":" in server else socket.AF_INET,
                                   socket.SOCK_DGRAM) as sock:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, 0x7653)
                    sock.setblocking(False)
                    reply = dns.query.udp(query, server, timeout=2, sock=sock)
                if reply.flags & dns.flags.TC:
                    continue
                rr = reply.resolve_chaining().answer
                if rr and rr.rdtype == dns.rdatatype.from_text(family):
                    result.extend(str(ipaddress.ip_address(r.address)) for r in rr)
            except (OSError, dns.exception.DNSException):
                continue
        if result:
            return result
    raise RuntimeError("no numeric address for a VPN endpoint (check bootstrapDNS)")


def prepare():
    os.umask(0o077)
    source = Path("/run/vpnctl/pending.ovpn")
    if not source.is_symlink():
        source = Path("/var/lib/vpnctl/active.ovpn")
    source = source.resolve(strict=True)
    content = source.read_bytes()
    if hashlib.sha256(content).hexdigest() != json.loads(Path(str(source)+".json").read_text())["sha256"]:
        raise ValueError("stored profile checksum mismatch")
    lines = content.decode("ascii").splitlines()
    nameservers = json.loads(Path("/etc/vpnctl/policy.json").read_text())["bootstrapDNS"]
    proto = "udp"
    inside = False
    for line in lines:
        if line.startswith("<"):
            inside = not line.startswith("</")
        elif not inside and line.startswith("proto "):
            proto = line.split()[1]
    output = []
    for line in lines:
        if line.startswith("<"):
            inside = not line.startswith("</")
        if not inside and line.startswith("remote "):
            _, host, *args = line.split()
            try:
                ipaddress.ip_address(host)
            except ValueError:
                mode = args[1] if len(args) > 1 else proto
                families = ["AAAA"] if "6" in mode else ["A"] if "4" in mode else ["A","AAAA"]
                for ip in bootstrap(host, nameservers, families):
                    output.append(" ".join(["remote",ip,*args]))
                continue
        output.append(line)
    Path("/run/vpnctl-tunnel/client.ovpn").write_text("\n".join(output)+"\n", "ascii")


if __name__ == "__main__":
    prepare()
