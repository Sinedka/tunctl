"""Read-only support report for an already installed VPNCTL, including older clients."""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


UNITS = ["vpnctl.socket", "vpnctl-routing.service", "vpnctl-session.service",
         "vpnctl-tunnel.service", "vpnctl-dns.service"]
STORE_PACKAGE = re.compile(r"/nix/store/([0-9a-z]{32}-(?:vpnctl|openvpn)-[0-9][\w.+-]*)/")
# Only print text from this list, never the matching input. In particular
# AUTH_FAILED can be followed by arbitrary text supplied by the server.
MARKERS = (
    "Connect: requested profile", "Switch: previous profile", "stopping previous tunnel",
    "Connect: starting OpenVPN", "fallback installed", "stored checksum verified",
    "stored profile checksum mismatch", "resolving VPN endpoint", "bootstrap returned",
    "bootstrap DNS did not resolve", "no numeric address for a VPN endpoint",
    "profile preparation failed", "runtime configuration ready", "waiting for handshake",
    "handshake confirmed", "tunnel routes installed", "readiness timed out",
    "Timed out waiting for vpnctl0", "is active on vpnctl0", "OpenVPN initialization failed",
    "Rollback: restarting previous profile", "previous tunnel restored",
    "previous tunnel also failed", "Disconnect: tunnel stopped",
    "Initialization Sequence Completed", "AUTH_FAILED", "server rejected authentication",
    "VERIFY ERROR", "certificate verification failed", "certificate has expired",
    "certificate is not yet valid", "unable to get local issuer certificate",
    "TLS key negotiation failed", "TLS negotiation timed out", "TLS handshake failed",
    "packet HMAC authentication failed", "tls-crypt unwrap error", "no shared data cipher",
    "failed to negotiate cipher", "Cannot load private key", "Cannot load certificate",
    "ca md too weak", "ee key too small", "no suitable signature algorithm",
    "unsupported protocol", "bad decrypt", "Cannot pre-load keyfile",
    "Cannot open TUN/TAP", "Cannot ioctl TUNSETIFF", "Cannot resolve host address",
    "Connection refused", "Network is unreachable", "Operation not permitted",
    "Permission denied", "No such file or directory", "Cannot find device",
    "RTNETLINK answers", "Options error", "Unrecognized option", "ModuleNotFoundError",
    "FileNotFoundError", "PermissionError", "File exists", "Device or resource busy",
    "Address already in use", "invalid gateway", "invalid JSON schema",
    "Dependency failed", "Control process exited", "Main process exited",
    "start operation timed out", "Failed to start", "Start request repeated too quickly",
    "Condition check resulted", "unauthorized peer", "IPC closed or timed out",
    "vpnctl socket unavailable or access denied", "startup or readiness check failed",
    "OpenVPN unit started but tunnel readiness was lost", "systemd could not start the OpenVPN unit",
)
STATES = {"INITIAL", "CONNECTING", "RESOLVE", "TCP_CONNECT", "WAIT", "AUTH",
          "AUTH_PENDING", "GET_CONFIG", "ASSIGN_IP", "ADD_ROUTES", "CONNECTED",
          "RECONNECTING", "EXITING", "WAIT_MANAGEMENT"}


def run(args, timeout=6):
    try:
        p = subprocess.run(args, capture_output=True, text=True, errors="replace",
                           env={**os.environ, "LC_ALL": "C"}, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "command missing"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def markers(message):
    lower = message.lower()
    labels = [m for m in MARKERS if m.lower() in lower]
    if message.startswith("OpenVPN state: ") and message[15:] in STATES:
        labels.append(message[15:])
    return labels


def snapshot():
    client = shutil.which("vpnctl")
    print("client:", "missing from PATH" if not client else
          next(iter(STORE_PACKAGE.findall(os.path.realpath(client))), "installed (outside Nix store)"))
    sock = Path("/run/vpnctl/control.sock")
    print("control socket:", "present" if sock.is_socket() else "missing",
          "writable by caller:", os.access(sock, os.W_OK))
    print("vpnctl0 present:", Path("/sys/class/net/vpnctl0").exists())
    if client:
        code, out, err = run([client, "status"])
        try:
            status = json.loads(out) if code == 0 else {}
            print("IPC status:", status.get("state", "") if status.get("state") in
                  {"active", "inactive", "connected", "reconnecting", "failed",
                   "activating", "deactivating", "reloading"} else f"exit={code}")
            if code == 0:
                print("profiles:", len(status.get("profiles", [])), "killSwitch:",
                      status.get("killSwitch") is True)
            failure = markers(err + " " + str(status.get("lastError", "")))
            if failure:
                print("last error:", " / ".join(failure))
        except (ValueError, AttributeError, TypeError):
            print("IPC status: unrecognised response")
    for unit in UNITS:
        fields = "LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,NRestarts,ConditionResult"
        code, out, _ = run(["systemctl", "show", unit, "--property=" + fields])
        print(unit, " ".join(out.splitlines()) or f"systemctl exit={code}")
    # The deployed unit and the client in PATH may belong to different generations.
    _, commands, _ = run(["systemctl", "show", "vpnctl-tunnel.service",
                          "--property=ExecStartPre,ExecStart,ExecStartPost,ExecStopPost"])
    print("tunnel unit packages:", ", ".join(sorted(set(STORE_PACKAGE.findall(commands)))) or "unavailable")
    print("tunnel unit waits for handshake:", "wait-ready" in commands if commands else "unknown")
    for row in commands.splitlines():
        phase, _, entries = row.partition("=")
        if phase not in {"ExecStartPre", "ExecStart", "ExecStartPost", "ExecStopPost"}:
            continue
        for step, entry in enumerate(re.findall(r"\{([^{}]+)\}", entries), start=1):
            if match := re.search(r"\bstatus=([0-9]{1,3})\b", entry):
                if int(match[1]):
                    print("Failed command:", phase, "step", step, "status", match[1])


def number(path):
    try:
        return int(Path(path).read_text())
    except (OSError, ValueError):
        return None


def route(family, target, mark):
    code, out, err = run(["ip", family, "-j", "route", "get", target, "mark", mark])
    if code:
        return "unreachable" if "unreachable" in err.lower() else f"lookup failed ({code})"
    try:
        device = json.loads(out)[0]["dev"]
        return "vpnctl0" if device == "vpnctl0" else "other interface"
    except (ValueError, IndexError, KeyError, TypeError):
        return "unknown"


def counters():
    result = {key: number("/sys/class/net/vpnctl0/statistics/" + key)
              for key in ("rx_packets", "tx_packets")}
    try:
        rows = Path("/proc/net/netstat").read_text().splitlines()
        for header, values in zip(rows[::2], rows[1::2]):
            columns = dict(zip(header.split(), values.split()))
            if "IPReversePathFilter" in columns:
                result["host_rpf_drops"] = int(columns["IPReversePathFilter"])
    except (OSError, ValueError):
        pass
    return result


def network_report(probe):
    print("Network path:")
    for name in ("all", "vpnctl0"):
        value = number(f"/proc/sys/net/ipv4/conf/{name}/rp_filter")
        print(f"  rp_filter {name}:", value if value is not None else "unavailable")
    for family, dest in [("-4", "1.1.1.1"), ("-6", "2606:4700:4700::1111")]:
        print(f"  {family} unmarked route:", route(family, dest, "0"))
        print(f"  {family} VPN-marked route:", route(family, dest, "0x7651"))
        print(f"  {family} transport-marked route:", route(family, dest, "0x7653"))
    resolvers = []
    try:
        for line in Path("/etc/resolv.conf").read_text().splitlines():
            fields = line.split()
            if len(fields) < 2 or fields[0] != "nameserver":
                continue
            addr = ipaddress.ip_address(fields[1].split("%")[0])
            if addr.is_loopback:
                resolvers.append("local stub")
            elif addr.is_global:
                resolvers.append("public")
            else:
                resolvers.append("private/link-local")
    except (OSError, ValueError):
        resolvers.append("unavailable")
    print("  system resolver targets:", ", ".join(resolvers) or "none listed")
    if not probe:
        return
    if not Path("/sys/class/net/vpnctl0").exists():
        print("  probes skipped: vpnctl0 absent")
        return
    before = counters()
    # No DNS, proxy, curlrc or redirect. Compare a regular socket with one
    # bound to the tunnel using precisely the same HTTPS endpoint.
    for label, binding in [("normal policy", []), ("bound to vpnctl0", ["--interface", "vpnctl0"])]:
        code, out, _ = run(["curl", "--disable", "-4", "--noproxy", "*", *binding,
                            "--resolve", "one.one.one.one:443:1.1.1.1",
                            "--head", "--silent", "--output", "/dev/null",
                            "--write-out", "http=%{http_code} tcp_s=%{time_connect} tls_s=%{time_appconnect}",
                            "--connect-timeout", "4", "--max-time", "6", "https://one.one.one.one/"],
                           timeout=8)
        print(f"  IPv4 HTTPS without DNS ({label}): curl={code}", out.strip())
    code, out, _ = run(["getent", "ahostsv4", "example.org"], timeout=6)
    print("  system lookup example.org:", "resolved" if code == 0 and out.strip() else f"failed ({code})")
    for key, value in counters().items():
        if value is not None and before.get(key) is not None:
            print(f"  delta {key}:", value - before[key])


def journal(elevated):
    args = ["journalctl", "-b", "--since=-15min", "-n", "400", "--no-pager", "-o", "json",
            "--output-fields=MESSAGE,UNIT,_SYSTEMD_UNIT,_COMM,EXIT_STATUS,PRIORITY"]
    for unit in [*UNITS, "vpnctl@*.service"]:
        args.extend(["-u", unit])
    if elevated:
        if not shutil.which("sudo") or subprocess.run(["sudo", "-v"]).returncode:
            print("System journal: sudo unavailable or access denied. Reading visible entries.")
        else:
            args = ["sudo", "-n", "--", *args]
    code, out, _ = run(args, timeout=12)
    print("Journal (last 15 minutes, UTC), exit:", code)
    seen = 0
    unknown = 0
    for row in out.splitlines():
        try:
            e = json.loads(row)
            when = datetime.fromtimestamp(int(e["__REALTIME_TIMESTAMP"]) / 1e6, timezone.utc)
        except (KeyError, ValueError, OverflowError, TypeError):
            continue
        message = e.get("MESSAGE", "")
        if not isinstance(message, str):
            continue
        unit = e.get("UNIT") or e.get("_SYSTEMD_UNIT")
        unit = unit if unit in UNITS else "vpnctl IPC/service"
        labels = markers(message)
        # systemd supplies the numeric exit status independently of log text.
        status = str(e.get("EXIT_STATUS", ""))
        if re.fullmatch(r"[0-9]{1,3}", status):
            labels.append("exit=" + status)
        if not labels:
            if str(e.get("PRIORITY")) not in {"0", "1", "2", "3", "4"}:
                continue
            unknown += 1
            labels = ["unclassified warning/error (original text withheld)"]
        print(when.strftime("%H:%M:%S"), unit, " / ".join(labels))
        seen += 1
    print("Reportable entries:", seen, "unclassified:", unknown)
    if not seen:
        print("No matching events visible in this boot/time window.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sudo-journal", action="store_true",
                        help="use sudo for journalctl; query client status as the current user")
    parser.add_argument("--probe", action="store_true",
                        help="also try IPv4 HTTPS to Cloudflare and a system lookup of example.org")
    options = parser.parse_args()
    print("VPNCTL connection report v2", datetime.now(timezone.utc).isoformat(), flush=True)
    snapshot()
    network_report(options.probe)
    journal(options.sudo_journal)
