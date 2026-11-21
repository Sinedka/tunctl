#!/usr/bin/env python3
"""Package profile material as the invoking user. Never extract archive members."""
import json
import re
import shlex
import socket
import stat
import struct
import subprocess
import sys
import zipfile
from pathlib import Path, PurePosixPath

LIMIT = 1024 * 1024
BLOBS = {"ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "auth-user-pass"}


def relative(name):
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\\" in name:
        raise ValueError("unsafe relative path")
    return path


def local(root, name):
    path = (root / relative(str(name))).resolve(strict=True)
    if not path.is_relative_to(root) or not path.is_file() or path.stat().st_size > LIMIT:
        raise ValueError("invalid external file")
    with path.open("rb") as stream:
        return stream.read(LIMIT + 1)


def expand(path, load):
    lines = []
    block = None
    for line in load(path).decode("ascii").splitlines():
        if block:
            if line.strip() == f"</{block}>":
                block = None
        elif line.strip().startswith("<"):
            block = line.strip()[1:-1]
        elif line.split()[:1] and line.split()[0] in BLOBS:
            parts = shlex.split(line, comments=True)
            key = parts[0]
            if len(parts) != 2 and not (key == "tls-auth" and len(parts) == 3 and parts[2] in ("0", "1")):
                raise ValueError("external credential file required")
            ref = PurePosixPath(parts[1])
            if ref.is_absolute() or "\\" in parts[1]:
                raise ValueError("unsafe external path")
            from posixpath import normpath
            blob = load(relative(normpath(str(path.parent / ref)))).decode("ascii").strip()
            if "<" in blob or ">" in blob:
                raise ValueError("invalid credential data")
            line = f"<{key}>\n{blob}\n</{key}>"
            if len(parts) == 3:
                line += "\nkey-direction " + parts[2]
        lines.append(line)
    return "\n".join(lines)


def submit(path, load):
    name = re.sub(r"[^A-Za-z0-9_.-]", "_", path.stem)
    profile = expand(path, load)
    if "--validate" in sys.argv[2:]:
        subprocess.run(["vpnctl","validate-stdin"],input=profile,text=True,check=True)
        print(name)
        return
    data = json.dumps(dict(op="import", name=name, profile=profile)).encode()
    if len(data) > 2 * LIMIT:
        raise ValueError("oversized profile")
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(120)
        sock.connect("/run/vpnctl/control.sock")
        sock.sendall(struct.pack("!I", len(data)) + data)
        with sock.makefile("rb") as reply:
            length, = struct.unpack("!I", reply.read(4))
            result = json.loads(reply.read(length))
    if "error" in result:
        raise ValueError(f"{name}: {result['error']}")
    print(name, flush=True)


def main(source):
    source = source.resolve(strict=True)
    if source.suffix.lower() == ".zip":
        if source.stat().st_size > 64 * LIMIT:
            raise ValueError("oversized archive")
        with zipfile.ZipFile(source) as archive:
            names = set()
            entries = archive.infolist()
            if len(entries) > 2048 or sum(i.file_size for i in entries) > 64 * LIMIT:
                raise ValueError("archive limit exceeded")
            for i in entries:
                p = relative(i.filename)
                if str(p) in names or i.file_size > LIMIT or stat.S_ISLNK(i.external_attr >> 16):
                    raise ValueError("invalid zip member")
                names.add(str(p))
            profiles = sorted(PurePosixPath(n) for n in names if n.lower().endswith(".ovpn"))
            if not profiles:
                raise ValueError("no profiles found")
            for p in profiles:
                submit(p, lambda name: archive.read(str(name)))
    else:
        root = source if source.is_dir() else source.parent
        paths = sorted(root.rglob("*.ovpn")) if source.is_dir() else [source]
        if not paths:
            raise ValueError("no profiles found")
        for path in paths:
            submit(path.relative_to(root), lambda name: local(root, name))


if __name__ == "__main__":
    try:
        main(Path(sys.argv[1]))
    except Exception as error:
        sys.exit(str(error))
