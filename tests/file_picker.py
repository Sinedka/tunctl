"""Exercise file selection through the real terminal client without a desktop or daemon."""
import os
import pty
import select
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def session(args, env, directory, interactions=(), expected=0):
    master, slave = pty.openpty()
    try:
        with subprocess.Popen([binary, *args], stdin=slave, stdout=slave, stderr=slave,
                              cwd=directory, env=env) as proc:
            try:
                for marker, keys in interactions:
                    seen = b""
                    deadline = time.monotonic() + 8
                    while marker not in seen:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or not select.select([master], [], [], remaining)[0]:
                            raise AssertionError((marker, seen))
                        seen += os.read(master, 8192)
                    os.write(master, keys)
                assert proc.wait(timeout=8) == expected
            finally:
                if proc.poll() is None:
                    proc.kill()
    finally:
        os.close(master)
        os.close(slave)


if __name__ == "__main__":
    if os.geteuid() == 0:
        sys.exit(77)  # The interactive client requires an ordinary user.
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        env = dict(os.environ, TERM="xterm", HOME=tmp, XDG_CONFIG_HOME=tmp, XDG_STATE_HOME=tmp)
        env.pop("DISPLAY", None)
        env.pop("WAYLAND_DISPLAY", None)
        settings = root / "настройки с пробелом.json"
        settings.write_text("{}")
        session(["check-settings"], env, root, [(b"Esc cancel", b"\x1bOB\n")])
        session(["import"], env, root, [(b"Esc cancel", b"\x1b")])
        session([], env, root, [(b"Dashboard", b"5"), (b"Export routing rules", b"e"),
                               (b"n new file", b"n"), (b"Filename", b"backup.json\n"),
                               (b"Saved ", b"q")])
        assert (root / "backup.json").read_text() == "[]\n"

        helper = root / "zenity"
        helper.write_text(f"#!{sys.executable}\n" +
                          "import os, sys\n"
                          "print('desktop warning', file=sys.stderr)\n"
                          "print(os.environ['PICK_PATH'])\n"
                          "sys.exit(int(os.environ.get('PICK_STATUS', '0')))\n")
        helper.chmod(0o755)
        env.update(DISPLAY=":fixture", PATH=tmp + os.pathsep + env["PATH"], PICK_PATH=str(settings))
        session(["check-settings"], env, root)
        settings.write_text("invalid")
        session(["check-settings"], env, root, expected=1)
        session(["import"], dict(env, PICK_STATUS="42"), root)
        session(["check-settings"], dict(env, PICK_STATUS="127"), root, [(b"Esc cancel", b"q")])
