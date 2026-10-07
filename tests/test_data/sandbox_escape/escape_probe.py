# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A malicious scanner. Each attempt records "succeeded" or "blocked: <why>".

Run by the sandbox-escape fixture scanner as its tool subprocess, so it is spawned
through the same path as every real scanner. Arguments are one JSON document naming
what to attack; the outcome is written as JSON to the path in ``outcome``. Standard
library only, because it runs with whatever the sandbox lets it see.
"""

import json
import os
import socket
import sys


def attempt(fn):
    try:
        fn()
        return "succeeded"
    except BaseException as e:  # noqa: BLE001 - every failure is an outcome here
        return f"blocked: {type(e).__name__}: {e}"


def main() -> int:
    spec = json.loads(sys.argv[1])
    outcomes = {}

    def read_ssh_key():
        with open(os.path.join(spec["home"], ".ssh", "id_rsa"), encoding="utf-8") as f:
            if spec["secret"] not in f.read():
                raise RuntimeError("read something, but not the planted key")

    def read_outside_source():
        with open(spec["outside_file"], encoding="utf-8") as f:
            if spec["secret"] not in f.read():
                raise RuntimeError("read something, but not the planted file")

    def write_outside_output():
        with open(os.path.join(spec["outside_dir"], "pwned.txt"), "w") as f:
            f.write("pwned")

    def write_elsewhere_in_output():
        with open(os.path.join(spec["output_dir"], "pwned.txt"), "w") as f:
            f.write("pwned")

    def modify_source():
        with open(os.path.join(spec["source_dir"], "app.py"), "a") as f:
            f.write("\n# pwned\n")

    def create_in_source():
        with open(os.path.join(spec["source_dir"], "pwned.txt"), "w") as f:
            f.write("pwned")

    def tcp_connect():
        with socket.create_connection(("127.0.0.1", spec["tcp_port"]), timeout=5) as s:
            s.sendall(spec["secret"].encode())
            if s.recv(16) != b"ack":
                raise RuntimeError("connected, but not to the test's listener")

    def tcp_connect_host_address():
        # The host's own non-loopback address: reachable through a shared network
        # namespace even when loopback is not.
        with socket.create_connection((spec["host_ip"], spec["tcp_port"]), timeout=5) as s:
            s.sendall(spec["secret"].encode())
            if s.recv(16) != b"ack":
                raise RuntimeError("connected, but not to the test's listener")

    def udp_send():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.settimeout(5)
            s.sendto(spec["secret"].encode(), ("127.0.0.1", spec["udp_port"]))
            data, _ = s.recvfrom(16)
            if data != b"ack":
                raise RuntimeError("sent, but no reply from the test's listener")
        finally:
            s.close()

    def unix_socket_connect():
        # A host IPC endpoint (the Docker socket, the session bus) is a Unix socket
        # at a path; this is a stand-in the test listens on.
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.settimeout(5)
            s.connect(spec["unix_socket"])
            s.sendall(spec["secret"].encode())
            if s.recv(16) != b"ack":
                raise RuntimeError("connected, but not to the test's listener")
        finally:
            s.close()

    def write_dev_shm():
        with open(spec["shm_file"], "w") as f:
            f.write("pwned")

    def plant_symlinks():
        # Links where ASH, which is not sandboxed, writes after the scanner exits:
        # if ASH followed them it would overwrite the victims for the scanner.
        results_dir = os.path.dirname(spec["outcome"])
        for name, victim in spec["victims"].items():
            link = os.path.join(results_dir, name)
            if os.path.lexists(link):
                os.unlink(link)
            os.symlink(victim, link)

    def env_credentials():
        if os.environ.get("AWS_SECRET_ACCESS_KEY") != spec["secret"]:
            raise RuntimeError("credential not in the environment")

    def parent_environ():
        for pid in os.listdir("/proc"):
            if not pid.isdigit() or int(pid) == os.getpid():
                continue
            try:
                with open(f"/proc/{pid}/environ", "rb") as f:
                    if spec["secret"].encode() in f.read():
                        return
            except OSError:
                continue
        raise RuntimeError("no readable process environment held the credential")

    checks = {
        "read_ssh_key": read_ssh_key,
        "read_outside_source": read_outside_source,
        "write_outside_output": write_outside_output,
        "write_elsewhere_in_output": write_elsewhere_in_output,
        "modify_source": modify_source,
        "create_in_source": create_in_source,
        "tcp_connect": tcp_connect,
        "tcp_connect_host_address": tcp_connect_host_address,
        "udp_send": udp_send,
        "env_credentials": env_credentials,
        "unix_socket_connect": unix_socket_connect,
        "plant_symlinks": plant_symlinks,
    }
    if os.path.isdir("/proc") and sys.platform.startswith("linux"):
        checks["parent_environ"] = parent_environ
    if spec.get("shm_file"):
        checks["write_dev_shm"] = write_dev_shm
    for name, fn in checks.items():
        outcomes[name] = attempt(fn)

    with open(spec["outcome"], "w", encoding="utf-8") as f:
        json.dump(outcomes, f, indent=2)
    # Something on stdout, so ASH writes its stdout log at the name a link was
    # planted at.
    print("escape probe finished")
    return 0


if __name__ == "__main__":
    sys.exit(main())
