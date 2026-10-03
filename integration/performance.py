#!/usr/bin/env python3
"""Run only inside unshare --user --map-root-user --mount --net.

The client and Linux/strongSwan gateway communicate over a private veth pair.
The gateway owns a second network namespace. No host interfaces or services
are modified. Logs and profiles remain in --output after processes exit.
"""

import argparse
import concurrent.futures
import hashlib
import json
import os
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--client", required=True, type=Path)
parser.add_argument("--output", required=True, type=Path)
parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parent.parent)
parser.add_argument("--cores", type=int, default=6)
parser.add_argument("--duration", type=int, default=15)
parser.add_argument("--streams", type=int, default=8)
parser.add_argument("--directions", default="bidir")
parser.add_argument(
    "--no-profile", action="store_true", help="disable CPU profiles and mid-run state sampling"
)
parser.add_argument("--gro", choices=["on", "off"])
parser.add_argument("--delay", default=None)
parser.add_argument("--protocol", choices=["tcp", "udp"], default="tcp")
parser.add_argument(
    "--rate", type=float, default=10, help="aggregate UDP Gbit/s per direction"
)
parser.add_argument("--replay-window", type=int, default=32)
parser.add_argument("--affinity")
parser.add_argument("--client-port", type=int, default=20000)
args = parser.parse_args()
if args.cores < 1 or args.duration < 1 or args.streams < 1 or args.rate < 0:
    parser.error(
        "cores, duration, and streams must be positive; rate must be nonnegative"
    )
if any(
    direction not in {"bidir", "outbound", "inbound"}
    for direction in args.directions.split(",")
):
    parser.error(
        "directions must be a comma-separated list of outbound, inbound, or bidir"
    )
uid_map = Path("/proc/self/uid_map").read_text().split()
if (
    os.geteuid() != 0
    or len(uid_map) != 3
    or uid_map[0] != "0"
    or uid_map[1] == "0"
    or uid_map[2] != "1"
):
    parser.error(
        "run with unshare --user --map-root-user --mount --net as an ordinary user"
    )
args.client, args.repo, args.output = (
    args.client.resolve(),
    args.repo.resolve(),
    args.output.resolve(),
)
if not args.client.is_file():
    parser.error(f"client binary does not exist: {args.client}")
commands = {}
for name in [
    "ip",
    "ss",
    "mount",
    "unshare",
    "nsenter",
    "sleep",
    "cat",
    "bird",
    "charon-systemd",
    "swanctl",
    "ping",
    "tc",
    "taskset",
    "iperf3",
    "ethtool",
]:
    executable = shutil.which(name)
    if executable is None:
        parser.error(f"required program {name!r} is missing; use nix develop")
    commands[name] = str(Path(executable).resolve())
for name in ["sleep", "cat"]:
    # Preserve argv[0] for coreutils' multicall binary.
    commands[name] = str(Path(commands[name]).parent / name)
# NixOS may expose mount through a security wrapper. Use the util-linux
# executable directly: privileges come only from the private user namespace.
mount = Path(commands["unshare"]).parent / "mount"
if mount.exists():
    commands["mount"] = str(mount)
args.output.mkdir(parents=True, exist_ok=False)
with args.client.open("rb") as binary:
    client_hash = hashlib.file_digest(binary, "sha256").hexdigest()
(args.output / "metadata.json").write_text(
    json.dumps(
        {
            "arguments": vars(args),
            "kernel": os.uname().release,
            "client_sha256": client_hash,
            "iperf3": {
                "executable": commands["iperf3"],
                "version": subprocess.run(
                    [commands["iperf3"], "--version"],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout,
            },
            "cpu_model": next(
                (
                    line.split(":", 1)[1].strip()
                    for line in Path("/proc/cpuinfo").read_text().splitlines()
                    if line.startswith("model name")
                ),
                "unknown",
            ),
        },
        indent=2,
        default=str,
    )
    + "\n"
)
processes = []
process_names = {}


def run(command, gateway=False, check=True, **kwargs):
    command = [commands.get(str(command[0]), str(command[0]))] + [
        str(v) for v in command[1:]
    ]
    if gateway:
        command = [commands["nsenter"], "-t", str(ns.pid), "-n"] + command
    return subprocess.run(
        command,
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        **kwargs,
    )


def start(command, name, gateway=False, env=None):
    command = [commands.get(str(command[0]), str(command[0]))] + [
        str(v) for v in command[1:]
    ]
    if gateway:
        command = [commands["nsenter"], "-t", str(ns.pid), "-n"] + command
    with (args.output / (name + ".log")).open("w") as log:
        proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, env=env)
    processes.append(proc)
    process_names[proc.pid] = name
    return proc


def wait_for(test, message, timeout=15):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            if test():
                return
        except FileNotFoundError:
            pass
        for proc in processes:
            if proc.poll() is not None:
                raise RuntimeError(
                    f"process {proc.args} exited with {proc.returncode}; see {args.output}"
                )
        time.sleep(0.1)
    raise RuntimeError(message)


def profile(direction):
    url = f"http://127.0.0.1:6060/debug/pprof/profile?seconds={args.duration}"
    with urllib.request.urlopen(url, timeout=args.duration + 10) as response:
        (args.output / (direction + ".pprof")).write_bytes(response.read())


def sample_state(direction):
    time.sleep(args.duration / 2)
    with urllib.request.urlopen(
        "http://127.0.0.1:6060/debug/pprof/goroutine?debug=2", timeout=5
    ) as response:
        (args.output / (direction + "-goroutines.txt")).write_bytes(response.read())
    (args.output / (direction + "-links.txt")).write_text(
        run(["ip", "-s", "link"]).stdout
    )
    (args.output / (direction + "-udp.txt")).write_text(
        run(["cat", "/proc/net/snmp"]).stdout
    )
    (args.output / (direction + "-qdisc.txt")).write_text(
        run(["tc", "-s", "qdisc", "show", "dev", "ranet0"]).stdout
    )
    for side, gateway in [("client", False), ("gateway", True)]:
        (args.output / f"{direction}-{side}-packet-sockets.txt").write_text(
            run(["cat", "/proc/net/packet"], gateway=gateway).stdout
        )
        (args.output / f"{direction}-{side}-tcp.txt").write_text(
            run(["ss", "-tin"], gateway=gateway).stdout
        )


def cpu_snapshot():
    """Read CPU time charged to the whole process, including kernel work.

    Pair the sampled Go profile with process accounting and system counters.
    System counters include both namespaces and any other activity on this
    shared host, including softirq time not charged to individual processes.
    """
    snapshot = {"time": time.monotonic(), "processes": {}, "system": {}}
    for proc in processes:
        try:
            # comm may contain spaces and parentheses. Fields after its final
            # ')' start at field 3 (state); utime and stime are fields 14/15.
            fields = (
                Path(f"/proc/{proc.pid}/stat").read_text().rsplit(")", 1)[1].split()
            )
        except FileNotFoundError:
            continue
        snapshot["processes"][proc.pid] = {
            "name": process_names[proc.pid],
            "user": int(fields[11]),
            "system": int(fields[12]),
        }
    for line in Path("/proc/stat").read_text().splitlines():
        fields = line.split()
        if fields[0] == "cpu":
            # guest time is already included in user/nice. Do not add it twice.
            snapshot["system"] = dict(
                zip(
                    [
                        "user",
                        "nice",
                        "system",
                        "idle",
                        "iowait",
                        "irq",
                        "softirq",
                        "steal",
                    ],
                    map(int, fields[1:9]),
                )
            )
            break
    return snapshot


def cpu_usage(before, after):
    elapsed = after["time"] - before["time"]
    ticks = os.sysconf("SC_CLK_TCK")
    result = {"elapsed_seconds": elapsed, "processes": {}, "system_average_cores": {}}
    for pid, end in after["processes"].items():
        start = before["processes"].get(pid)
        if start is None:
            continue
        user = (end["user"] - start["user"]) / ticks
        system = (end["system"] - start["system"]) / ticks
        result["processes"][end["name"]] = {
            "pid": pid,
            "user_seconds": user,
            "system_seconds": system,
            "average_cores": (user + system) / elapsed,
        }
    result["system_average_cores"] = {
        key: (value - before["system"][key]) / ticks / elapsed
        for key, value in after["system"].items()
    }
    return result


def traffic(label, address, flags, collect_profile=False):
    print(
        f"Starting {label}: cores={args.cores}, streams={args.streams}, seconds={args.duration}",
        flush=True,
    )
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        future = pool.submit(profile, label) if collect_profile else None
        state = pool.submit(sample_state, label) if collect_profile else None
        if args.protocol == "udp":
            flags = flags + [
                "--udp",
                "--gsro",
                "-w",
                "4M",
                "-l",
                "1300",
                "-b",
                str(int(args.rate * 1e9 / args.streams)),
            ]
        port = (
            args.client_port
            + {"plain-bidir": 0, "outbound": 100, "inbound": 200, "bidir": 300}[label]
        )
        flags = flags + ["--cport", str(port)]
        before = cpu_snapshot()
        result = run(
            ["iperf3", "-c", address, "-P", args.streams, "-t", args.duration, "--json"]
            + flags,
            check=False,
            timeout=args.duration + 15,
        )
        usage = cpu_usage(before, cpu_snapshot())
        (args.output / (label + "-cpu.json")).write_text(
            json.dumps(usage, indent=2) + "\n"
        )
        (args.output / (label + ".json")).write_text(result.stdout)
        if result.returncode:
            raise RuntimeError(result.stdout)
        data = json.loads(result.stdout)
        summary = {
            key: value
            for key, value in data.get("end", {}).items()
            if key.startswith("sum_")
        }
        print(
            json.dumps({"label": label, "end": summary, "error": data.get("error")}),
            flush=True,
        )
        if future:
            future.result()
            state.result()


try:
    # Isolate daemon PID/socket files as well as networking. All executable
    # paths were resolved before hiding the host's /run/current-system link.
    run(["mount", "-t", "tmpfs", "tmpfs", "/run"])
    ns = start(["unshare", "--net", commands["sleep"], "infinity"], "namespace")
    wait_for(
        lambda: (
            os.readlink(f"/proc/{ns.pid}/ns/net") != os.readlink("/proc/self/ns/net")
        ),
        "gateway namespace did not start",
    )
    for command in [
        ["ip", "link", "set", "lo", "up"],
        ["ip", "link", "add", "client0", "type", "veth", "peer", "name", "gateway0"],
        ["ip", "link", "set", "gateway0", "netns", ns.pid],
        ["ip", "addr", "add", "10.200.0.1/30", "dev", "client0"],
        ["ip", "link", "set", "client0", "up"],
    ]:
        run(command)
    for command in [
        ["ip", "link", "set", "lo", "up"],
        ["ip", "addr", "add", "10.200.0.2/30", "dev", "gateway0"],
        ["ip", "link", "set", "gateway0", "up"],
        ["ip", "link", "add", "swan0", "type", "xfrm", "dev", "gateway0", "if_id", "1"],
        ["ip", "link", "set", "swan0", "mtu", "1400", "multicast", "on", "up"],
        ["ip", "addr", "add", "fe80::1/64", "dev", "swan0", "nodad"],
        ["ip", "addr", "add", "fd00:99::1/64", "dev", "swan0", "nodad"],
    ]:
        run(command, gateway=True)
    for interface, gateway in [("client0", False), ("gateway0", True)]:
        if args.delay:
            run(
                [
                    "tc",
                    "qdisc",
                    "add",
                    "dev",
                    interface,
                    "root",
                    "netem",
                    "delay",
                    args.delay,
                    "limit",
                    "100000",
                ],
                gateway=gateway,
            )
        if args.gro:
            run(["ethtool", "-K", interface, "gro", args.gro], gateway=gateway)
        (args.output / (interface + "-offloads.txt")).write_text(
            run(["ethtool", "-k", interface], gateway=gateway).stdout
        )
    swan_dir = args.output / "swanctl"
    for directory in [
        "x509",
        "x509ca",
        "x509ocsp",
        "x509aa",
        "x509ac",
        "x509crl",
        "rsa",
        "ecdsa",
        "pkcs8",
        "pkcs12",
    ]:
        (swan_dir / directory).mkdir(parents=True, exist_ok=True)
    for directory, fixture in [("private", "org-key.pem"), ("pubkey", "org-pub.pem")]:
        (swan_dir / directory).mkdir(parents=True, exist_ok=True)
        shutil.copyfile(
            args.repo / "integration" / fixture, swan_dir / directory / fixture
        )
    swan_conf = swan_dir / "swanctl.conf"
    swan_conf.write_text("""connections {
  ranet {
    version = 2
    local_addrs = 10.200.0.2
    remote_addrs = 10.200.0.1
    local_port = 13000
    remote_port = 14000
    encap = yes
    mobike = no
    if_id_in = 1
    if_id_out = 1
    local {
      auth = pubkey
      pubkeys = org-pub.pem
      id = "O=testorg, CN=server, serialNumber=1"
    }
    remote {
      auth = pubkey
      pubkeys = org-pub.pem
      id = "O=testorg, CN=client, serialNumber=2"
    }
    children {
      default {
        local_ts = 0.0.0.0/0, ::/0
        remote_ts = 0.0.0.0/0, ::/0
        mode = tunnel
      }
    }
  }
}
""")
    swan_conf.write_text(
        swan_conf.read_text().replace(
            "        mode = tunnel",
            f"        replay_window = {args.replay_window}\n        mode = tunnel",
        )
    )
    strong_conf = args.output / "strongswan.conf"
    strong_conf.write_text(
        """charon-systemd {
  port = 0
  port_nat_t = 13000
  install_routes = no
  plugins {
    vici { socket = unix:///run/charon.vici }
    kernel-netlink { install_routes = no }
  }
  journal { default = -1 }
  filelog {
    stdout { default = 1; flush_line = yes }
  }
}
""".replace("; flush_line", "\n      flush_line")
    )
    env = dict(os.environ, STRONGSWAN_CONF=str(strong_conf), SWANCTL_DIR=str(swan_dir))
    start(["charon-systemd"], "strongswan", gateway=True, env=env)
    wait_for(
        lambda: Path("/run/charon.vici").exists(),
        "strongSwan did not create its private VICI socket",
    )
    print(
        run(
            [
                "swanctl",
                "--load-all",
                "--file",
                swan_conf,
                "--uri",
                "unix:///run/charon.vici",
            ],
            gateway=True,
            env=env,
        ).stdout,
        flush=True,
    )
    bird_conf = args.output / "bird.conf"
    bird_conf.write_text("""log stderr all;
router id 10.200.0.2;
ipv6 sadr table sadr6;
protocol device { scan time 1; }
protocol kernel { ipv6 sadr { export all; import none; }; }
protocol static { ipv6 sadr; route fd00:99::/64 from ::/0 unreachable; }
protocol babel {
  ipv6 sadr { export all; import all; };
  interface "swan0" {
    type tunnel;
    rxcost 32;
    hello interval 500 ms;
    update interval 1 s;
    rx buffer 1500;
  };
}
""")
    start(
        ["bird", "-f", "-c", bird_conf, "-s", "/run/bird.ctl", "-P", "/run/bird.pid"],
        "bird",
        gateway=True,
    )
    start(["iperf3", "-s"], "iperf-server", gateway=True)
    public = (args.repo / "integration/org-pub.pem").read_text()
    registry = args.output / "registry.json"
    registry.write_text(
        json.dumps(
            [
                {
                    "organization": "testorg",
                    "public_key": public,
                    "nodes": [
                        {
                            "common_name": "client",
                            "endpoints": [
                                {
                                    "serial_number": "2",
                                    "address_family": "ip4",
                                    "address": "10.200.0.1",
                                    "port": 14000,
                                }
                            ],
                        },
                        {
                            "common_name": "server",
                            "endpoints": [
                                {
                                    "serial_number": "1",
                                    "address_family": "ip4",
                                    "address": "10.200.0.2",
                                    "port": 13000,
                                }
                            ],
                        },
                    ],
                }
            ]
        )
    )
    client_conf = args.output / "client.yaml"
    client_conf.write_text(f"""organization: testorg
common_name: client
port: 14000
endpoints:
  - serial_number: "2"
    address_family: ip4
private_key: {args.repo / "integration/org-key.pem"}
registry: {registry}
originate: ["fd00:88::2/128"]
tun: ranet0
child_rekey_interval: 0
ike_rekey_interval: 0
peers:
  - common_name: server
    serial_number: "1"
babel:
  hello_interval: 500ms
  update_interval: 1s
""")
    client_command = [
        str(args.client),
        "-config",
        client_conf,
        "-pprof",
        "127.0.0.1:6060",
    ]
    if args.affinity:
        client_command = ["taskset", "-c", args.affinity] + client_command
    start(client_command, "client", env=dict(os.environ, GOMAXPROCS=str(args.cores)))
    wait_for(
        lambda: run(["ip", "link", "show", "ranet0"], check=False).returncode == 0,
        "client did not create TUN",
    )
    run(["ip", "addr", "add", "fd00:88::2/128", "dev", "ranet0", "nodad"])
    run(["ip", "route", "add", "fd00:99::/64", "dev", "ranet0"])
    wait_for(
        lambda: (
            run(["ping", "-c", "1", "-W", "1", "fd00:99::1"], check=False).returncode
            == 0
        ),
        "ESP/Babel did not converge",
        timeout=30,
    )
    print(
        run(
            ["swanctl", "--list-sas", "--uri", "unix:///run/charon.vici"],
            gateway=True,
            env=env,
        ).stdout,
        flush=True,
    )
    traffic("plain-bidir", "10.200.0.2", ["--bidir"])
    for direction in args.directions.split(","):
        flags = {"bidir": ["--bidir"], "outbound": [], "inbound": ["--reverse"]}[
            direction
        ]
        traffic(direction, "fd00:99::1", flags, collect_profile=not args.no_profile)
    (args.output / "xfrm-state.txt").write_text(
        run(["ip", "-s", "xfrm", "state", "list", "nokeys"], gateway=True).stdout
    )
    (args.output / "xfrm-stat.txt").write_text(
        run(["cat", "/proc/net/xfrm_stat"], gateway=True, check=False).stdout
    )
finally:
    for proc in reversed(processes):
        if proc.poll() is None:
            proc.terminate()
    for proc in reversed(processes):
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
