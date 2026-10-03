{
  pkgs,
  before,
  after,
  repo,
  cores ? 6,
  streams ? 8,
  duration ? 10,
  repeats ? 3,
}:

let
  benchmarkIperf = import ./iperf3.nix { inherit pkgs; };
in
pkgs.testers.runNixOSTest {
  name = "ranet-lite-throughput-comparison";
  nodes.machine = {
    virtualisation.cores = cores;
    virtualisation.memorySize = 4096;
    boot.kernelModules = [
      "tun"
      "xfrm_interface"
    ];
    users.users.bench.isNormalUser = true;
    environment.systemPackages = with pkgs; [
      python3
      iproute2
      util-linux
      iputils
      strongswan
      bird3
      benchmarkIperf
      ethtool
    ];
  };
  testScript = ''
    import datetime as dt
    import json
    import shlex
    import statistics

    start_all()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("echo kvm-clock > /sys/devices/system/clocksource/clocksource0/current_clocksource")
    clients = {"before": "${before}/bin/ranet-lite", "after": "${after}/bin/ranet-lite"}
    runs = []
    for trial in range(1, ${toString (repeats + 1)}):
        order = ["before", "after"] if trial % 2 else ["after", "before"]
        for version in order:
            output = f"/tmp/throughput-{version}-{trial}"
            command = (
                "runuser -u bench -- unshare --user --map-root-user --mount --net "
                "python3 ${./performance.py} --repo ${repo} "
                f"--client {clients[version]} --output {output} "
                "--cores ${toString cores} --streams ${toString streams} "
                "--duration ${toString duration} --directions outbound,inbound,bidir --no-profile"
            )
            print(machine.succeed(command, timeout=dt.timedelta(seconds=${toString (4 * duration + 80)})))
            row = {"trial": trial, "version": version}
            for direction in ["plain-bidir", "outbound", "inbound", "bidir"]:
                data = json.loads(machine.succeed(f"cat {output}/{direction}.json"))
                assert not data.get("error"), data.get("error")
                end = data["end"]
                row[direction] = end["sum_received"]["bits_per_second"] / 1e9
                if direction in ["plain-bidir", "bidir"]:
                    row[direction + "-reverse"] = end["sum_received_bidir_reverse"]["bits_per_second"] / 1e9
                    row[direction + "-total"] = row[direction] + row[direction + "-reverse"]
            runs.append(row)
            print("THROUGHPUT_RESULT " + json.dumps(row), flush=True)
            machine.copy_from_machine(output)
    metrics = ["outbound", "inbound", "bidir", "bidir-reverse", "bidir-total", "plain-bidir-total"]
    medians = {
        version: {metric: statistics.median(row[metric] for row in runs if row["version"] == version) for metric in metrics}
        for version in clients
    }
    paired_changes = {}
    for metric in metrics:
        changes = []
        for trial in range(1, ${toString (repeats + 1)}):
            pair = {row["version"]: row[metric] for row in runs if row["trial"] == trial}
            changes.append(100 * (pair["after"] / pair["before"] - 1))
        paired_changes[metric] = changes
    summary = {
        "settings": {"cores": ${toString cores}, "streams": ${toString streams}, "duration": ${toString duration}, "trials": ${toString repeats}},
        "runs": runs, "medians_gbps": medians, "paired_changes_pct": paired_changes,
    }
    payload = json.dumps(summary, indent=2) + "\n"
    machine.succeed("printf %s " + shlex.quote(payload) + " > /tmp/throughput-summary.json")
    machine.copy_from_machine("/tmp/throughput-summary.json")
    print("THROUGHPUT_SUMMARY " + json.dumps(summary), flush=True)
  '';
}
