{ pkgs, ranetLite }:

let
  # The NixOS test driver assigns VLAN addresses by alphabetical node order.
  clientUnderlay = "192.168.1.1";
  gatewayUnderlay = "192.168.1.2";
  gatewayTunnel = "fd00:99::1";
  clientTunnel = "fd00:88::2";
  publicKey = builtins.readFile ./org-pub.pem;

  common = {
    virtualisation.vlans = [ 1 ];
    networking = {
      useDHCP = false;
      firewall.enable = false;
    };
  };
in
{
  name = "ranet-lite-integration";

  nodes = {
    gateway =
      { config, ... }:
      {
        imports = [ common ];

        boot.kernelModules = [ "xfrm_interface" ];
        environment.systemPackages = with pkgs; [
          bird2
          iperf3
          iproute2
          config.services.strongswan-swanctl.package
        ];

        environment.etc = {
          "swanctl/private/org-key.pem".source = ./org-key.pem;
          "swanctl/pubkey/org-pub.pem".source = ./org-pub.pem;
        };

        systemd.services.ranet-link = {
          description = "Ranet integration-test XFRM interface";
          wantedBy = [ "multi-user.target" ];
          before = [
            "bird.service"
            "iperf3.service"
            "strongswan-swanctl.service"
          ];
          path = [ pkgs.iproute2 ];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
          };
          script = ''
            ip link add swan0 type xfrm dev eth1 if_id 1
            ip link set swan0 up multicast on
            ip -6 address replace fe80::1/64 dev swan0
            ip -6 address replace ${gatewayTunnel}/64 dev swan0
          '';
          preStop = "ip link delete swan0";
        };

        services.strongswan-swanctl = {
          enable = true;
          strongswan.extraConfig = ''
            charon-systemd {
              port = 0
              port_nat_t = 13000
            }
          '';
          swanctl = {
            connections.ranet = {
              version = 2;
              local_addrs = [ "0.0.0.0/0" ];
              remote_addrs = [ "0.0.0.0/0" ];
              local_port = 13000;
              if_id_in = "1";
              if_id_out = "1";
              proposals = [
                "aes256gcm16-prfsha384-curve25519"
                "aes128gcm16-prfsha256-curve25519"
                "chacha20poly1305-prfsha256-curve25519"
              ];
              encap = true;
              mobike = false;
              local.main = {
                auth = "pubkey";
                pubkeys = [ "org-pub.pem" ];
                id = "O=testorg, CN=server, serialNumber=1";
              };
              remote.main = {
                auth = "pubkey";
                pubkeys = [ "org-pub.pem" ];
                id = "O=testorg, CN=client, serialNumber=2";
              };
              children.mesh = {
                mode = "tunnel";
                local_ts = [
                  "0.0.0.0/0"
                  "::/0"
                ];
                remote_ts = [
                  "0.0.0.0/0"
                  "::/0"
                ];
                esp_proposals = [
                  "aes256gcm16-noesn"
                  "aes128gcm16-noesn"
                  "chacha20poly1305-noesn"
                ];
                start_action = "none";
              };
            };
          };
        };
        systemd.services.strongswan-swanctl = {
          requires = [ "ranet-link.service" ];
          after = [ "ranet-link.service" ];
        };

        services.bird = {
          enable = true;
          package = pkgs.bird2;
          config = ''
            log stderr all;
            router id 192.0.2.1;

            protocol device {
            }

            protocol kernel kernel6 {
              ipv6 {
                import none;
                export all;
              };
            }

            protocol static test_routes {
              ipv6;
              route fd00:99::/64 blackhole;
            }

            protocol babel ranet {
              ipv6 {
                import all;
                export where source = RTS_STATIC;
              };
              randomize router id;
              interface "swan0" {
                type tunnel;
                rxcost 32;
                hello interval 500 ms;
                update interval 1 s;
                rtt cost 1024;
                rtt max 1024 ms;
                rx buffer 1500;
              };
            }
          '';
        };
        systemd.services.bird = {
          requires = [ "ranet-link.service" ];
          after = [ "ranet-link.service" ];
        };

        systemd.services.iperf3 = {
          description = "iperf3 server for the ranet integration test";
          wantedBy = [ "multi-user.target" ];
          requires = [ "ranet-link.service" ];
          after = [ "ranet-link.service" ];
          serviceConfig = {
            ExecStart = "${pkgs.iperf3}/bin/iperf3 --server --bind ${gatewayTunnel}";
            Restart = "on-failure";
          };
        };
      };

    client = {
      imports = [ common ];

      boot.kernelModules = [ "tun" ];
      environment.systemPackages = with pkgs; [
        iperf3
        iproute2
      ];

      environment.etc = {
        "ranet-lite/key.pem".source = ./org-key.pem;
        "ranet-lite/registry.json".text = builtins.toJSON [
          {
            public_key = publicKey;
            organization = "testorg";
            nodes = [
              {
                common_name = "client";
                endpoints = [
                  {
                    serial_number = "2";
                    address_family = "ip4";
                    address = clientUnderlay;
                    port = 14000;
                  }
                ];
                remarks = { };
              }
              {
                common_name = "server";
                endpoints = [
                  {
                    serial_number = "1";
                    address_family = "ip4";
                    address = gatewayUnderlay;
                    port = 13000;
                  }
                ];
                remarks = { };
              }
            ];
          }
        ];
        "ranet-lite/config.yaml".text = ''
          organization: testorg
          common_name: client
          port: 14000
          endpoints:
            - serial_number: "2"
              address_family: ip4
          private_key: /etc/ranet-lite/key.pem
          registry: /etc/ranet-lite/registry.json
          originate:
            - "${clientTunnel}/128"
          tun: ranet0
          child_rekey_interval: 0
          ike_rekey_interval: 0
          peers:
            - common_name: server
              serial_number: "1"
          babel:
            hello_interval: 500ms
            update_interval: 1s
        '';
      };

      systemd.services.ranet-lite = {
        description = "Ranet-lite integration-test client";
        wantedBy = [ "multi-user.target" ];
        wants = [ "network-online.target" ];
        after = [ "network-online.target" ];
        serviceConfig = {
          ExecStart = "${ranetLite}/bin/ranet-lite -config /etc/ranet-lite/config.yaml -log-level debug";
          Restart = "on-failure";
          AmbientCapabilities = [ "CAP_NET_ADMIN" ];
          CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
        };
      };
    };
  };

  testScript = ''
    import datetime as dt
    import json

    convergence_timeout = dt.timedelta(seconds=30)

    def dump_state():
        diagnostics = [
            (client, "client ranet", "journalctl -b -u ranet-lite.service --no-pager"),
            (client, "client routes", "ip -6 route show; ip xfrm state; ip xfrm policy"),
            (gateway, "gateway strongSwan", "journalctl -b -u strongswan-swanctl.service --no-pager; swanctl --list-sas"),
            (gateway, "gateway BIRD", "birdc show protocols all; birdc show route all"),
            (gateway, "gateway routes", "ip -6 route show; ip xfrm state; ip xfrm policy"),
        ]
        for machine, label, command in diagnostics:
            status, output = machine.execute(command)
            print(f"--- {label} (status {status}) ---\n{output}")

    start_all()

    gateway.wait_for_unit("ranet-link.service")
    gateway.wait_for_unit("strongswan-swanctl.service")
    gateway.wait_for_unit("bird.service")
    gateway.wait_for_unit("iperf3.service")
    client.wait_for_unit("ranet-lite.service")

    client.wait_until_succeeds("ip link show ranet0")
    client.succeed("ip link set ranet0 up")
    client.succeed("ip -6 address replace ${clientTunnel}/128 dev ranet0")
    client.succeed("ip -6 route replace fd00:99::/64 dev ranet0")
    client.succeed("ip -6 route get ${gatewayTunnel} | grep -F 'dev ranet0'")

    try:
        client.wait_until_succeeds(
            "journalctl -u ranet-lite.service --no-pager | "
            "grep -F 'msg=\"babel route installed\"' | "
            "grep -F 'route=fd00:99::/64'",
            timeout=convergence_timeout,
        )
        gateway.wait_until_succeeds(
            "birdc show route for ${clientTunnel}/128 | grep -F '${clientTunnel}/128'",
            timeout=convergence_timeout,
        )
        report = json.loads(client.wait_until_succeeds(
            "iperf3 --client ${gatewayTunnel} -6 --time 3 --connect-timeout 2000 --json",
            timeout=convergence_timeout,
        ))
    except Exception:
        dump_state()
        raise

    received = report["end"]["sum_received"]
    assert received["bytes"] > 0, report
    assert received["bits_per_second"] > 0, report
    print(f'iperf3 bandwidth: {received["bits_per_second"] / 1_000_000:.2f} Mbit/s')
  '';
}
