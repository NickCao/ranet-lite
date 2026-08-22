{ pkgs, ranetLite }:

let
  gatewayTunnel = "fd00:99::1";
  clientTunnel = "fd00:88::2";
  publicKey = builtins.readFile ./org-pub.pem;

  common = {
    virtualisation.vlans = [ 1 ];
    networking = {
      useNetworkd = true;
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

        systemd.network = {
          netdevs."20-swan0" = {
            netdevConfig = {
              Name = "swan0";
              Kind = "xfrm";
            };
            xfrmConfig.InterfaceId = 1;
          };
          networks = {
            # The test network module already defines 40-eth1; extend it to
            # create swan0 with eth1 as its underlying device.
            "40-eth1".networkConfig.Xfrm = "swan0";
            "40-swan0" = {
              matchConfig.Name = "swan0";
              linkConfig = {
                Multicast = true;
                RequiredForOnline = false;
              };
              networkConfig.ConfigureWithoutCarrier = true;
              addresses = [
                { Address = "fe80::1/64"; }
                { Address = "${gatewayTunnel}/64"; }
              ];
            };
          };
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
          requires = [ "network-online.target" ];
          after = [ "network-online.target" ];
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
          requires = [ "network-online.target" ];
          after = [ "network-online.target" ];
        };

        systemd.services.iperf3 = {
          description = "iperf3 server for the ranet integration test";
          wantedBy = [ "multi-user.target" ];
          requires = [ "network-online.target" ];
          after = [ "network-online.target" ];
          serviceConfig = {
            ExecStart = "${pkgs.iperf3}/bin/iperf3 --server --bind ${gatewayTunnel}";
            Restart = "on-failure";
          };
        };
      };

    client =
      { nodes, ... }:
      {
        imports = [ common ];

        boot.kernelModules = [ "tun" ];
        environment.systemPackages = with pkgs; [
          iperf3
          iproute2
        ];

        systemd.network = {
          netdevs."20-ranet0" = {
            netdevConfig = {
              Name = "ranet0";
              Kind = "tun";
            };
            tunConfig = {
              PacketInfo = false;
              VNetHeader = true;
            };
          };
          networks."40-ranet0" = {
            matchConfig.Name = "ranet0";
            linkConfig = {
              MTUBytes = 1400;
              RequiredForOnline = false;
            };
            networkConfig.ConfigureWithoutCarrier = true;
            addresses = [ { Address = "${clientTunnel}/128"; } ];
            routes = [ { Destination = "fd00:99::/64"; } ];
          };
        };

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
                      address = nodes.client.networking.primaryIPAddress;
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
                      address = nodes.gateway.networking.primaryIPAddress;
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

    timeout = dt.timedelta(seconds=30)

    start_all()

    try:
        gateway.wait_for_unit("systemd-networkd-wait-online.service")
        gateway.wait_for_unit("strongswan-swanctl.service")
        gateway.wait_for_unit("bird.service")
        gateway.wait_for_unit("iperf3.service")
        client.wait_for_unit("ranet-lite.service")

        client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)

        print(client.succeed("iperf3 --client ${gatewayTunnel} --time 5"))
        print(client.succeed("iperf3 --client ${gatewayTunnel} --time 5 --reverse"))
    finally:
        print(gateway.succeed("swanctl --list-sas"))
        print(gateway.succeed("birdc show babel neighbors"))
        print(gateway.succeed("birdc show babel routes"))
  '';
}
