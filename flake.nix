{
  description = "A lightweight ranet client";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { nixpkgs, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      benchmarkIperf = import ./integration/iperf3.nix { inherit pkgs; };
      ranet-lite = pkgs.buildGoModule {
        pname = "ranet-lite";
        version = "0.1.0";
        src = ./.;
        vendorHash = "sha256-29o8/jPaEReTYPKrNTjIHoeRfxjcMrvLwXm3oVprW6w=";
        subPackages = [ "cmd/ranet-lite" ];
      };
      integration =
        args:
        pkgs.testers.runNixOSTest (
          import ./integration/nixos-test.nix (
            {
              inherit pkgs;
              ranetLite = ranet-lite;
            }
            // args
          )
        );
    in
    {
      packages.${system} = {
        inherit ranet-lite;
        iperf3-benchmark = benchmarkIperf;
        default = ranet-lite;
        integration-profile = integration {
          cores = 4;
          profile = true;
        };
        namespace-profile = pkgs.testers.runNixOSTest (
          import ./integration/nixos-performance.nix {
            inherit pkgs benchmarkIperf;
            ranetLite = ranet-lite;
          }
        );
      };

      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          go
          python3
          iproute2
          util-linux
          iputils
          strongswan
          bird3
          benchmarkIperf
          ethtool
          pprof
        ];
      };

      checks.${system} = {
        unit = ranet-lite.overrideAttrs {
          name = "ranet-lite-unit-tests";
          checkPhase = ''
            runHook preCheck
            go test -race ./...
            runHook postCheck
          '';
        };
        integration = integration { };
        integration-multicore = integration { cores = 4; };
      };
    };
}
