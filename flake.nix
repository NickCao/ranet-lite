{
  description = "A lightweight ranet client";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { nixpkgs, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      ranet-lite = pkgs.buildGoModule {
        pname = "ranet-lite";
        version = "0.1.0";
        src = ./.;
        vendorHash = "sha256-3FRdONnzY53jXsC7j6Ig6BwjCF09Qn2PZxnqXzAYoBY=";
        subPackages = [ "cmd/ranet-lite" ];
      };
    in
    {
      packages.${system} = {
        inherit ranet-lite;
        default = ranet-lite;
      };

      checks.${system}.integration = pkgs.testers.runNixOSTest (
        import ./integration/nixos-test.nix {
          inherit pkgs;
          ranetLite = ranet-lite;
        }
      );
    };
}
