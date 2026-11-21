{
  description = "Terminal OpenVPN manager for NixOS";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.home-manager.url = "github:nix-community/home-manager/master";
  inputs.home-manager.inputs.nixpkgs.follows = "nixpkgs";
  outputs =
    {
      self,
      nixpkgs,
      home-manager,
    }:
    let
      each = nixpkgs.lib.genAttrs [
        "x86_64-linux"
        "aarch64-linux"
      ];
      package = system: self.packages.${system}.vpnctl;
      inject = file: { pkgs, lib, ... }: {
        imports = [ file ];
        _module.args.vpnctlDefault = package pkgs.stdenv.hostPlatform.system;
      };
    in
    {
      packages = each (system: rec {
        vpnctl = nixpkgs.legacyPackages.${system}.callPackage ./nix/package.nix { };
        default = vpnctl;
      });
      apps = each (system: {
        default = {
          type = "app";
          program = "${package system}/bin/vpnctl";
        };
      });
      devShells = each (system: {
        default = nixpkgs.legacyPackages.${system}.mkShell { inputsFrom = [ (package system) ]; };
      });
      nixosModules.default = inject ./nix/modules/nixos/vpnctl.nix;
      homeModules.default = inject ./nix/modules/home-manager/vpnctl.nix;
      homeManagerModules = self.homeModules;
      checks = each (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          inherit (self.packages.${system}) vpnctl;
          vm = pkgs.testers.runNixOSTest (import ./nix/tests/vm.nix self);
          home =
            (home-manager.lib.homeManagerConfiguration {
              inherit pkgs;
              modules = [
                self.homeModules.default
                {
                  home.username = "tester";
                  home.homeDirectory = "/home/tester";
                  home.stateVersion = "25.11";
                  programs.vpnctl = {
                    enable = true;
                    settings.routing = {
                      directIPs = [ "192.0.2.0/24" ];
                      directDomains = [ "example.org" ];
                      applications = [
                        {
                          name = "firefox";
                          action = "direct";
                        }
                      ];
                    };
                  };
                }
              ];
            }).activationPackage;
        }
      );
    };
}
