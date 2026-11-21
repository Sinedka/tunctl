{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    home-manager.url = "github:nix-community/home-manager";
    home-manager.inputs.nixpkgs.follows = "nixpkgs";
    vpnctl = {
      url = "github:sinedka/tunctl";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.home-manager.follows = "home-manager";
    };
  };

  outputs = inputs@{ nixpkgs, home-manager, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ./configuration.nix
        inputs.vpnctl.nixosModules.default
        {
          services.vpnctl = {
            enable = true;
            operators = [ "alice" ];
            policyUser = "alice";
            routing.killSwitch = false;
          };
        }
        home-manager.nixosModules.home-manager
        {
          home-manager.users.alice = {
            imports = [ inputs.vpnctl.homeModules.default ];
            programs.vpnctl.enable = true;
            home.stateVersion = "25.11";
          };
        }
      ];
    };
  };
}
