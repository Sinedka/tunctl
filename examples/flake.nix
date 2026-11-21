{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    vpnctl.url = "github:sinedka/tunctl";
    vpnctl.inputs.nixpkgs.follows = "nixpkgs";
    home-manager.url = "github:nix-community/home-manager/master";
    home-manager.inputs.nixpkgs.follows = "nixpkgs";
    vpnctl.inputs.home-manager.follows = "home-manager";
  };
  outputs = { nixpkgs, vpnctl, home-manager, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ./configuration.nix
        vpnctl.nixosModules.default
        ./nixos.nix
        home-manager.nixosModules.home-manager
        {
          home-manager.users.alice.imports = [ vpnctl.homeManagerModules.default ./home.nix ];
        }
      ];
    };
  };
}
