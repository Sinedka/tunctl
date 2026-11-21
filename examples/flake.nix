{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    vpnctl.url = "git+file:///home/sinedka/tunctl";
    vpnctl.inputs.nixpkgs.follows = "nixpkgs";
    home-manager.follows = "vpnctl/home-manager";
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
