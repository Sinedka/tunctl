args@{
  config,
  lib,
  pkgs,
  vpnctlDefault,
  ...
}:
let
  cfg = config.programs.vpnctl;
  opt =
    type: default: description:
    lib.mkOption { inherit type default description; };
  inherit (lib) types;
  apps = cfg.settings.routing.applications;
  onNixOS = args ? osConfig && args.osConfig ? system && args.osConfig.system ? nixos;
  binary = "${cfg.package}/bin/vpnctl";
in
{
  options.programs.vpnctl = {
    enable = lib.mkEnableOption "VPNCTL terminal client";
    package = opt types.package vpnctlDefault "VPNCTL package.";
    syncOnLogin = opt types.bool false "Send merged routing rules to the privileged backend at login.";
    settings = {
      autolaunch = opt types.bool (onNixOS && (args.osConfig.services.vpnctl.autolaunch or false || args.osConfig.services.vpnctl.openvpn.autoConnect or false)) "Start the last successful profile at system boot.";
      theme = opt (types.enum [
        "dark"
        "light"
      ]) "dark" "Terminal color palette.";
      diagnostics.publicIPUrl =
        opt (types.strMatching "https://.*") "https://api64.ipify.org"
          "HTTPS endpoint returning the caller IP.";
      diagnostics.downloadUrl =
        opt (types.strMatching "https://.*") "https://speed.cloudflare.com/__down?bytes=1048576"
          "HTTPS endpoint serving exactly one MiB.";
      diagnostics.uploadUrl =
        opt (types.strMatching "https://.*") "https://speed.cloudflare.com/__up"
          "HTTPS endpoint accepting a one MiB POST.";
      diagnostics.pingTarget = opt types.str "1.1.1.1" "Default ping destination.";
      diagnostics.pingInterval =
        opt (types.ints.between 1 3600) 5
          "Dashboard refresh interval in seconds.";
      routing.directIPs = opt (types.listOf (
        types.strMatching "[a-fA-F0-9.:]+(/[0-9]{1,3})?"
      )) [ ] "Host-wide IP exceptions submitted by the delegated operator.";
      routing.directDomains = opt (types.listOf types.str) [ ] "Domain exceptions submitted to dnsmasq.";
      routing.applications = opt (types.listOf (
        types.submodule {
          options = {
            name = lib.mkOption {
              type = types.strMatching "[a-z0-9][a-z0-9_-]*";
              description = "Application executable and launcher name.";
            };
            action = opt (types.enum [
              "vpn"
              "direct"
            ]) "vpn" "Socket routing policy.";
            enabled = opt types.bool true "Apply the routing rule.";
            desktopId = opt (types.nullOr (
              types.strMatching "[A-Za-z0-9_.-]+"
            )) null "Override the desktop file ID.";
          };
        }
      )) [ ] "Applications launched in managed user slices.";
    };
  };
  config = lib.mkIf cfg.enable {
    home.packages = [ cfg.package ];
    xdg.configFile."vpnctl/${if onNixOS then "locked" else "settings"}.json".source = pkgs.runCommand "vpnctl-settings.json" { } ''
      cp ${pkgs.writeText "vpnctl-settings-input.json" (builtins.toJSON cfg.settings)} "$out"
      ${binary} check-settings "$out"
    '';
    xdg.desktopEntries = builtins.listToAttrs (
      map (
        app:
        lib.nameValuePair
          (
            if app.desktopId != null then
              app.desktopId
            else if app.name == "telegram-desktop" then
              "org.telegram.desktop"
            else
              app.name
          )
          {
            name = app.name;
            exec = "${binary} launch ${app.name} ${app.name} %U";
            terminal = false;
          }
      ) apps
    );
    systemd.user.services.vpnctl-sync = lib.mkIf cfg.syncOnLogin {
      Unit.Description = "Submit VPNCTL routing preferences";
      Service = {
        Type = "oneshot";
        ExecStart = "${binary} sync";
      };
      Install.WantedBy = [ "default.target" ];
    };
  };
}
