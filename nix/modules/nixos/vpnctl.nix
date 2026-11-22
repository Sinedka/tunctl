{
  config,
  lib,
  pkgs,
  vpnctlDefault,
  ...
}:
let
  inherit (lib) mkOption types;
  cfg = config.services.vpnctl;
  opt =
    type: default: description:
    mkOption { inherit type default description; };
  address = types.strMatching "[0-9a-fA-F.:]+(/[0-9]{1,3})?";
  domain = types.strMatching "(\\*\\.)?[a-zA-Z0-9-]+(\\.[a-zA-Z0-9-]+)*";
  direct =
    ip: "${if lib.hasInfix ":" ip then "ip6" else "ip"} daddr ${ip} meta mark set 0x7652 accept";
  daemon = "${cfg.package}/bin/vpnctl-daemon";
  ip = "${pkgs.iproute2}/bin/ip";
  networkHelper = "${pkgs.python3}/bin/python3 ${../../../packaging/network.py.in}";
  unit = "vpnctl-tunnel";
  delegatedHome = lib.attrByPath [ "home-manager" "users" (if cfg.policyUser == null then "" else cfg.policyUser) "programs" "vpnctl" ] {} config;
  bootDefault = cfg.autolaunch || cfg.openvpn.autoConnect;
  dns = cfg.routing.directDomains != [ ] || cfg.dns.enable;
  ready = pkgs.writeShellScript "vpnctl-ready" ''
    set -eu
    # Replies entering the tunnel have no output fwmark. Strict kernel RPF
    # can therefore look up their source via the physical default route.
    tun_rpf=/proc/sys/net/ipv4/conf/vpnctl0/rp_filter
    read -r all_rpf < /proc/sys/net/ipv4/conf/all/rp_filter
    read -r current_rpf < "$tun_rpf"
    if [ "$all_rpf" -lt 2 ] && [ "$current_rpf" -lt 2 ] && { [ "$current_rpf" = 1 ] || [ "$all_rpf" = 1 ]; }; then
      echo 2 > "$tun_rpf"
    fi
    ${ip} -4 route replace default dev vpnctl0 table 30201 metric 10
    if ${ip} -6 addr show dev vpnctl0 scope global | ${pkgs.gnugrep}/bin/grep -q inet6; then
      ${ip} -6 route replace default dev vpnctl0 table 30201 metric 10
    fi
  '';
  # Both families have a terminal fallback for the entire OpenVPN lifetime.
  fallback =
    op:
    pkgs.writeShellScript "vpnctl-fallback-${op}" ''
      set -eu
      for family in -4 -6; do
        ${ip} "$family" route ${op} unreachable default metric 42760 table 30201 ${
          lib.optionalString (op == "del") "|| true"
        }
      done
    '';
in
{
  options.services.vpnctl = {
    enable = lib.mkEnableOption "VPNCTL terminal OpenVPN manager";
    package = opt types.package vpnctlDefault "Package containing the daemon and client.";
    operators =
      opt (types.listOf types.str) [ ]
        "Trusted accounts allowed to import and select VPN endpoints for the entire host.";
    policyUser =
      opt (types.nullOr types.str) null
        "Single trusted operator allowed to submit host-wide routing exceptions.";
    openvpn.enable = opt types.bool true "Enable the managed OpenVPN client.";
    autolaunch = opt types.bool false "Start the last successful VPN profile on boot by default.";
    openvpn.autoConnect = opt types.bool false "Connect the last selected profile on boot.";
    routing.default = opt (types.enum [ "vpn" ]) "vpn" "Default action during a connection.";
    routing.killSwitch =
      opt types.bool true
        "Block ordinary host output outside the tunnel even while disconnected.";
    routing.directIPs =
      opt (types.listOf address) [ ]
        "Administrator-defined physical-network destinations.";
    routing.directDomains =
      opt (types.listOf domain) [ ]
        "Names and subdomains learned by local dnsmasq.";
    dns.enable = opt types.bool false "Configure the NixOS dnsmasq local resolver explicitly.";
    dns.bootstrapDNS = opt (types.listOf (types.strMatching "[0-9a-fA-F.:]+")) [
      "9.9.9.9"
    ] "Physical DNS servers used only for OpenVPN endpoint hostnames.";
    dns.upstreams = opt (types.listOf (types.strMatching "[0-9a-fA-F.:]+")) [
      "9.9.9.9"
    ] "DNS upstream addresses routed through the VPN.";
  };
  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.openvpn.enable;
        message = "vpnctl requires openvpn.enable.";
      }
      {
        assertion = cfg.policyUser == null || builtins.elem cfg.policyUser cfg.operators;
        message = "policyUser must be an operator.";
      }
      {
        assertion = !config.networking.nftables.flushRuleset;
        message = "vpnctl requires nftables.flushRuleset = false.";
      }
      {
        assertion = !dns || !config.services.resolved.enable;
        message = "Choose dnsmasq or resolved explicitly before enabling vpnctl DNS.";
      }
    ];
    environment.systemPackages = [ cfg.package ];
    users.groups.vpnctl.members = cfg.operators;
    environment.etc."vpnctl/locked.json" = lib.mkIf (!(delegatedHome.enable or false)) {
      text = builtins.toJSON { autolaunch = bootDefault; };
    };
    environment.etc."vpnctl/policy.json".text = builtins.toJSON {
      inherit (cfg) operators;
      inherit dns;
      autolaunch = if delegatedHome.enable or false then delegatedHome.settings.autolaunch else bootDefault;
      inherit (cfg.dns) upstreams bootstrapDNS;
      policyUser = if cfg.policyUser == null then "" else cfg.policyUser;
      inherit (cfg.routing) killSwitch directIPs directDomains;
    };
    systemd.tmpfiles.rules = [
      "d /var/lib/vpnctl 0700 root root -"
      "d /run/vpnctl 0755 root root -"
      "f /run/vpnctl/dns.lock 0644 root root -"
    ];
    networking.nftables.enable = true;
    networking.nftables.tables.vpnctl = {
      family = "inet";
      content = builtins.replaceStrings [ "%DIRECT_IPS%" "%GUARD%" ] [
        (lib.concatMapStringsSep "\n" direct cfg.routing.directIPs)
        (lib.optionalString cfg.routing.killSwitch ''oifname != { "lo", "vpnctl0" } meta mark != { 0x7652, 0x7653 } counter drop'')
      ] (builtins.readFile ../../../packaging/routing.nft.in);
    };
    services.dnsmasq = lib.mkIf dns {
      enable = true;
      resolveLocalQueries = true;
      settings = {
        conf-file = [ ];
        no-resolv = true;
        server = [ "127.0.0.1#53071" ];
        listen-address = "127.0.0.1";
        bind-interfaces = true;
        cache-size = 0;
        max-ttl = 300;
      };
    };
    networking.firewall.extraReversePathFilterRules = ''iifname "vpnctl0" accept'';
    systemd.services.vpnctl-dns = lib.mkIf dns {
      wantedBy = [ "multi-user.target" ];
      after = [ "vpnctl-routing.service" ];
      requires = [ "vpnctl-routing.service" ];
      before = [ "dnsmasq.service" ];
      path = [ pkgs.nftables ];
      serviceConfig = {
        ExecStart = "${cfg.package}/libexec/vpnctl-dns";
        DynamicUser = true;
        AmbientCapabilities = [ "CAP_NET_ADMIN" ];
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        Restart = "on-failure";
      };
    };
    systemd.services.vpnctl-routing = {
      wantedBy = [ "multi-user.target" ];
      requiredBy = [
        "network-pre.target"
        "NetworkManager.service"
        "systemd-networkd.service"
      ];
      before = [
        "network-pre.target"
        "NetworkManager.service"
        "systemd-networkd.service"
      ];
      after = [ "nftables.service" ];
      requires = [ "nftables.service" ];
      unitConfig.DefaultDependencies = false;
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        for family in -4 -6; do
          if ! ${ip} "$family" rule show | ${pkgs.gnugrep}/bin/grep -Eq '^30201:.*fwmark 0x7651 lookup 30201$'; then
            ${ip} "$family" rule add pref 30201 fwmark 0x7651 lookup 30201
          fi
        done
      '';
      preStop = ''
        for family in -4 -6; do
          ${ip} "$family" rule del pref 30201 fwmark 0x7651 lookup 30201 || true
        done
      '';
    };
    systemd.services.vpnctl-session = {
      after = [ "vpnctl-routing.service" ];
      requires = [ "vpnctl-routing.service" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${pkgs.nftables}/bin/nft -f ${pkgs.writeText "vpnctl-session.nft" ''
          destroy table inet vpnctl_session
          table inet vpnctl_session {
            chain guard {
              type filter hook output priority filter; policy accept;
              oifname != { "lo", "vpnctl0" } meta mark != { 0x7652, 0x7653 } counter drop
            }
          }
        ''}";
        ExecStop = "${pkgs.nftables}/bin/nft destroy table inet vpnctl_session";
      };
    };
    systemd.services.vpnctl-autolaunch = {
      wantedBy = [ "multi-user.target" ];
      after = [ "vpnctl-routing.service" "network-online.target" ];
      wants = [ "network-online.target" ];
      requires = [ "vpnctl-routing.service" ];
      restartIfChanged = false;
      serviceConfig = { Type = "oneshot"; RemainAfterExit = true; ExecStart = "${daemon} autolaunch"; };
    };
    systemd.services.${unit} = {
      path = [ pkgs.iproute2 pkgs.nftables ];

      after = [
        "network-online.target"
        "vpnctl-session.service"
      ];
      requires = [ "vpnctl-session.service" ];
      wants = [ "network-online.target" ];
      unitConfig.ConditionPathExists = [
        "|/var/lib/vpnctl/active.ovpn"
        "|/run/vpnctl/pending.ovpn"
      ];
      serviceConfig = {
        RuntimeDirectory = "vpnctl-tunnel";
        RuntimeDirectoryMode = "0700";
        Type = "exec";
        TimeoutStartSec = 35;
        TimeoutStopSec = 6;
        Restart = "always";
        RestartSec = 3;
        ExecStartPre = [
          (fallback "replace")
          "${cfg.package}/libexec/vpnctl-prepare"
        ];
        ExecStartPost = [
          "${daemon} wait-ready"
          ready
          "${networkHelper} source-ready"
          "-${daemon} routes-ready"
        ];
        ExecStopPost = [
          "-${daemon} tunnel-stopped"
          (fallback "del")
          "${networkHelper} source-clear"
        ];
        ExecStart = lib.concatStringsSep " " [
          "${pkgs.openvpn}/sbin/openvpn"
          "--config /run/vpnctl-tunnel/client.ovpn"
          "--management /run/vpnctl-tunnel/management unix"
          "--mark 30291"
          "--route-nopull"
          "--route-noexec"
          "--script-security 1"
          "--remap-usr1 SIGTERM --disable-dco"
          "--verb 1"
          "--pull-filter accept ifconfig"
          "--pull-filter accept topology"
          "--pull-filter accept ping"
          "--pull-filter accept peer-id"
          "--pull-filter accept cipher"
          "--pull-filter accept protocol-flags"
          "--pull-filter ignore ''"
        ];
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
        CapabilityBoundingSet = [
          "CAP_NET_ADMIN"
          "CAP_NET_RAW"
        ];
        DevicePolicy = "closed";
        DeviceAllow = [ "/dev/net/tun rw" ];
      };
    };
    systemd.sockets.vpnctl = {
      wantedBy = [ "sockets.target" ];
      socketConfig = {
        ListenStream = "/run/vpnctl/control.sock";
        Accept = true;
        SocketMode = "0660";
        SocketGroup = "vpnctl";
        MaxConnections = 16;
      };
    };
    systemd.services."vpnctl@" = {
      after = [ "vpnctl-routing.service" ];
      requires = [ "vpnctl-routing.service" ];
      serviceConfig = {
        ExecStart = daemon;
        StandardInput = "socket";
        StandardOutput = "null";
        UMask = "0077";
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        ReadWritePaths = [ "/run/vpnctl" ];
        StateDirectory = "vpnctl";
        StateDirectoryMode = "0700";
        NoNewPrivileges = true;
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
        MemoryMax = "128M";
        RuntimeMaxSec = 150;
      };
    };
    systemd.services.vpnctl-refresh = {
      after = [ "vpnctl-routing.service" ];
      requires = [ "vpnctl-routing.service" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${daemon} refresh";
        ReadWritePaths = [ "/run/vpnctl" ];
        StateDirectory = "vpnctl";
        StateDirectoryMode = "0700";
      };
    };
    systemd.timers.vpnctl-refresh = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "3s";
        OnUnitInactiveSec = "10s";
        AccuracySec = "1s";
      };
    };
  };
}
