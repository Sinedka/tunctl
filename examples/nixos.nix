{
  services.vpnctl = {
    enable = true;
    operators = [ "alice" ];
    policyUser = "alice";
    openvpn = { enable = true; autoConnect = true; };
    routing = {
      default = "vpn";
      killSwitch = true;
      directIPs = [ "192.168.0.0/16" ];
      directDomains = [ "github.com" ];
    };
    dns.enable = true;
  };
}
