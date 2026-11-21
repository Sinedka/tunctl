{
  programs.vpnctl = {
    enable = true;
    syncOnLogin = true;
    settings = {
      theme = "dark";
      diagnostics = { pingTarget = "1.1.1.1"; pingInterval = 5; };
      routing = {
        directIPs = [ "1.1.1.1/32" ];
        directDomains = [ "example.org" ];
        applications = [
          { name = "firefox"; action = "direct"; enabled = true; }
          { name = "telegram-desktop"; action = "direct"; enabled = true; }
          { name = "steam"; action = "vpn"; enabled = true; }
        ];
      };
    };
  };
}
