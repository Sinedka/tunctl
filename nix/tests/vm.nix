self: {
  name = "vpnctl";
  nodes.machine = { pkgs, ... }: {
    imports = [ self.nixosModules.default ];
    services.vpnctl = {
      enable = true;
      operators = [ "tester" ];
      policyUser = "tester";
      dns = {
        enable = true;
        bootstrapDNS = [ "192.0.2.1" ];
        upstreams = [ "10.44.0.1" ];
      };
      routing.directDomains = [ "direct.test" ];
      routing.directIPs = [ "192.0.2.1/32" ];
    };
    environment.etc."http-peer.py".source = ./http-peer.py;
    environment.etc."test-peer.sh".source = ./peer.sh;
    users.users.observer = {
      isNormalUser = true;
      extraGroups = [ "vpnctl" ];
    };
    users.users.tester = {
      isNormalUser = true;
      linger = true;
    };
    environment.systemPackages = [
      pkgs.iproute2
      pkgs.nftables
      pkgs.openvpn
      pkgs.openssl
      pkgs.dnsutils
      pkgs.dnsmasq
      pkgs.jq
      pkgs.python3
      pkgs.curl
    ];
  };
  testScript = ''
    machine.start()
    machine.wait_for_unit("vpnctl.socket")
    machine.succeed("su - tester -c 'vpnctl status' | grep inactive")
    code, denial = machine.execute("su - observer -c 'vpnctl status' 2>&1")
    assert code != 0 and "unauthorized peer" in denial, denial
    machine.fail("su -s /bin/sh nobody -c 'vpnctl status'")
    machine.succeed("nft list table inet vpnctl | grep 0x00007652")
    machine.succeed("ip -4 rule show | grep 'lookup 30201'")
    machine.succeed("ip -6 rule show | grep 'lookup 30201'")
    machine.succeed("ip netns add peer; ip link add uplink type veth peer name end; ip link set end netns peer; ip addr add 192.0.2.10/24 dev uplink; ip link set uplink up; ip -n peer addr add 192.0.2.1/24 dev end; ip -n peer addr add 192.0.2.2/24 dev end; ip -n peer link set end up")
    machine.succeed("ping -c1 -W1 192.0.2.1")
    machine.succeed("ip -6 addr add fd42::10/64 dev uplink nodad; ip -n peer -6 addr add fd42::2/64 dev end nodad")
    machine.fail("ping -6 -c1 -W1 fd42::2")
    machine.fail("ping -c1 -W1 192.0.2.2")
    machine.succeed("su - tester -c 'vpnctl sync'")
    machine.succeed("bash /etc/test-peer.sh")
    machine.succeed("su - tester -c 'vpnctl import ~/bundle'")
    machine.succeed("su - tester -c 'TERM=xterm printf 2q | TERM=xterm script -qec vpnctl /dev/null' | grep VPNCTL")

    machine.succeed("su - tester -c 'vpnctl connect first'")
    machine.succeed("su - tester -c 'vpnctl status' | jq -e '.state == \"connected\"'")
    machine.succeed("ping -c1 -W2 10.44.0.1")
    machine.succeed("su - tester -c 'vpnctl diag ping 10.44.0.1 vpn' | jq -e '.received == 4 and .avg_ms >= 0'")
    for mode in ["download","upload"]:
        machine.succeed(f"su - tester -c 'CURL_CA_BUNDLE=~/bundle/ca.crt vpnctl diag {mode} 10.44.0.1 vpn --confirm' | grep Mbps")
    machine.succeed("su - tester -c 'CURL_CA_BUNDLE=~/bundle/ca.crt vpnctl diag public-ip 10.44.0.1 vpn' | grep 10.44.0.2")
    machine.succeed("ip link set uplink down; ip link set uplink name moved; ip link set moved up")
    machine.wait_until_succeeds("ping -c1 -W1 10.44.0.1")
    machine.succeed("systemctl kill --kill-whom=main --signal=KILL vpnctl-tunnel.service")
    machine.wait_until_succeeds("su - tester -c 'vpnctl status' | jq -e '.state == \"connected\"'")

    machine.succeed("ip route get 203.0.113.12 mark 0x7651 | grep vpnctl0")
    machine.succeed("dig +short @127.0.0.1 direct.test | grep 192.0.2.2")
    machine.succeed("nft get element inet vpnctl domains4 '{ 192.0.2.2 }'")
    machine.succeed("curl -fsS --cacert /tmp/vpntest/ca.crt https://192.0.2.2:8443/ip | grep 192.0.2.10")
    machine.succeed("sed -i 's/10.44.0.1/192.0.2.2/g' /home/tester/.config/vpnctl/settings.json")
    machine.succeed("su - tester -c 'XDG_RUNTIME_DIR=/run/user/$(id -u) CURL_CA_BUNDLE=~/bundle/ca.crt vpnctl diag upload 192.0.2.2 direct --confirm' | grep Mbps")
    machine.succeed("su - tester -c 'vpnctl connect second'")
    machine.fail("su - tester -c 'vpnctl connect broken'")
    machine.succeed("su - tester -c 'vpnctl status' | jq -e '.state == \"connected\" and .selected == \"second\"'")
    machine.succeed("su - tester -c 'vpnctl disconnect'")
    machine.wait_until_fails("nft get element inet vpnctl domains4 '{ 192.0.2.2 }'")
    machine.fail("ping -c1 -W1 192.0.2.2")
    machine.succeed("mkdir -p /home/tester/.config/vpnctl; echo '{\"routing\":{\"applications\":[{\"name\":\"fixture\",\"action\":\"direct\"}]}}' >/home/tester/.config/vpnctl/settings.json; chown -R tester:users /home/tester/.config")
    machine.succeed("su - tester -c 'vpnctl sync'")
    machine.succeed("su - tester -c 'XDG_RUNTIME_DIR=/run/user/$(id -u) vpnctl launch fixture ping -c1 -W2 192.0.2.2'")
    machine.succeed("echo '{\"routing\":{\"directIPs\":[\"192.0.2.2/32\"],\"applications\":[{\"name\":\"locked\",\"action\":\"vpn\"}]}}' >/home/tester/.config/vpnctl/settings.json")
    machine.succeed("su - tester -c 'vpnctl sync'")
    machine.succeed("ping -c1 -W1 192.0.2.2")
    machine.fail("su - tester -c 'XDG_RUNTIME_DIR=/run/user/$(id -u) vpnctl launch locked ping -c1 -W1 192.0.2.2'")
    machine.succeed("su - tester -c 'vpnctl status' | jq -e '.ruleStates[0] == \"applied\"'")
    machine.succeed("echo '{\"routing\":{\"directIPs\":[\"10.0.0.0/44\"]}}' >/home/tester/.config/vpnctl/settings.json")
    machine.fail("su - tester -c 'vpnctl sync'")
    machine.succeed("ping -c1 -W1 192.0.2.2")
  '';
}
