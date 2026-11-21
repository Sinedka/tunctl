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

    # Hold the peer until after the client process starts but before any TLS reply.
    # The peer also represents an internet host. An unmarked reverse lookup
    # for its address chooses the physical link, unlike the VPN-marked request.
    machine.succeed("sysctl -qw net.ipv4.conf.all.rp_filter=1; ip -n peer link set lo up; ip -n peer addr add 198.51.100.8/32 dev lo; ip route add 198.51.100.8/32 dev uplink")
    machine.succeed("kill -STOP $(cat /tmp/vpntest/server.pid)")
    machine.succeed("systemd-run --unit=test-vpnctl-connect --property=User=tester --property=RemainAfterExit=yes -- $(command -v vpnctl) connect first")
    machine.wait_until_succeeds("test -S /run/vpnctl-tunnel/management && test $(systemctl show -p SubState --value vpnctl-tunnel) = start-post")
    machine.succeed("test ! -e /sys/class/net/vpnctl0 && ip route show table 30201 | grep 'unreachable default'")
    machine.fail("ping -c1 -W1 192.0.2.2")
    machine.succeed("su - tester -c 'timeout 5 vpnctl logs' | grep 'OpenVPN: waiting for handshake'")
    machine.fail("su - observer -c 'vpnctl logs'")
    machine.succeed("su - tester -c 'logger -t vpnctl-events test-user-injected-line'")
    machine.succeed("kill -CONT $(cat /tmp/vpntest/server.pid)")
    machine.wait_for_unit("vpnctl-tunnel.service")
    machine.wait_until_succeeds("test $(systemctl show -p SubState --value test-vpnctl-connect) = exited")
    machine.succeed("test $(systemctl show -p ExecMainStatus --value test-vpnctl-connect) = 0")
    machine.succeed("su - tester -c 'vpnctl status' | jq -e '.state == \"connected\"'")
    machine.succeed("ping -c1 -W2 10.44.0.1")
    machine.succeed("test $(cat /proc/sys/net/ipv4/conf/vpnctl0/rp_filter) = 2 && test $(cat /proc/sys/net/ipv4/conf/all/rp_filter) = 1")
    machine.succeed("ip route get 198.51.100.8 mark 0x7651 | grep vpnctl0 && ping -c1 -W2 198.51.100.8")
    machine.succeed("ip route get 198.51.100.8 | grep 'dev vpnctl0.*src 10.44.0.2'")
    machine.succeed("su - tester -c 'curl -4fsS --noproxy \"*\" --max-time 5 --cacert ~/bundle/ca.crt https://198.51.100.8:8443/ip' | grep -Fx 10.44.0.2")
    machine.succeed("getent ahostsv4 direct.test | grep 192.0.2.2")
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
    logs = machine.succeed("su - tester -c 'vpnctl logs'")
    for expected in ["Connect: requested profile first", "Profile: stored checksum verified",
                     "DNS: bootstrap returned", "OpenVPN state: CONNECTED", "Routing: tunnel routes installed",
                     "Switch: previous profile", "Rollback: restarting previous profile second",
                     "previous tunnel restored"]:
        assert expected in logs, (expected, logs)
    assert "test-user-injected-line" not in logs and "PRIVATE KEY" not in logs
    machine.succeed("su - tester -c 'vpnctl disconnect'")
    machine.fail("ip -4 rule show | grep '^30200:'")
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
