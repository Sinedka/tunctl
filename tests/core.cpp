#include "vpnctl/core.hpp"
#include <iostream>
#include <sys/socket.h>
#include <unistd.h>
using namespace vpn;
int main() {
  try {
    for (auto s : {"1.1.1.1/32", "::/0", "2001:db8::1", "192.168.0.0/16"})
      require(cidr(s), s);
    for (auto s : {"1.1.1.1/33", "::/129", "1/0", "::/-1", "::/1xyz"})
      require(!cidr(s), s);
    require(domain("*.example.org") && !domain(".x") && !domain("host\nrule") &&
                !domain("a..b"),
            "domain validation");
    auto cert = run({"openssl", "req", "-new", "-x509", "-newkey", "ec",
                     "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                     "-subj", "/CN=test", "-keyout", "/dev/null"});
    require(cert.status == 0, "test certificate generation");
    auto start = cert.output.find("-----BEGIN CERTIFICATE-----");
    require(start != std::string::npos, "test certificate");
    auto good =
        std::string("client\ndev tun\nremote example.org 1194 udp\n<ca>\n") +
        cert.output.substr(start) + "</ca>\n";
    require(profile(good).endpoint == "example.org", "remote");
    for (auto bad : {"up /bin/true", "config /etc/file", "script-security 2",
                     "ca /tmp/ca", "<key>\n</key> extra", "remote :: 99999"}) {
      bool rejected = false;
      try {
        profile(good + bad);
      } catch (...) {
        rejected = true;
      }
      require(rejected, "unexpected profile acceptance");
    }
    require(ruleLine({{"kind", "ip"}, {"match", "::/0"}, {"action", "vpn"}},
                     42) == "ip6 daddr ::/0 meta mark set 0x7651 accept",
            "terminal rule");
    require(covers("10.0.0.0/8", "10.0.1.0/24") && !covers("::/64", "1.1.1.1"),
            "shadowed rule");
    auto ping = pingMetrics(
        "time=1.0 ms\ntime=3.0 ms\n2 packets transmitted, 2 received, 0% "
        "packet loss\nrtt min/avg/max/mdev = 1.0/2.0/3.0/1.0 ms");
    require(ping.at("jitter_ms") == 2.0 && ping.at("avg_ms") == 2.0,
            "RTT summary");
    int fds[2];
    require(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair");
    sendJson(fds[0], {{"op", "status"}});
    require(recvJson(fds[1]).at("op") == "status", "IPC framing");
    close(fds[0]);
    close(fds[1]);
    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
