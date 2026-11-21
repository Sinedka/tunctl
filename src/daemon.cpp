#include "vpnctl/core.hpp"
#include <chrono>
#include <ctime>
#include <fcntl.h>
#include <iostream>
#include <net/if.h>
#include <pwd.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

using namespace vpn;
namespace {
const fs::path state = "/var/lib/vpnctl", profiles = state / "profiles",
               active = state / "active.ovpn";
const std::string unit = "vpnctl-tunnel.service";
const fs::path policyFile = "/etc/vpnctl/policy.json";
Json policy() { return Json::parse(read(policyFile)); }
std::string selected() {
  return fs::is_symlink(active) ? fs::read_symlink(active).stem().string() : "";
}
void selectProfile(const std::string &n) {
  if (n.empty()) {
    fs::remove(active);
    return;
  }
  auto temp = state / "active.next";
  fs::remove(temp);
  fs::create_symlink(fs::path("profiles") / (n + ".ovpn"), temp);
  fs::rename(temp, active);
}
bool ctl(const char *op) {
  return run({"systemctl", op, unit}, 48).status == 0;
}
bool initialized() {
  if (!if_nametoindex("vpnctl0"))
    return false;
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
    return false;
  timeval t{1, 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof t);
  sockaddr_un a{AF_UNIX, "/run/vpnctl-tunnel/management"};
  std::string reply;
  if (connect(fd, (sockaddr *)&a, sizeof a) == 0 &&
      send(fd, "state\n", 6, MSG_NOSIGNAL) == 6) {
    char buf[1024];
    while (reply.size() < 8192 && !reply.contains("END\r\n")) {
      auto n = recv(fd, buf, sizeof buf, 0);
      if (n <= 0)
        break;
      reply.append(buf, n);
    }
  }
  close(fd);
  return reply.contains(",CONNECTED,SUCCESS,");
}
void event(const std::string &text) {
  auto p = state / "events";
  std::string events = fs::exists(p) ? read(p) : "";
  events = std::to_string(time(nullptr)) + "  " + text + "\n" + events;
  if (events.size() > 4096)
    events.resize(4096);
  write(p, events);
}
Json userRules() {
  auto path = state / "rules.json";
  if (fs::exists(path)) {
    auto layer = Json::parse(read(path));
    if (layer.is_object() && layer.value("owner", "") ==
                                 policy().at("policyUser").get<std::string>())
      return layer.at("rules");
  }
  return Json::array();
}
void applyRules(const Json &rules, const Json &cfg) {
  require(rules.is_array() && rules.size() <= 256, "up to 256 rules allowed");
  auto owner = cfg.at("policyUser").get<std::string>();
  auto pw = getpwnam(owner.c_str());
  uid_t uid = pw ? pw->pw_uid : 0;
  std::string batch = "flush chain inet vpnctl applications\nflush chain inet "
                      "vpnctl addresses\n";
  if (pw) {
    auto probe = ruleLine(
        {{"kind", "app"}, {"match", "probe_direct"}, {"action", "direct"}},
        uid);
    if (!probe.empty())
      batch += "add rule inet vpnctl applications " + probe + "\n";
  }
  Json domains = Json::array();
  if (pw)
    for (auto &r : rules) {
      bool enabled = r.value("enabled", true);
      if (r.at("kind") == "domain") {
        std::string m = r.at("match"), a = r.at("action");
        require(domain(m) && (a == "vpn" || a == "direct"),
                "invalid domain rule");
        require(cfg.value("dns", false),
                "enable services.vpnctl.dns.enable first");
        if (enabled)
          domains.push_back({{"match", m}, {"action", a}});
        continue;
      }
      auto line = ruleLine(r, uid);
      if (enabled && !line.empty())
        batch += "add rule inet vpnctl " +
                 std::string(r.at("kind") == "app" ? "applications "
                                                   : "addresses ") +
                 line + " comment \"vpnctl-" + digest(r.dump()).substr(0, 16) +
                 "\"\n";
    }
  auto dnsFile = fs::path("/run/vpnctl/domains.json");
  std::string payload = Json{{"owner", owner}, {"rules", domains}}.dump();
  bool changed = cfg.value("dns", false) &&
                 (!fs::exists(dnsFile) || read(dnsFile) != payload);
  struct Lock {
    int fd = -1;
    ~Lock() {
      if (fd >= 0)
        close(fd);
    }
  } lock;
  if (changed) {
    lock.fd = open("/run/vpnctl/dns.lock", O_RDONLY | O_CLOEXEC);
    require(lock.fd >= 0 && flock(lock.fd, LOCK_EX) == 0, "DNS lock failed");
    for (auto set : {"domains4", "domains6", "domainvpn4", "domainvpn6"})
      batch += "flush set inet vpnctl " + std::string(set) + "\n";
  }
  auto path = state / "apply.nft";
  write(path, batch);
  require(run({"nft", "-f", path.string()}).status == 0,
          "kernel rejected routing rules");
  if (changed) {
    write(dnsFile, payload);
    require(chmod(dnsFile.c_str(), 0644) == 0, "DNS policy permissions");
  }
}
const fs::path pending = "/run/vpnctl/pending.ovpn",
               transaction = "/run/vpnctl/previous-running";
void releaseGuard() {
  require(run({"systemctl", "stop", "vpnctl-session.service"}).status == 0,
          "session guard still active");
}
void recoverSwitch() {
  if (!fs::exists(transaction))
    return;
  bool restore = read(transaction) == "yes";
  require(ctl("stop"), "cannot stop interrupted switch");
  fs::remove(pending);
  if (restore && !selected().empty())
    require(ctl("start") && initialized(),
            "recovery of previous connection failed");
  else
    releaseGuard();
  fs::remove(transaction);
  event("recovered interrupted profile switch");
}
Json handle(const Json &j, uid_t uid) {
  auto cfg = policy();
  auto *pw = getpwuid(uid);
  require(pw != nullptr, "unknown peer");
  std::string user = pw->pw_name;
  require(uid == 0 ||
              std::find(cfg.at("operators").begin(), cfg.at("operators").end(),
                        user) != cfg.at("operators").end(),
          "unauthorized peer");
  auto op = j.at("op").get<std::string>();
  if (op == "inspect") {
    std::string section = j.at("section");
    if (section == "tables") {
      std::string out;
      for (auto family : {"-4", "-6"}) {
        out += std::string(family) + " rules\n" +
               run({"ip", family, "rule", "show"}).output;
        out += run({"ip", family, "route", "show", "table", "30201"}).output;
      }
      return {{"text", out}};
    }
    require(section == "dns" || section == "guard", "unknown section");
    if (section == "guard")
      return {
          {"text",
           run({"nft", "list", "chain", "inet", "vpnctl", "guard"}).output}};
    std::string out = read("/etc/resolv.conf");
    for (auto set : {"domains4", "domains6", "domainvpn4", "domainvpn6"})
      out += run({"nft", "list", "set", "inet", "vpnctl", set}).output;
    return {{"text", out}};
  }
  if (op == "status") {
    auto service =
        run({"systemctl", "show", "-p", "ActiveState", "--value", unit}).output;
    while (service.ends_with('\n'))
      service.pop_back();
    bool connected = service == "active" && initialized();
    Json rows = Json::array();
    for (auto &e : fs::directory_iterator(profiles))
      if (e.path().extension() == ".ovpn") {
        auto m = Json::parse(read(e.path().string() + ".json"));
        rows.push_back(m);
      }
    Json data = {{"state", connected             ? "connected"
                           : service == "active" ? "reconnecting"
                                                 : service},
                 {"selected", selected()},
                 {"killSwitch", cfg.at("killSwitch")},
                 {"profiles", rows},
                 {"rules", userRules()},
                 {"allowDirectProbe", cfg.at("policyUser") == user},
                 {"systemIPs", cfg.at("directIPs")},
                 {"domains", cfg.at("directDomains")}};
    auto owner = cfg.at("policyUser").get<std::string>();
    auto account = getpwnam(owner.c_str());
    Json states = Json::array();
    std::string installed;
    Json domainRules = Json::array();
    if (!data.at("rules").empty()) {
      for (auto chain : {"addresses", "applications"})
        installed +=
            run({"nft", "list", "chain", "inet", "vpnctl", chain}).output;
      auto f = fs::path("/run/vpnctl/domains.json");
      if (cfg.at("dns") == true && fs::exists(f) &&
          run({"systemctl", "is-active", "dnsmasq.service",
               "vpnctl-dns.service"})
                  .output == "active\nactive\n") {
        auto layer = Json::parse(read(f));
        if (layer.at("owner") == owner)
          domainRules = layer.at("rules");
      }
    }
    for (auto &r : data.at("rules")) {
      std::string stateName = "missing from kernel";
      if (!r.value("enabled", true))
        stateName = "disabled";
      else if (r.at("kind") == "domain") {
        Json entry = {{"action", r.at("action")}, {"match", r.at("match")}};
        stateName = std::find(domainRules.begin(), domainRules.end(), entry) !=
                            domainRules.end()
                        ? "applied (DNS)"
                        : "DNS inactive";
      } else if (r.at("kind") == "app" &&
                 (!account || ruleLine(r, account->pw_uid).empty()))
        stateName = "waiting for slice";
      else if (installed.contains("vpnctl-" + digest(r.dump()).substr(0, 16)))
        stateName = "applied";
      states.push_back(stateName);
    }
    data["ruleStates"] = states;
    if (connected) {
      for (auto k : {"rx_bytes", "tx_bytes"})
        data[k] = std::stoull(
            read(fs::path("/sys/class/net/vpnctl0/statistics") / k));
      data["interface"] = "vpnctl0";
      auto t = run({"systemctl", "show", "-p", "ActiveEnterTimestampMonotonic",
                    "--value", unit})
                   .output;
      timespec now{};
      clock_gettime(CLOCK_MONOTONIC, &now);
      if (!t.empty() && isdigit(t[0]))
        data["uptime_s"] = now.tv_sec - std::stoll(t) / 1000000;
    }
    if (fs::exists(state / "last-error"))
      data["lastError"] = read(state / "last-error");
    if (fs::exists(state / "events"))
      data["events"] = read(state / "events");
    return data;
  }
  if (op == "refresh") {
    applyRules(userRules(), cfg);
    return {{"refreshed", true}};
  }
  if (op == "sync") {
    require(cfg.at("policyUser") == user,
            "administrator has not delegated routing policy");
    auto old = userRules();
    auto r = j.at("rules");
    try {
      applyRules(r, cfg);
      write(state / "rules.json", Json{{"owner", user}, {"rules", r}}.dump());
    } catch (...) {
      applyRules(old, cfg);
      throw;
    }
    return {{"applied", r.size()}};
  }
  if (op == "disconnect") {
    require(ctl("stop"), "stop failed");
    fs::remove(pending);
    fs::remove(transaction);
    releaseGuard();
    event("disconnected");
    return {{"disconnected", true}};
  }
  std::string n = j.at("name");
  require(id(n), "invalid profile name");
  auto path = profiles / (n + ".ovpn");
  if (op == "import") {
    require(!fs::exists(path), "name already exists");
    require(std::distance(fs::directory_iterator(profiles),
                          fs::directory_iterator{}) < 1024,
            "profile limit reached");
    auto p = profile(j.at("profile"));
    write(path.string() + ".json", Json{{"name", n},
                                        {"endpoint", p.endpoint},
                                        {"protocol", p.protocol},
                                        {"sha256", digest(p.config)}}
                                       .dump());
    write(path, p.config);
    event("imported " + n);
    return {{"imported", n}};
  }
  require(fs::exists(path), "unknown profile");
  if (op == "country") {
    std::string country = j.at("country");
    require(country.size() <= 64 && std::all_of(country.begin(), country.end(),
                                                [](unsigned char c) {
                                                  return isalpha(c) ||
                                                         c == ' ' || c == '-';
                                                }),
            "use a country name or ISO code");
    auto metadata = path.string() + ".json";
    auto data = Json::parse(read(metadata));
    data["country"] = country;
    write(metadata, data.dump());
    return {{"country", country}};
  }
  if (op == "remove") {
    if (selected() == n) {
      require(
          run({"systemctl", "show", "--property=ActiveState", "--value", unit})
                  .output == "inactive\n",
          "disconnect before removing the active profile");
      selectProfile("");
    }
    fs::remove(path);
    fs::remove(path.string() + ".json");
    return {{"removed", n}};
  }
  require(op == "connect", "unknown operation");

  bool restore =
      !selected().empty() &&
      run({"systemctl", "is-active", "vpnctl-session.service"}).status == 0;
  write(transaction, restore ? "yes" : "no");
  require(ctl("stop"), "cannot stop tunnel");

  fs::remove(pending);
  fs::create_symlink(path, pending);
  if (ctl("start") && initialized()) {
    selectProfile(n);
    fs::remove(transaction);
    fs::remove(pending);
    fs::remove(state / "last-error");
    event("connected " + n);
    return {{"connected", n}};
  }
  require(ctl("stop"), "candidate could not be stopped");
  fs::remove(pending);
  std::string message = "OpenVPN initialization failed; see journalctl -b -u "
                        "vpnctl-tunnel.service";
  if (restore)
    message += (ctl("start") && initialized())
                   ? "; previous tunnel restored"
                   : "; previous tunnel also failed";
  else
    releaseGuard();
  fs::remove(transaction);
  event(message);
  write(state / "last-error", message);
  throw std::runtime_error(message);
}
} // namespace
int main(int argc, char **argv) {
  umask(0077);
  // systemctl start is called while the IPC handler holds the transaction lock.
  // ExecStartPost must observe OpenVPN directly, without acquiring that lock.
  if (argc == 2 && std::string_view(argv[1]) == "wait-ready") {
    using namespace std::chrono_literals;
    auto deadline = std::chrono::steady_clock::now() + 32s;
    do {
      if (initialized())
        return 0;
      std::this_thread::sleep_for(100ms);
    } while (std::chrono::steady_clock::now() < deadline);
    std::cerr
        << "Timed out waiting for vpnctl0 and OpenVPN CONNECTED,SUCCESS\n";
    return 1;
  }
  try {
    bool refresh = argc == 2 && std::string(argv[1]) == "refresh";
    Json j;
    ucred peer{};
    socklen_t size = sizeof peer;
    if (!refresh) {
      require(getsockopt(0, SOL_SOCKET, SO_PEERCRED, &peer, &size) == 0,
              "expected systemd socket");
      timeval tv{4, 0};
      setsockopt(0, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
      setsockopt(0, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
      j = recvJson(0);
    }
    int lock =
        open((state / "lock").c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    require(lock >= 0 && flock(lock, LOCK_EX) == 0, "state lock failed");
    fs::create_directories(profiles);
    if (refresh) {
      recoverSwitch();
      applyRules(userRules(), policy());
    } else
      sendJson(0, handle(j, peer.uid));
    return 0;
  } catch (const nlohmann::json::exception &) {
    try {
      sendJson(0, {{"error", "invalid JSON schema"}});
    } catch (...) {
    }
    return 1;
  } catch (const std::exception &e) {
    if (argc == 1) {
      try {
        sendJson(0, {{"error", e.what()}});
      } catch (...) {
      }
    } else
      std::cerr << e.what() << "\n";
    return 1;
  }
}
