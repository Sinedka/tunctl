#include "vpnctl/core.hpp"
#include <chrono>
#include <ctime>
#include <fcntl.h>
#include <iostream>
#include <net/if.h>
#include <pwd.h>
#include <sstream>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <syslog.h>
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
// Only fixed state names are exposed: management detail fields can contain peer
// data.
std::string managementState() {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
    return "WAIT_MANAGEMENT";
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
  std::istringstream stream(reply);
  for (std::string row; std::getline(stream, row);) {
    auto first = row.find(',');
    if (first == 0 || first == row.npos ||
        row.find_first_not_of("0123456789") != first)
      continue;
    auto next = row.find(',', first + 1);
    if (next == row.npos)
      continue;
    auto name = row.substr(first + 1, next - first - 1);
    if (name == "CONNECTED" && row.compare(next, 9, ",SUCCESS,") == 0)
      return name;
    for (auto known : {"INITIAL", "CONNECTING", "RESOLVE", "TCP_CONNECT",
                       "WAIT", "AUTH", "AUTH_PENDING", "GET_CONFIG",
                       "ASSIGN_IP", "ADD_ROUTES", "RECONNECTING", "EXITING"})
      if (name == known)
        return name;
  }
  return "WAIT_MANAGEMENT";
}
bool initialized() {
  return if_nametoindex("vpnctl0") && managementState() == "CONNECTED";
}
void logEvent(const std::string &text, int level = LOG_INFO) {
  syslog(level, "%s", text.c_str());
}
std::string connectionLog() {
  auto r = run({"journalctl", "--no-pager", "--quiet", "--utc", "--no-hostname",
                "-o", "short-iso", "-r", "-n", "160", "_UID=0",
                "SYSLOG_IDENTIFIER=vpnctl-events"},
               4);
  if (r.status == 0 && !r.output.empty()) {
    std::istringstream in(r.output);
    std::string out;
    for (std::string row; std::getline(in, row);) {
      auto stamp = row.find(' '), tag = row.find(": ", stamp);
      if (stamp != row.npos && tag != row.npos)
        out += row.substr(0, stamp) + "  " + row.substr(tag + 2) + "\n";
    }
    if (!out.empty())
      return out;
  }
  auto legacy = state / "events";
  auto history = fs::exists(legacy) ? read(legacy) : std::string{};
  return r.status == 0
             ? history
             : "System journal unavailable. Recent actions:\n" + history;
}
void event(const std::string &text) {
  logEvent(text);
  auto p = state / "events";
  std::string events = fs::exists(p) ? read(p) : "";
  events = std::to_string(time(nullptr)) + "  " + text + "\n" + events;
  if (events.size() > 4096)
    events.resize(4096);
  write(p, events);
}
Json savedPolicy(const Json &cfg) {
  auto path = state / "rules.json";
  if (fs::exists(path)) {
    auto layer = Json::parse(read(path));
    if (layer.is_object() &&
        layer.value("owner", "") == cfg.at("policyUser").get<std::string>())
      return layer;
  }
  return Json::object();
}
Json userRules() { return savedPolicy(policy()).value("rules", Json::array()); }
bool autolaunch(const Json &cfg, const Json &layer) {
  return layer.value("autolaunch", cfg.value("autolaunch", false));
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
  logEvent("Recovery: interrupted profile switch detected", LOG_WARNING);
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
std::string operatorName(uid_t uid, const Json &cfg) {
  auto *pw = getpwuid(uid);
  require(pw != nullptr, "unknown peer");
  std::string user = pw->pw_name;
  require(uid == 0 ||
              std::find(cfg.at("operators").begin(), cfg.at("operators").end(),
                        user) != cfg.at("operators").end(),
          "unauthorized peer");
  return user;
}
Json handle(const Json &j, uid_t uid) {
  auto cfg = policy();
  auto user = operatorName(uid, cfg);
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
                 {"autolaunch", autolaunch(cfg, savedPolicy(cfg))},
                 {"baseAutolaunch", cfg.value("autolaunch", false)},
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
    auto layer = savedPolicy(cfg);
    if (j.contains("autolaunch")) {
      if (j.at("autolaunch").is_null())
        layer.erase("autolaunch");
      else {
        require(j.at("autolaunch").is_boolean(), "autolaunch must be boolean");
        layer["autolaunch"] = j.at("autolaunch");
      }
    }
    auto old = layer.value("rules", Json::array());
    require(j.contains("rules") || j.contains("autolaunch"),
            "no settings supplied");
    auto r = j.value("rules", old);
    try {
      if (j.contains("rules"))
        applyRules(r, cfg);
      layer["owner"] = user;
      layer["rules"] = r;
      write(state / "rules.json", layer.dump());
    } catch (...) {
      logEvent("Routing: update failed; restoring previous rules", LOG_WARNING);
      if (j.contains("rules"))
        applyRules(old, cfg);
      throw;
    }
    event("Routing: applied " + std::to_string(r.size()) + " user rules");
    return {{"applied", r.size()}};
  }
  if (op == "disconnect") {
    logEvent("Disconnect: stopping OpenVPN");
    require(ctl("stop"), "stop failed");
    fs::remove(pending);
    fs::remove(transaction);
    releaseGuard();
    event("Disconnect: tunnel stopped and session guard released");
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
    event("Profile: removed " + n);
    return {{"removed", n}};
  }
  require(op == "connect", "unknown operation");

  bool restore =
      !selected().empty() &&
      run({"systemctl", "is-active", "vpnctl-session.service"}).status == 0;
  event("Connect: requested profile " + n);
  if (restore)
    logEvent("Switch: previous profile " + selected() +
             " available for rollback");
  write(transaction, restore ? "yes" : "no");
  logEvent("Connect: stopping previous tunnel instance");
  require(ctl("stop"), "cannot stop tunnel");

  fs::remove(pending);
  fs::create_symlink(path, pending);
  logEvent("Connect: starting OpenVPN for " + n);
  bool started = ctl("start");
  if (started && initialized()) {
    selectProfile(n);
    fs::remove(transaction);
    fs::remove(pending);
    fs::remove(state / "last-error");
    event("Connect: profile " + n + " is active on vpnctl0");
    return {{"connected", n}};
  }
  logEvent(started
               ? "Connect: OpenVPN unit started but tunnel readiness was lost"
               : "Connect: systemd could not start the OpenVPN unit",
           LOG_ERR);
  require(ctl("stop"), "candidate could not be stopped");
  fs::remove(pending);
  std::string message = "OpenVPN initialization failed for " + n +
                        "; see Logs (6) or vpnctl logs";
  if (restore) {
    logEvent("Rollback: restarting previous profile " + selected());
    message += (ctl("start") && initialized())
                   ? "; previous tunnel restored"
                   : "; previous tunnel also failed";
  } else {
    releaseGuard();
    logEvent("Connect: failed candidate stopped and session guard released");
  }
  fs::remove(transaction);
  event(message);
  write(state / "last-error", message);
  throw std::runtime_error(message);
}
} // namespace
int main(int argc, char **argv) {
  umask(0077);
  openlog("vpnctl-events", LOG_PID, LOG_DAEMON);
  if (argc == 2 && std::string_view(argv[1]) == "routes-ready") {
    logEvent("Routing: tunnel routes installed in table 30201");
    return 0;
  }
  if (argc == 2 && std::string_view(argv[1]) == "tunnel-stopped") {
    // The invocation filter excludes previous attempts. Never forward raw
    // provider messages, certificate subjects, or authentication fields.
    std::string invocation =
        getenv("INVOCATION_ID") ? getenv("INVOCATION_ID") : "";
    if (invocation.size() == 32 &&
        invocation.find_first_not_of("0123456789abcdef") == invocation.npos) {
      auto journal =
          run({"journalctl", "--no-pager", "--quiet", "-o", "cat", "-n", "80",
               "_SYSTEMD_INVOCATION_ID=" + invocation, "_COMM=openvpn"},
              2);
      for (auto [marker, reason] :
           {std::pair{"AUTH_FAILED", "server rejected authentication"},
            {"VERIFY ERROR", "server certificate verification failed"},
            {"failed to negotiate cipher", "no shared data cipher"},
            {"TLS key negotiation failed", "TLS negotiation timed out"},
            {"TLS handshake failed", "TLS handshake failed"},
            {"Network is unreachable", "network unreachable"},
            {"Connection refused", "transport connection refused"}}) {
        if (journal.status == 0 && journal.output.contains(marker)) {
          logEvent(std::string("OpenVPN: ") + reason, LOG_ERR);
          break;
        }
      }
    }
    auto raw = getenv("SERVICE_RESULT");
    std::string result = "unknown";
    for (auto known : {"success", "exit-code", "signal", "core-dump", "timeout",
                       "resources", "protocol", "watchdog", "oom-kill"})
      if (raw && std::string_view(raw) == known)
        result = known;
    logEvent("OpenVPN: service stopped (" + result + ")",
             result == "success" ? LOG_INFO : LOG_WARNING);
    return 0;
  }
  // systemctl start is called while the IPC handler holds the transaction lock.
  // ExecStartPost must observe OpenVPN directly, without acquiring that lock.
  if (argc == 2 && std::string_view(argv[1]) == "wait-ready") {
    using namespace std::chrono_literals;
    auto deadline = std::chrono::steady_clock::now() + 32s;
    auto start = std::chrono::steady_clock::now();
    std::string previous;
    logEvent("OpenVPN: waiting for handshake and vpnctl0");
    do {
      auto stage = managementState();
      if (stage != previous) {
        logEvent("OpenVPN state: " + stage);
        previous = stage;
      }
      if (stage == "CONNECTED" && if_nametoindex("vpnctl0")) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        logEvent("OpenVPN: handshake confirmed, vpnctl0 present (" +
                 std::to_string(ms.count()) + " ms since readiness check)");
        return 0;
      }
      std::this_thread::sleep_for(100ms);
    } while (std::chrono::steady_clock::now() < deadline);
    logEvent("OpenVPN: readiness timed out; last state " + previous, LOG_ERR);
    std::cerr
        << "Timed out waiting for vpnctl0 and OpenVPN CONNECTED,SUCCESS\n";
    return 1;
  }
  try {
    bool boot = argc == 2 && std::string_view(argv[1]) == "autolaunch";
    bool refresh = argc == 2 && std::string(argv[1]) == "refresh";
    Json j;
    ucred peer{};
    socklen_t size = sizeof peer;
    if (!refresh && !boot) {
      require(getsockopt(0, SOL_SOCKET, SO_PEERCRED, &peer, &size) == 0,
              "expected systemd socket");
      timeval tv{4, 0};
      setsockopt(0, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
      setsockopt(0, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
      j = recvJson(0);
      // Reading logs must work while connect holds the profile transaction
      // lock.
      if (j.value("op", "") == "logs") {
        operatorName(peer.uid, policy());
        sendJson(0, {{"events", connectionLog()}});
        return 0;
      }
    }
    int lock =
        open((state / "lock").c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    require(lock >= 0 && flock(lock, LOCK_EX) == 0, "state lock failed");
    fs::create_directories(profiles);
    if (boot) {
      auto cfg = policy();
      if (autolaunch(cfg, savedPolicy(cfg)) && !selected().empty()) {
        recoverSwitch();
        applyRules(userRules(), cfg);
        logEvent("Autolaunch: starting last successful profile");
        if (!ctl("start") || !initialized()) {
          require(ctl("stop"), "cannot stop failed boot connection");
          releaseGuard();
          write(state / "last-error", "Autolaunch failed; see Logs");
          throw std::runtime_error("Autolaunch failed; see Logs");
        }
        event("Autolaunch: tunnel ready");
      }
    } else if (refresh) {
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
