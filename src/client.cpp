#include "picker.hpp"
#include "tui.hpp"
#include "vpnctl/core.hpp"
#include <algorithm>
#include <chrono>
#include <clocale>
#include <cmath>
#include <csignal>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <future>
#include <iomanip>
#include <iostream>
#include <regex>
#include <set>
#include <sstream>
#include <sys/file.h>
#include <thread>
#include <unistd.h>

using namespace vpn;
namespace {
volatile std::sig_atomic_t interrupted = 0;
void interrupt(int) { interrupted = 1; }
bool cliCancelled() { return interrupted != 0; }
const fs::path &executable() {
  static const auto path = fs::read_symlink("/proc/self/exe");
  return path;
}
std::string importHelper() {
  return (executable().parent_path() / VPNCTL_IMPORT_HELPER).lexically_normal();
}
fs::path xdg(const char *var, const char *fallback) {
  if (auto p = getenv(var); p && *p)
    return fs::path(p) / "vpnctl";
  auto home = getenv("HOME");
  require(home, "HOME is unset");
  return fs::path(home) / fallback / "vpnctl";
}
fs::path prefs() {
  auto personal = xdg("XDG_CONFIG_HOME", ".config") / "locked.json";
  const fs::path system = "/etc/vpnctl/locked.json";
  return !fs::exists(personal) && fs::exists(system) ? system : personal;
}
Json resetLayer() {
  return fs::exists(prefs()) ? Json::object() : Json{{"autolaunch", false}};
}
auto overrides() {
  return xdg("XDG_STATE_HOME", ".local/state") / "unlocked.json";
}
Json load(const fs::path &p, Json fallback) {
  return fs::exists(p) ? Json::parse(read(p)) : fallback;
}
Json unlocked() {
  if (fs::exists(overrides()))
    return load(overrides(), Json::object());
  // Adopt the previous layout on the first edit. Reset writes an empty
  // layer, so obsolete files can never resurrect a discarded override.
  auto dir = xdg("XDG_CONFIG_HOME", ".config");
  auto cfg = fs::exists(dir / "locked.json")
                 ? Json::object()
                 : load(dir / "settings.json", Json::object());
  cfg.merge_patch(
      load(overrides().parent_path() / "preferences.json", Json::object()));
  auto legacy = overrides().parent_path() / "overrides.json";
  if (fs::exists(legacy))
    cfg["rules"] = load(legacy, Json::array());
  if (!fs::exists(prefs()) && !cfg.contains("autolaunch"))
    cfg["autolaunch"] = false;
  return cfg;
}
Json settings(const Json &layer) {
  auto cfg = load(prefs(), Json::object());
  cfg.merge_patch(layer);
  return cfg;
}
Json settings() { return settings(unlocked()); }
std::string slice(std::string s) {
  require(id(s), "invalid application name");
  std::replace(s.begin(), s.end(), '-', '_');
  require(s.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789_") ==
              s.npos,
          "unsupported slice name");
  return s;
}
Json fromSettings(const Json &config) {
  auto routing = config.value("routing", Json::object());
  auto r = Json::array();
  for (auto k : {"directIPs", "directDomains"})
    for (auto &m : routing.value(k, Json::array()))
      r.push_back({{"kind", std::string(k) == "directIPs" ? "ip" : "domain"},
                   {"match", m},
                   {"action", "direct"}});
  for (auto &a : routing.value("applications", Json::array()))
    r.push_back({{"kind", "app"},
                 {"match", slice(a.at("name"))},
                 {"action", a.at("action")},
                 {"enabled", a.value("enabled", true)}});
  return r;
}
Json rules(const Json &cfg) { return cfg.value("rules", fromSettings(cfg)); }
Json rules() { return rules(settings()); }
class ConfigLock {
  int fd;

public:
  ConfigLock() {
    fs::create_directories(overrides().parent_path());
    fd = open((overrides().parent_path() / "unlocked.lock").c_str(),
              O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    require(fd >= 0, "cannot open settings lock");
    if (flock(fd, LOCK_EX) != 0) {
      close(fd);
      throw std::runtime_error("cannot lock settings");
    }
  }
  ~ConfigLock() { close(fd); }
};
enum class Apply { local, all, boot };
Json sendConfig(const Json &layer, Apply mode) {
  Json j = {{"op", "sync"},
            {"autolaunch", layer.value("autolaunch", Json(nullptr))}};
  if (mode == Apply::all)
    j["rules"] = rules(settings(layer));
  return rpc(j);
}
Json syncCurrent() {
  ConfigLock lock;
  return sendConfig(unlocked(), Apply::all);
}
void saveConfig(const Json &layer, Apply mode) {
  ConfigLock lock;
  auto old = unlocked();
  write(overrides(), layer.dump(2) + "\n");
  try {
    if (mode != Apply::local)
      sendConfig(layer, mode);
  } catch (...) {
    write(overrides(), old.dump(2) + "\n");
    throw;
  }
}
void initUnlocked() {
  ConfigLock lock;
  if (!fs::exists(overrides()))
    write(overrides(), unlocked().dump(2) + "\n");
}
void saveRules(const Json &r) {
  auto layer = unlocked();
  layer["rules"] = r;
  saveConfig(layer, Apply::all);
}
Args scope(std::string name, const Args &args) {
  Args a = {"systemd-run",
            "--user",
            "--scope",
            "--quiet",
            "--slice=vpnctl-" + slice(name) + ".slice",
            "--",
            executable(),
            "exec-ready"};
  a.insert(a.end(), args.begin(), args.end());
  return a;
}
void execute(const Args &a) {
  std::vector<char *> argv;
  for (auto &s : a)
    argv.push_back(const_cast<char *>(s.c_str()));
  argv.push_back(nullptr);
  execvp(argv[0], argv.data());
  throw std::runtime_error("cannot launch " + a.front());
}
std::string output(const Args &a, int timeout, bool (*cancel)()) {
  auto r = run(a, timeout, cancel);
  require(r.status == 0, r.output.empty() ? "command failed" : r.output);
  return r.output;
}
std::string diag(std::string test, std::string target, std::string via,
                 bool confirmed, bool (*cancel)()) {
  require(via == "vpn" || via == "direct", "use vpn or direct");
  require((domain(target) && !target.starts_with("*.")) ||
              (cidr(target) && !target.contains('/')),
          "invalid diagnostic target");
  auto endpoints = settings().value("diagnostics", Json::object());
  auto https = [&](const char *key, std::string fallback) {
    auto uri = endpoints.value(key, fallback);
    require(uri.starts_with("https://"), "HTTPS test endpoint required");
    return uri;
  };
  std::string url;
  if (test == "download")
    url = https("downloadUrl",
                "https://speed.cloudflare.com/__down?bytes=1048576");
  if (test == "upload")
    url = https("uploadUrl", "https://speed.cloudflare.com/__up");
  if (test == "public-ip" || test == "ipv6")
    url = https("publicIPUrl", "https://api64.ipify.org");
  std::string resolveEntry;
  std::string device = "vpnctl0";
  if (via == "direct") {
    require(rpc({{"op", "status"}}).value("allowDirectProbe", false),
            "DIRECT tests require policyUser delegation");
    require(read("/proc/self/cgroup").contains("/vpnctl-probe_direct.slice/"),
            "DIRECT test requires the managed probe scope");
    if (test != "dns" && test != "dns-leak") {
      std::string host = target, port = "443";
      if (!url.empty()) {
        static const std::regex authority(
            R"(^https://(\[[A-Fa-f0-9:]+\]|[a-zA-Z0-9.-]+)(:([0-9]+))?([/?#].*)?$)");
        std::smatch m;
        require(std::regex_match(url, m, authority), "invalid HTTPS authority");
        host = m[1];
        if (m[3].matched)
          port = m[3];
        if (host.starts_with('['))
          host = host.substr(1, host.size() - 2);
      }
      std::string addr = host;
      if (!cidr(addr)) {
        std::istringstream answers(
            output({"getent", test == "ipv6" ? "ahostsv6" : "ahostsv4", host},
                   4, cancel));
        answers >> addr;
        require(cidr(addr), "cannot resolve target");
        if (!url.empty())
          resolveEntry = host + ":" + port + ":" +
                         (addr.contains(':') ? "[" + addr + "]" : addr);
      }
      auto routes = Json::parse(output(
          {"ip", "-j", "route", "get", addr, "mark", "0x7652"}, 3, cancel));
      require(!routes.empty(), "no physical route");
      device = routes[0].at("dev");
      require(device != "vpnctl0" && device != "lo",
              "target has no physical route");
      if (url.empty())
        target = addr;
    }
  }
  if (test == "route")
    return output({"ip", "route", "get", target, "mark",
                   via == "vpn" ? "0x7651" : "0x7652"},
                  4, cancel);
  if (test == "dns")
    return output({"dig", "+tries=1", "+timeout=3", target}, 5, cancel);
  if (test == "dns-leak")
    return "Configured resolver path (external resolver identity requires an "
           "authoritative DNS probe)\n" +
           read("/etc/resolv.conf") +
           output({"dig", "+tries=1", "+timeout=3", "whoami.akamai.net", "A"},
                  5, cancel);
  if (test == "ping" || test == "endpoint") {
    Args a = {"ping", "-n", "-c", "4", "-W", "2", "-w", "10"};
    if (test == "ping" || via == "direct") {
      a.push_back("-I");
      a.push_back(device);
    }
    a.push_back(target);
    auto r = run(a, 12, cancel);
    require(r.status == 0 || r.status == 1, r.output);
    return pingMetrics(r.output).dump();
  }
  require(fs::exists(fs::path("/sys/class/net") / device),
          "missing interface " + device);
  Args a = {"curl",     "-q",           "--noproxy",         "*", "--fail",
            "--silent", "--show-error", "--connect-timeout", "4", "--max-time",
            "15",       "--interface",  "if!" + device};
  if (!resolveEntry.empty())
    a.insert(a.end(), {"--resolve", resolveEntry});
  if (test == "public-ip" || test == "ipv6") {
    a.push_back(test == "ipv6" ? "-6" : "-4");
    a.push_back("--max-filesize");
    a.push_back("256");
    a.push_back(url);
    return device + "  " + output(a, 17, cancel);
  }
  bool down = test == "download";
  require(down || test == "upload", "unknown diagnostic");
  require(confirmed, "speed test requires --confirm (1 MiB payload)");
  auto &endpoint = url;
  char file[] = "/tmp/vpnctl-upload-XXXXXX";
  int fd = -1;
  struct Cleanup {
    char *p;
    int &fd;
    ~Cleanup() {
      if (fd >= 0) {
        close(fd);
        unlink(p);
      }
    }
  } cleanup{file, fd};
  if (!down) {
    fd = mkstemp(file);
    require(fd >= 0 && ftruncate(fd, 1048576) == 0, "cannot prepare payload");
    a.insert(a.end(), {"--data-binary", "@" + std::string(file)});
  }
  a.insert(a.end(), {"--max-filesize", "1048576", "-o", "/dev/null", "-w",
                     down ? "%{size_download} %{time_total} %{local_ip}"
                          : "%{size_upload} %{time_total} %{local_ip}",
                     endpoint});
  auto measured = output(a, 17, cancel);
  std::istringstream in(measured);
  double bytes, seconds;
  std::string local;
  require(bool(in >> bytes >> seconds >> local) && bytes == 1048576 &&
              seconds > 0,
          "incomplete transfer");
  std::ostringstream o;
  o << std::fixed << std::setprecision(2) << bytes * 8 / seconds / 1e6
    << " Mbps, " << seconds << " s, " << (long)bytes << " bytes\n"
    << device << " (" << local << ")\n"
    << endpoint;
  return o.str();
}
Terminal *activeTerminal = nullptr;
bool cancelled() { return activeTerminal && activeTerminal->key(0) == 27; }
int tui() {
  require(isatty(0) && isatty(1), "open a terminal or use vpnctl status");
  Terminal ui;
  activeTerminal = &ui;
  auto line = [&](int y, const std::string &s) { ui.row(y, s); };
  auto prompt = [&](const std::string &s) { return ui.prompt(s); };
  initUnlocked();
  auto cfg = settings();
  auto d = cfg.value("diagnostics", Json::object());
  auto target = d.value("pingTarget", "1.1.1.1");
  int interval = std::clamp(d.value("pingInterval", 5), 1, 3600);
  ui.light = cfg.value("theme", "dark") == "light";
  int page = 0, idx = 0, section = 0, scroll = 0;
  std::vector<std::string> sections = {"ip",     "domain", "app",
                                       "tables", "dns",    "guard"};
  std::string message, search, publicIP, session;
  bool latencySort = false, directTest = false;
  std::set<std::string> marked;
  Json ping = Json::object();
  auto historyPath = overrides().parent_path() / "latency.json";
  Json history = load(historyPath, Json::object());

  const auto choiceFile = overrides().parent_path() / "selected-server.json";
  std::string choice = load(choiceFile, "").get<std::string>();
  int firstServer = 0;
  Json status = Json::object(), rr = Json::array();
  bool chooseSection = true;
  std::string inspection;
  auto nextPoll = std::chrono::steady_clock::time_point::min();
  std::future<Json> connection;
  std::string logText;
  unsigned long long prevRx = 0, prevTx = 0;
  std::string rates;
  auto last = std::chrono::steady_clock::now();
  while (true) {
    const bool poll = std::chrono::steady_clock::now() >= nextPoll;
    if (poll)
      nextPoll = std::chrono::steady_clock::now() +
                 std::chrono::milliseconds(page == 5 ? 1000 : interval * 1000);
    try {
      if (connection.valid() && connection.wait_for(std::chrono::seconds(0)) ==
                                    std::future_status::ready) {
        try {
          message = connection.get().dump();
        } catch (const std::exception &e) {
          message = e.what();
        }
      }
      if (poll && page == 5)
        logText = rpc({{"op", "logs"}}).at("events").get<std::string>();
      else if (poll) {
        cfg = settings();
        rr = rules(cfg);
        status = rpc({{"op", "status"}});
        if (!cfg.contains("routing") && !cfg.contains("rules") &&
            !status.at("rules").empty()) {
          rr = status.at("rules");
        }
      }
    } catch (const std::exception &e) {
      status = {{"state", "unavailable"}, {"lastError", e.what()}};
      if (poll && page == 5)
        logText = e.what();
    }
    auto current =
        status.value("selected", "") + " " + status.value("state", "");
    if (current != session) {
      ping = Json::object();
      publicIP.clear();
      rates.clear();
      prevRx = 0;
      prevTx = 0;
      session = current;
    }
    ui.begin(page,
             page == 5 ? (connection.valid() ? "connecting" : "")
                       : status.value("state", "unknown"),
             page == 5 ? "" : status.value("selected", ""));
    auto profiles = status.value("profiles", Json::array());
    std::vector<Json> rows;
    for (auto &p : profiles)
      if ((p["name"].get<std::string>() + " " + p.value("country", ""))
              .contains(search))
        rows.push_back(p);
    auto score = [&](const Json &row) {
      auto n = row.at("name").get<std::string>();
      return history.value(n, Json::object()).value("avg_ms", 1e12);
    };
    std::ranges::sort(rows, [&](const Json &a, const Json &b) {
      if (latencySort && score(a) != score(b))
        return score(a) < score(b);
      return a.at("name") < b.at("name");
    });

    auto tableRules = rr;
    for (const auto &[kind, key] :
         {std::pair{"ip", "systemIPs"}, {"domain", "domains"}})
      for (const auto &match : status.value(key, Json::array()))
        tableRules.push_back(
            {{"kind", kind}, {"match", match}, {"action", "direct"}});
    const int adminEnd = static_cast<int>(tableRules.size());
    auto liveRules = status.value("rules", Json::array());
    for (const auto &r : liveRules)
      if (std::find(rr.begin(), rr.end(), r) == rr.end())
        tableRules.push_back(r);
    if (page == 2 && chooseSection) {
      chooseSection = false;
      for (int n = 0; n < 3; ++n) {
        if (std::ranges::any_of(tableRules, [&](const Json &r) {
              return r.at("kind") == sections[n];
            })) {
          section = n;
          break;
        }
      }
    }
    std::vector<int> visible;
    for (size_t i = 0; i < tableRules.size(); ++i)
      if (tableRules[i].at("kind") == sections[section])
        visible.push_back(i);
    int count = page == 1 ? int(rows.size()) : int(visible.size());
    idx = std::clamp(idx, 0, std::max(0, count - 1));
    std::string help = "1-6 views    q quit";
    const bool canConnect = std::ranges::any_of(
        profiles, [&](const Json &p) { return p.at("name") == choice; });
    if (page == 0 || page == 1) {
      if (canConnect)
        ui.actions.emplace_back("Connect", 'C');
      ui.actions.emplace_back("Disconnect", 'd');
      if (page == 1) {
        ui.actions.emplace_back("Search", '/');
        ui.actions.emplace_back("Import", 'i');
      } else
        ui.actions.emplace_back("Servers", '2');
    }
    if (page == 0) {
      line(3, "Selected     " + (canConnect ? choice : "Choose in Servers"));
      help = "C connect selected   d disconnect   2 choose server   q quit";
      line(4, "Interface    " + status.value("interface", "-"));
      line(5, "Uptime       " + std::to_string(status.value("uptime_s", 0)) +
                  " s");
      line(6,
           "Kill switch  " + status.value("killSwitch", Json(nullptr)).dump());
      auto rx = status.value("rx_bytes", 0ULL),
           tx = status.value("tx_bytes", 0ULL);
      auto now = std::chrono::steady_clock::now();
      double dt = std::chrono::duration<double>(now - last).count();
      if (dt >= 1) {
        rates = prevRx && rx >= prevRx && tx >= prevTx
                    ? std::to_string((long)((rx - prevRx) / dt)) + " / " +
                          std::to_string((long)((tx - prevTx) / dt)) + " B/s"
                    : "-";
        prevRx = rx;
        prevTx = tx;
        last = now;
      }
      line(8, "RX / TX      " + std::to_string(rx) + " / " +
                  std::to_string(tx) + " bytes");
      line(9, "Current rate " + rates);
      line(10, "Public IP    " + (publicIP.empty() ? "-" : publicIP));
      line(12, "Ping avg / loss    " +
                   ping.value("avg_ms", Json(nullptr)).dump() + " ms / " +
                   ping.value("loss_pct", Json(nullptr)).dump() + " %");
      line(11, "Last error   " + status.value("lastError", "-"));
    }
    if (page == 1) {
      line(4, "Selected: " + (canConnect ? choice : "—") + "   ·   " +
                  std::to_string(rows.size()) + " profiles" +
                  (search.empty() ? "" : "   Filter: " + search));
      int capacity = std::max(1, ui.height() - 12);
      firstServer = std::clamp(firstServer, std::max(0, idx - capacity + 1),
                               std::min(idx, std::max(0, count - capacity)));
      int top = firstServer;
      for (int i = top; i < int(rows.size()) && i < top + capacity; ++i) {
        const auto &p = rows[i];
        auto name = p.at("name").get<std::string>();
        ui.servers.push_back(
            {name, p.value("country", "-"),
             name == status.value("selected", "") ? status.value("state", "")
                                                  : "",
             p.at("endpoint"), p.at("protocol"),
             score(p) == 1e12 ? "—"
                              : std::to_string(std::lround(score(p))) + " ms",
             history.value(name, Json::object()).value("checked", "—"),
             marked.contains(name), i == idx, i});
      }
      line(5, "i import file/ZIP   I folder   v/V validate");
      help = "Enter select   C connect   d disconnect   x remove   / search   "
             "c country  p probe  Space mark  P batch  f fastest  o sort";
    }
    if (page == 2) {
      line(4, "[ / ]   IP   Domains   Apps   Tables   DNS   Kill switch     " +
                  sections[section]);
      if (section >= 3) {
        try {
          if (poll)
            inspection =
                rpc({{"op", "inspect"}, {"section", sections[section]}})
                    .at("text")
                    .get<std::string>();
          std::istringstream in(inspection);
          int n = 0;
          for (std::string l; std::getline(in, l); ++n)
            if (n >= scroll && n - scroll < ui.height() - 10)
              line(6 + n - scroll, l);
        } catch (const std::exception &e) {
          message = e.what();
        }
        help = "[ / ] section    arrows scroll    q quit";
      } else {
        int top = std::max(0, idx - std::max(0, ui.height() - 12));
        auto baselineRules = fromSettings(load(prefs(), Json::object()));
        for (int i = top; i < count && i - top < ui.height() - 10; i++) {
          int at = visible[i];
          bool admin = size_t(at) >= rr.size();
          auto r = tableRules[at];
          std::string m = r.at("match");
          std::string applied;
          if (admin)
            applied =
                at < adminEnd ? "system policy" : "backend only · pending sync";
          else {
            auto it = std::find(liveRules.begin(), liveRules.end(), r);
            applied = it == liveRules.end() ? "pending sync"
                                            : status.at("ruleStates")
                                                  .at(it - liveRules.begin())
                                                  .get<std::string>();
            applied += std::find(baselineRules.begin(), baselineRules.end(),
                                 r) == baselineRules.end()
                           ? " · unlocked"
                           : " · baseline";
          }
          if (!admin) {
            if (r.at("kind") == "ip")
              for (auto &sys : status.value("systemIPs", Json::array()))
                if (covers(sys, m))
                  applied = "system DIRECT wins";
            for (int j : visible) {
              if (j == at)
                break;
              if (rr[j].value("enabled", true) &&
                  (rr[j].at("match") == m ||
                   (r.at("kind") == "ip" && covers(rr[j].at("match"), m)))) {
                applied = "rule " + std::to_string(j + 1) + " wins";
                break;
              }
            }
          }
          ui.row(6 + i - top,
                 (i == idx ? "> " : "  ") + std::to_string(at + 1) +
                     (section == 2   ? "  P2  "
                      : section == 0 ? "  P3  "
                                     : "  P4  ") +
                     m + "   " + r["action"].get<std::string>() + "   " +
                     applied,
                 i);
        }
        if (count == 0)
          line(6, "No " + sections[section] + " rules. Use Add.");
        help = "[ / ] sections   a add   e edit   space toggle   x remove   s "
               "sync   r reset";
      }
    }
    if (page == 3) {
      line(4,
           "p  Ping through TUN       n  DNS lookup       l  Resolver probe");
      line(6, "i  Public IP              v  IPv6 public IP");
      line(8, "t  Route lookup           b  Download         u  Upload");
      line(10, "g  Change target    h  Path: " +
                   std::string(directTest ? "DIRECT" : "VPN") + "    " +
                   target);
      help = "Esc cancels running diagnostic    q quit";
    }
    if (page == 4) {
      line(4, "Autolaunch    " +
                  std::string(
                      status.value("autolaunch", cfg.value("autolaunch", false))
                          ? "On"
                          : "Off") +
                  "   ·   last successful server");
      line(5, "Theme         " + cfg.value("theme", "dark"));
      line(6, "Ping target   " + target);
      line(7, "Refresh       " + std::to_string(interval) + " s");
      line(8, "Routing       " + std::to_string(rr.size()) + " user rules · " +
                  std::to_string(tableRules.size() - rr.size()) +
                  " system rules");
      line(9,
           "Kill switch   " +
               std::string(status.value("killSwitch", false) ? "On" : "Off") +
               "   ·   system policy");
      line(10, "Unlocked      " + overrides().string());
      line(11, "Baseline      " + (fs::exists(prefs())
                                       ? prefs().string()
                                       : std::string("built-in defaults")));
      line(12, "e  Export routing rules to a JSON file");
      help = "a autolaunch   t theme   g ping target   j refresh interval   r "
             "reset settings";
    }
    if (page == 5) {
      std::vector<std::string> entries;
      std::istringstream events(logText);
      for (std::string row; std::getline(events, row);) {
        // Wrap the message so narrow terminals can still show the failure
        // reason.
        const size_t width = std::max(1, ui.width() - 2);
        for (size_t pos = 0; pos < row.size(); pos += width)
          entries.push_back(row.substr(pos, width));
      }
      int height = std::max(1, ui.height() - 6);
      scroll = std::clamp(scroll, 0, std::max(0, int(entries.size()) - height));
      line(3,
           message.empty() ? "Connection events (UTC, newest first)" : message);
      for (int i = 0; i < height && scroll + i < int(entries.size()); ++i)
        line(5 + i, entries[scroll + i]);
      help = "Up/Down or PgUp/PgDn scroll   Home latest   q quit";
    } else {
      ui.notice = message;
    }
    if (page == 2) {
      ui.actions = {{"IP", 'I'},
                    {"Domains", 'D'},
                    {"Apps", 'A'},
                    {"‹ Section", '['},
                    {"Section ›", ']'}};
      if (section < 3) {
        ui.actions.emplace_back("Add", 'a');
        ui.actions.emplace_back("Edit", 'e');
        ui.actions.emplace_back("Toggle", ' ');
        ui.actions.emplace_back("Delete", 'x');
      }
    } else if (page == 3)
      ui.actions = {
          {"Ping", 'p'}, {"DNS", 'n'}, {"Public IP", 'i'}, {"Path", 'h'}};
    else if (page == 4)
      ui.actions = {{"Routing", '3'},     {"Autolaunch", 'a'}, {"Theme", 't'},
                    {"Ping target", 'g'}, {"Interval", 'j'},   {"Export", 'e'},
                    {"Sync", 's'},        {"Reset", 'r'}};
    if (page == 5)
      ui.actions = {{"Newest", Terminal::Home},
                    {"Page up", Terminal::PgUp},
                    {"Page down", Terminal::PgDown}};
    ui.footer = help;
    ui.show();
    auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                         nextPoll - std::chrono::steady_clock::now())
                         .count();
    int k = ui.key(static_cast<int>(std::max<long long>(0, remaining)));
    if (k == -1)
      continue;
    if (k == Terminal::RowClick && (page == 1 || page == 2)) {
      if (ui.clickedRow < 0 || ui.clickedRow >= count)
        continue;
      idx = ui.clickedRow;
      if (page == 2)
        continue;
      k = '\n';
    }
    if (k == 'q')
      return 0;
    if (page == 5) {
      if (k == Terminal::Up || k == Terminal::Down)
        scroll += k == Terminal::Up ? -ui.steps : ui.steps;
      if (k == Terminal::PgUp || k == Terminal::PgDown)
        scroll += (k == Terminal::PgUp ? -1 : 1) * std::max(1, ui.height() - 6);
      if (k == Terminal::Home)
        scroll = 0;
      if (connection.valid() || k == Terminal::Home || k == Terminal::PgUp ||
          k == Terminal::PgDown || k == Terminal::Up || k == Terminal::Down)
        continue;
    }
    if (k >= '1' && k <= '6') {
      nextPoll = {};
      page = k - '1';
      scroll = 0;
      idx = 0;
      message.clear();

      continue;
    }
    if (page == 2 && (k == 'I' || k == 'D' || k == 'A')) {
      section = k == 'I' ? 0 : k == 'D' ? 1 : 2;
      idx = scroll = 0;
      continue;
    }
    if (page == 2 && (k == '[' || k == ']')) {
      nextPoll = {};
      section = (section + (k == ']' ? 1 : 5)) % 6;
      idx = 0;
      scroll = 0;
      continue;
    }
    if (page == 2 && section >= 3 &&
        (k == Terminal::Down || k == Terminal::Up)) {
      scroll =
          std::max(0, scroll + (k == Terminal::Down ? ui.steps : -ui.steps));
      continue;
    }
    if (k == Terminal::Down) {
      idx += ui.steps;
      continue;
    }
    if (k == Terminal::Up) {
      idx -= ui.steps;
      continue;
    }
    try {
      nextPoll = {};
      if ((page == 0 || page == 1) && k == 'C' && canConnect) {
        // Exiting the viewer does not cancel the daemon's transaction.
        std::packaged_task<Json()> request(
            [choice] { return rpc({{"op", "connect"}, {"name", choice}}); });
        connection = request.get_future();
        std::thread(std::move(request)).detach();
        page = 5;
        scroll = 0;
        status["state"] = "connecting";
        message = "Connecting " + choice;
      }
      if ((page == 0 || page == 1) && k == 'd')
        message = rpc({{"op", "disconnect"}}).dump();
      if (page == 1) {
        if (k == '/')
          search = prompt("Filter: ");
        if (k == 'i' || k == 'I' || k == 'v' || k == 'V') {
          bool validate = k == 'v' || k == 'V';
          auto mode =
              k == 'I' || k == 'V' ? PickMode::directory : PickMode::profile;
          auto path = choosePath(mode,
                                 validate ? "Validate OpenVPN profiles"
                                          : "Import OpenVPN profiles",
                                 &ui);
          if (path) {
            Args cmd{importHelper(), *path};
            if (validate)
              cmd.insert(cmd.end(), {"--validate", executable()});
            message = output(cmd, 120, nullptr);
          }
        }

        if (!rows.empty()) {
          auto n = rows[idx]["name"];
          if (k == 'c')
            message = rpc({{"op", "country"},
                           {"name", n},
                           {"country", prompt("Country (name or ISO code): ")}})
                          .dump();
          if (k == '\n') {
            auto name = n.get<std::string>();
            fs::create_directories(choiceFile.parent_path());
            write(choiceFile, n.dump());
            choice = name;
            message = "Selected " + name;
          }
          if (k == 'x' && prompt("Type DELETE: ") == "DELETE")
            message = rpc({{"op", "remove"}, {"name", n}}).dump();
          if (k == ' ') {
            auto name = n.get<std::string>();
            if (!marked.erase(name))
              marked.insert(name);
          }
          if (k == 'o') {
            latencySort = !latencySort;
          }
          if (k == 'f') {
            auto best = std::ranges::min_element(rows, {}, score);
            require(score(*best) != 1e12, "no endpoint measurements");
            idx = std::distance(rows.begin(), best);
          }
          if (k == 'p' || k == 'P') {
            if (k == 'P')
              require(!marked.empty(), "mark servers with Space");

            for (auto &p : rows) {
              auto name = p["name"].get<std::string>();
              if (k == 'p' ? p["name"] != n : !marked.contains(name))
                continue;
              ui.footer = "Measuring " + name + "  Esc cancels";
              ui.show();
              auto report =
                  output(scope("probe_direct",
                               {executable(), "measured", "endpoint",
                                p["endpoint"].get<std::string>(), "direct"}),
                         18, cancelled);
              Json h = Json::parse(report.substr(report.find('{')));
              time_t now = time(nullptr);
              char stamp[24];
              strftime(stamp, sizeof stamp, "%Y-%m-%d %H:%M", localtime(&now));
              h["checked"] = stamp;
              history[name] = h;
              fs::create_directories(historyPath.parent_path());
              write(historyPath, history.dump());
              message = h.dump();
            }
          }
        }
      }
      if (page == 2 && section < 3 &&
          (k == 'a' || k == 'e' || k == 'x' || k == ' ')) {
        if (k != 'a' && !visible.empty())
          require(size_t(visible.at(idx)) < rr.size(),
                  "Rule is managed by the system administrator");
        if (k == 'a' || (k == 'e' && !visible.empty())) {
          auto kind = sections[section], m = prompt("Match: "),
               a = prompt("Action (vpn/direct): ");
          Json r = {{"kind", kind},
                    {"match", kind == "app" ? slice(m) : m},
                    {"action", a},
                    {"enabled", true}};
          if (k == 'a')
            rr.push_back(r);
          else
            rr[visible.at(idx)] = r;
        } else if (!visible.empty()) {
          if (k == 'x')
            rr.erase(visible.at(idx));
          else
            rr[visible.at(idx)]["enabled"] =
                !rr[visible.at(idx)].value("enabled", true);
        }
        saveRules(rr);
        message = "Applied";
      }
      if ((page == 2 || page == 4) && k == 's')
        message = syncCurrent().dump();
      if ((page == 2 || page == 4) && k == 'r' &&
          prompt("Type RESET: ") == "RESET") {
        saveConfig(resetLayer(), Apply::all);
        cfg = settings();
        auto defaults = cfg.value("diagnostics", Json::object());
        target = defaults.value("pingTarget", "1.1.1.1");
        interval = std::clamp(defaults.value("pingInterval", 5), 1, 3600);
        ui.light = cfg.value("theme", "dark") == "light";
        message = "Restored baseline settings";
      }
      if (page == 4 && k == 'e') {
        if (auto path =
                choosePath(PickMode::saveRules, "Save routing rules", &ui)) {
          auto type = fs::symlink_status(*path).type();
          require(type == fs::file_type::not_found ||
                      type == fs::file_type::regular,
                  "choose a regular file for export");
          if (type == fs::file_type::not_found ||
              prompt("Replace existing file? Type YES: ") == "YES") {
            write(*path, rules().dump(2) + "\n");
            message = "Saved " + path->string();
          }
        }
      }
      if (page == 4 && (k == 't' || k == 'g' || k == 'a' || k == 'j')) {
        auto layer = unlocked();
        if (k == 'a')
          layer["autolaunch"] = !status.value("autolaunch", false);
        if (k == 'g') {
          auto value = prompt("Ping target");
          if (value.empty())
            continue;
          require((domain(value) && !value.starts_with("*.")) ||
                      (cidr(value) && !value.contains('/')),
                  "invalid ping target");
          layer["diagnostics"]["pingTarget"] = value;
        }
        if (k == 'j') {
          auto value = prompt("Refresh interval in seconds (1–3600)");
          if (value.empty())
            continue;
          require(value.size() <= 4 &&
                      value.find_first_not_of("0123456789") == value.npos,
                  "invalid interval");
          int n = std::stoi(value);
          require(n >= 1 && n <= 3600, "invalid interval");
          layer["diagnostics"]["pingInterval"] = n;
        }
        if (k == 't')
          layer["theme"] = ui.light ? "dark" : "light";
        saveConfig(layer, k == 'a' ? Apply::boot : Apply::local);
        cfg = settings(layer);
        auto diagnostics = cfg.value("diagnostics", Json::object());
        target = diagnostics.value("pingTarget", "1.1.1.1");
        interval = diagnostics.value("pingInterval", 5);
        ui.light = cfg.value("theme", "dark") == "light";
        message = "Settings saved";
      }
      if (page == 3) {
        if (k == 'h')
          directTest = !directTest;
        if (k == 'g')
          target = prompt("Target: ");
        std::map<int, std::string> tests = {
            {'p', "ping"},      {'n', "dns"},   {'l', "dns-leak"},
            {'i', "public-ip"}, {'v', "ipv6"},  {'t', "route"},
            {'b', "download"},  {'u', "upload"}};
        if (tests.contains(k)) {
          bool confirmed = (k != 'b' && k != 'u') ||
                           prompt("Transfer 1 MiB? Type YES: ") == "YES";

          ui.footer = "Measuring... Esc cancels";
          ui.show();
          if (directTest) {
            Args inner = {executable(), "measured", tests[k], target, "direct"};
            if (confirmed)
              inner.push_back("--confirm");
            message = output(scope("probe_direct", inner), 23, cancelled);
          } else {
            message = diag(tests[k], target, "vpn", confirmed, cancelled);
            if (k == 'i')
              publicIP = message;
            if (k == 'p')
              ping = Json::parse(message);
          }
        }
      }
    } catch (const std::exception &e) {
      message = e.what();
    }
  }
}
} // namespace
int main(int argc, char **argv) {
  try {
    std::setlocale(LC_CTYPE, "");
    Args a(argv + 1, argv + argc);
    if (a.empty()) {
      require(geteuid() != 0, "run the TUI as a normal user");
      return tui();
    }
    auto op = a[0];
    if (op == "--help" || op == "help") {
      std::cout
          << "vpnctl [status|logs|connect NAME|disconnect|remove NAME|import "
             "[PATH]|validate [PATH]|check-settings "
             "[PATH]|sync|reset|export|launch APP COMMAND...|diag TEST "
             "TARGET vpn|direct [--confirm]]\n";
      return 0;
    }
    if (op == "exec-ready" && a.size() >= 2) {
      rpc({{"op", "refresh"}});
      execute(Args(a.begin() + 1, a.end()));
    }
    if (op == "launch" && a.size() >= 3) {
      auto r = rules();
      auto live = rpc({{"op", "status"}});
      if (live.at("allowDirectProbe") == true && live.at("rules") != r)
        syncCurrent();
      execute(scope(a[1], Args(a.begin() + 2, a.end())));
    }
    if ((op == "import" || op == "validate" || op == "check-settings") &&
        a.size() == 1) {
      auto mode =
          op == "check-settings" ? PickMode::settings : PickMode::profile;
      auto path = choosePath(mode, "VPNCTL: " + op, nullptr);
      if (!path)
        return 0;
      a.push_back(*path);
    }
    if (op == "check-settings" && a.size() == 2) {
      auto c = Json::parse(read(a[1]));
      require(!c.contains("autolaunch") || c.at("autolaunch").is_boolean(),
              "invalid autolaunch");
      auto d = c.value("diagnostics", Json::object());
      auto target = d.value("pingTarget", "1.1.1.1");
      require((domain(target) && !target.starts_with("*.")) ||
                  (cidr(target) && !target.contains('/')),
              "invalid ping target");
      for (auto &r : fromSettings(c)) {
        if (r.at("kind") == "domain")
          require(domain(r.at("match")), "invalid domain");
        else
          ruleLine(r, getuid());
      }
      return 0;
    }
    if (op == "validate-stdin") {
      std::string raw(std::istreambuf_iterator<char>(std::cin), {});
      profile(raw);
      return 0;
    }
    if (op == "validate" && a.size() == 2)
      execute({importHelper(), a[1], "--validate", executable()});
    if (op == "import" && a.size() == 2)
      execute({importHelper(), a[1]});
    if (op == "diag" && a.size() >= 2) {
      bool confirm = a.back() == "--confirm";
      if (confirm)
        a.pop_back();
      if (a.size() == 2)
        a.push_back(settings()
                        .value("diagnostics", Json::object())
                        .value("pingTarget", "1.1.1.1"));
      if (a.size() == 3)
        a.push_back("vpn");
      if (confirm)
        a.push_back("--confirm");
    }
    if (op == "diag" && a.size() >= 4 && a[1] == "endpoint")
      require(a[3] == "direct", "use direct for endpoint latency");
    if (op == "diag" && a.size() >= 4 && a[3] == "direct") {
      Args inner = {executable(), "measured"};
      inner.insert(inner.end(), a.begin() + 1, a.end());
      execute(scope("probe_direct", inner));
    }
    if ((op == "diag" || op == "measured") && a.size() >= 4) {
      std::signal(SIGINT, interrupt);
      std::cout << diag(a[1], a[2], a[3], a.size() == 5 && a[4] == "--confirm",
                        cliCancelled)
                << "\n";
      return 0;
    }
    if (op == "logs" && a.size() == 1) {
      std::cout << rpc({{"op", "logs"}}).at("events").get<std::string>();
      return 0;
    }
    if (op == "export") {
      std::cout << rules().dump(2) << "\n";
      return 0;
    }
    if (op == "reset") {
      saveConfig(resetLayer(), Apply::all);
      return 0;
    }
    Json r;
    if (op == "sync")
      r = syncCurrent();
    else if ((op == "connect" || op == "remove") && a.size() == 2)
      r = rpc({{"op", op}, {"name", a[1]}});
    else {
      require(op == "status" || op == "refresh" || op == "disconnect",
              "unknown arguments");
      r = rpc({{"op", op}});
    }
    std::cout << r.dump(2) << "\n";
  } catch (const std::exception &e) {
    std::cerr << e.what() << "\n";
    return 1;
  }
}
