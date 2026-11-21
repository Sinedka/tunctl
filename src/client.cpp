#include "vpnctl/core.hpp"
#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstring>
#include <ctime>
#include <curses.h>
#include <iomanip>
#include <iostream>
#include <regex>
#include <set>
#include <sstream>
#include <unistd.h>

using namespace vpn;
namespace {
volatile std::sig_atomic_t interrupted = 0;
void interrupt(int) { interrupted = 1; }
bool cliCancelled() { return interrupted != 0; }
fs::path xdg(const char *var, const char *fallback) {
  if (auto p = getenv(var); p && *p)
    return fs::path(p) / "vpnctl";
  auto home = getenv("HOME");
  require(home, "HOME is unset");
  return fs::path(home) / fallback / "vpnctl";
}
auto prefs() { return xdg("XDG_CONFIG_HOME", ".config") / "settings.json"; }
auto overrides() {
  return xdg("XDG_STATE_HOME", ".local/state") / "overrides.json";
}
Json load(const fs::path &p, Json fallback) {
  return fs::exists(p) ? Json::parse(read(p)) : fallback;
}
Json settings() {
  auto cfg = load(prefs(), Json::object());
  cfg.merge_patch(
      load(overrides().parent_path() / "preferences.json", Json::object()));
  return cfg;
}
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
Json baseRules() { return fromSettings(settings()); }
Json rules() { return load(overrides(), baseRules()); }
Json sync(const Json &r) { return rpc({{"op", "sync"}, {"rules", r}}); }
void saveRules(const Json &r) {
  fs::create_directories(overrides().parent_path());
  auto old = rules();
  sync(r);
  try {
    write(overrides(), r.dump(2));
  } catch (...) {
    sync(old);
    throw;
  }
}
Args scope(std::string name, const Args &args) {
  Args a = {"systemd-run",
            "--user",
            "--scope",
            "--quiet",
            "--slice=vpnctl-" + slice(name) + ".slice",
            "--",
            "vpnctl",
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
std::string prompt(const std::string &s) {
  timeout(-1);
  echo();
  curs_set(1);
  move(LINES - 2, 0);
  clrtoeol();
  addnstr(s.c_str(), COLS - 1);
  char v[1024]{};
  getnstr(v, sizeof(v) - 1);
  noecho();
  curs_set(0);
  return v;
}
bool cancelled() { return getch() == 27; }
void line(int y, const std::string &s) {
  if (y >= 0 && y < LINES)
    mvaddnstr(y, 1, s.c_str(), std::max(0, COLS - 2));
}
int tui() {
  require(isatty(0) && isatty(1), "open a terminal or use vpnctl status");
  initscr();
  struct End {
    ~End() { endwin(); }
  } end;
  cbreak();
  noecho();
  keypad(stdscr, true);
  curs_set(0);
  start_color();
  use_default_colors();
  auto cfg = settings();
  auto d = cfg.value("diagnostics", Json::object());
  auto target = d.value("pingTarget", "1.1.1.1");
  int interval = std::clamp(d.value("pingInterval", 5), 1, 3600);
  init_pair(1, cfg.value("theme", "dark") == "light" ? COLOR_BLUE : COLOR_CYAN,
            -1);
  int page = 0, idx = 0, section = 0, scroll = 0;
  std::vector<std::string> sections = {"ip",     "domain", "app",
                                       "tables", "dns",    "guard"};
  std::string message, search, publicIP, session;
  bool latencySort = false, directTest = false;
  std::set<std::string> marked;
  Json ping = Json::object();
  auto historyPath = overrides().parent_path() / "latency.json";
  Json history = load(historyPath, Json::object());

  Json status;
  std::string tabs[] = {"Dashboard",   "Servers",  "Routing",
                        "Diagnostics", "Settings", "Logs"};
  unsigned long long prevRx = 0, prevTx = 0;
  std::string rates;
  auto last = std::chrono::steady_clock::now();
  while (true) {
    try {
      status = rpc({{"op", "status"}});
    } catch (const std::exception &e) {
      status = {{"state", "unavailable"}};
      message = e.what();
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
    erase();
    attron(COLOR_PAIR(1) | A_BOLD);
    line(0, "VPNCTL    " + status.value("state", "unknown") + "    " +
                status.value("selected", ""));
    attroff(COLOR_PAIR(1) | A_BOLD);
    std::string nav;
    for (int i = 0; i < 6; i++)
      nav += " " + std::to_string(i + 1) + " " + tabs[i] +
             (i == page ? " *  " : "    ");
    line(2, nav);
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

    auto rr = rules();
    std::vector<int> visible;
    for (size_t i = 0; i < rr.size(); ++i)
      if (rr[i].at("kind") == sections[section])
        visible.push_back(i);
    int count = page == 1 ? int(rows.size()) : int(visible.size());
    idx = std::clamp(idx, 0, std::max(0, count - 1));
    std::string help = "1-6 views    q quit";
    if (page == 0) {
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
      line(4, "Profile / country / state / endpoint / protocol    filter: " +
                  search);
      int top = std::max(0, idx - std::max(0, LINES - 12));
      for (int i = top; i < int(rows.size()) && i - top < LINES - 10; i++) {
        auto &p = rows[i];
        line(
            6 + i - top,
            (i == idx ? "> " : "  ") + p["name"].get<std::string>() + "  " +
                p.value("country", "-") + "  " +
                (p["name"] == status.value("selected", "")
                     ? status.value("state", "")
                     : "") +
                "  " + p["endpoint"].get<std::string>() + "  " +
                p["protocol"].get<std::string>() + "   " +
                (score(p) == 1e12 ? "-" : std::to_string(score(p)) + " ms") +
                "   " +
                history.value(p["name"].get<std::string>(), Json::object())
                    .value("checked", "-") +
                (marked.contains(p["name"].get<std::string>()) ? "  [x]" : ""));
      }
      help = "Enter connect   d disconnect   i import   x remove   / search   "
             "c country  p probe  Space mark  P batch  f fastest  o sort";
    }
    if (page == 2) {
      line(4, "[ / ]   IP   Domains   Apps   Tables   DNS   Kill switch     " +
                  sections[section]);
      if (section >= 3) {
        try {
          std::istringstream in(
              rpc({{"op", "inspect"}, {"section", sections[section]}})
                  .at("text")
                  .get<std::string>());
          int n = 0;
          for (std::string l; std::getline(in, l); ++n)
            if (n >= scroll && n - scroll < LINES - 10)
              line(6 + n - scroll, l);
        } catch (const std::exception &e) {
          message = e.what();
        }
        help = "[ / ] section    arrows scroll    q quit";
      } else {
        int top = std::max(0, idx - std::max(0, LINES - 12));
        bool same = status.value("rules", Json::array()) == rr;
        for (int i = top; i < count && i - top < LINES - 10; i++) {
          int at = visible[i];
          auto r = rr[at];
          std::string m = r.at("match");
          std::string applied =
              same ? status.at("ruleStates")[at].get<std::string>()
                   : "pending sync";
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
          line(6 + i - top, (i == idx ? "> " : "  ") + std::to_string(at + 1) +
                                (section == 2   ? "  P2  "
                                 : section == 0 ? "  P3  "
                                                : "  P4  ") +
                                m + "   " + r["action"].get<std::string>() +
                                "   " + applied);
        }
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
      line(4, "Declarative: " + prefs().string());
      line(6, "Runtime:     " + overrides().string());
      line(8, "System DIRECT IPs: " +
                  status.value("systemIPs", Json::array()).dump());
      line(10, "DNS domains: " + status.value("domains", Json::array()).dump());
      help = "t theme    g ping target    s synchronize    r reset rules    q "
             "quit";
    }
    if (page == 5) {
      line(4, "Connection events");
      std::istringstream events(status.value("events", ""));
      int y = 6;
      for (std::string e; std::getline(events, e) && y < LINES - 2;)
        line(y++, e);
    }
    int y = std::max(5, LINES - 7);
    std::istringstream msg(message);
    for (std::string l; std::getline(msg, l) && y < LINES - 2;)
      line(y++, l);
    line(LINES - 1, help);
    refresh();
    timeout(interval * 1000);
    int k = getch();
    if (k == 'q')
      return 0;
    if (k >= '1' && k <= '6') {
      page = k - '1';
      idx = 0;
      message.clear();

      continue;
    }
    if (page == 2 && (k == '[' || k == ']')) {
      section = (section + (k == ']' ? 1 : 5)) % 6;
      idx = 0;
      scroll = 0;
      continue;
    }
    if (page == 2 && section >= 3 && (k == KEY_DOWN || k == KEY_UP)) {
      scroll = std::max(0, scroll + (k == KEY_DOWN ? 1 : -1));
      continue;
    }
    if (k == KEY_DOWN) {
      idx++;
      continue;
    }
    if (k == KEY_UP) {
      idx--;
      continue;
    }
    try {
      if (page == 1) {
        if (k == '/')
          search = prompt("Filter: ");
        if (k == 'i') {
          auto p = prompt("Profile / directory / ZIP: ");
          message = output({"vpnctl-import", p}, 120, nullptr);
        }
        if (k == 'd')
          message = rpc({{"op", "disconnect"}}).dump();
        if (!rows.empty()) {
          auto n = rows[idx]["name"];
          if (k == 'c')
            message = rpc({{"op", "country"},
                           {"name", n},
                           {"country", prompt("Country (name or ISO code): ")}})
                          .dump();
          if (k == '\n' || (k == 'x' && prompt("Type DELETE: ") == "DELETE"))
            message =
                rpc({{"op", k == 'x' ? "remove" : "connect"}, {"name", n}})
                    .dump();
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
            nodelay(stdscr, true);
            for (auto &p : rows) {
              auto name = p["name"].get<std::string>();
              if (k == 'p' ? p["name"] != n : !marked.contains(name))
                continue;
              line(LINES - 1, "Measuring " + name + "  Esc cancels");
              refresh();
              auto report =
                  output(scope("probe_direct",
                               {"vpnctl", "measured", "endpoint",
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
        message = sync(rules()).dump();
      if ((page == 2 || page == 4) && k == 'r' &&
          prompt("Type RESET: ") == "RESET") {
        sync(baseRules());
        fs::remove(overrides());
        message = "Declarative rules applied";
      }
      if (page == 4 && (k == 't' || k == 'g')) {
        auto file = overrides().parent_path() / "preferences.json";
        auto pref = load(file, Json::object());
        if (k == 'g') {
          target = prompt("Ping target: ");
          require(domain(target) || cidr(target), "invalid target");
          pref["diagnostics"]["pingTarget"] = target;
        } else {
          auto light = settings().value("theme", "dark") == "dark";
          pref["theme"] = light ? "light" : "dark";
          init_pair(1, light ? COLOR_BLUE : COLOR_CYAN, -1);
        }
        fs::create_directories(file.parent_path());
        write(file, pref.dump(2));
        message = "Preferences saved";
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
          nodelay(stdscr, true);
          line(LINES - 1, "Measuring... Esc cancels");
          refresh();
          if (directTest) {
            Args inner = {"vpnctl", "measured", tests[k], target, "direct"};
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
    Args a(argv + 1, argv + argc);
    if (a.empty()) {
      require(geteuid() != 0, "run the TUI as a normal user");
      return tui();
    }
    auto op = a[0];
    if (op == "--help" || op == "help") {
      std::cout << "vpnctl [status|connect NAME|disconnect|remove NAME|import "
                   "PATH|sync|reset|export|launch APP COMMAND...|diag TEST "
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
        sync(r);
      execute(scope(a[1], Args(a.begin() + 2, a.end())));
    }
    if (op == "check-settings" && a.size() == 2) {
      auto c = Json::parse(read(a[1]));
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
      execute({"vpnctl-import", a[1], "--validate"});
    if (op == "import" && a.size() == 2)
      execute({"vpnctl-import", a[1]});
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
      Args inner = {"vpnctl", "measured"};
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
    if (op == "export") {
      std::cout << rules().dump(2) << "\n";
      return 0;
    }
    if (op == "reset") {
      sync(baseRules());
      fs::remove(overrides());
      return 0;
    }
    Json r;
    if (op == "sync")
      r = sync(rules());
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
