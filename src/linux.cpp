#include "vpnctl/core.hpp"
#include <arpa/inet.h>
#include <chrono>
#include <fcntl.h>
#include <fstream>
#include <poll.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
namespace vpn {
std::string read(const fs::path &p) {
  std::ifstream in(p);
  require(in.good(), "cannot read " + p.string());
  return {std::istreambuf_iterator<char>(in), {}};
}
void write(const fs::path &p, const std::string &s) {
  auto tmp = p;
  tmp += ".XXXXXX";
  auto name = tmp.string();
  int fd = mkstemp(name.data());
  require(fd >= 0, "create failed");
  size_t n = 0;
  while (n < s.size()) {
    auto k = ::write(fd, s.data() + n, s.size() - n);
    if (k <= 0)
      break;
    n += k;
  }
  bool ok = n == s.size() && fsync(fd) == 0;
  ok = (close(fd) == 0) && ok;
  if (!ok || rename(name.c_str(), p.c_str())) {
    unlink(name.c_str());
    throw std::runtime_error("atomic write failed");
  }
}
Result run(const Args &args, int seconds, bool (*cancel)()) {
  std::vector<char *> av;
  for (auto &s : args)
    av.push_back(const_cast<char *>(s.c_str()));
  av.push_back(nullptr);
  int pp[2];
  require(pipe2(pp, O_CLOEXEC) == 0, "pipe failed");
  auto parent = getpid();
  auto pid = fork();
  if (pid == 0) {
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    if (getppid() != parent)
      _exit(1);
    setpgid(0, 0);
    setenv("LC_ALL", "C", 1);
    dup2(pp[1], 1);
    dup2(pp[1], 2);
    close(pp[0]);
    close(pp[1]);
    int null = open("/dev/null", O_RDONLY);
    dup2(null, 0);
    execvp(av[0], av.data());
    _exit(127);
  }
  close(pp[1]);
  if (pid < 0) {
    close(pp[0]);
    throw std::runtime_error("fork failed");
  }
  setpgid(pid, pid);
  fcntl(pp[0], F_SETFL, O_NONBLOCK);
  auto until = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
  Result r{-1, {}};
  int st;
  while (true) {
    char buf[4096];
    auto n = ::read(pp[0], buf, sizeof buf);
    if (n > 0 && r.output.size() < 65536)
      r.output.append(buf, n);
    if (n <= 0 && waitpid(pid, &st, WNOHANG) == pid) {
      if (WIFEXITED(st))
        r.status = WEXITSTATUS(st);
      break;
    }
    if (std::chrono::steady_clock::now() >= until || (cancel && cancel())) {
      kill(-pid, SIGKILL);
      waitpid(pid, &st, 0);
      r.output += "\ntimeout or cancelled";
      break;
    }
    pollfd f{pp[0], POLLIN, 0};
    poll(&f, 1, 50);
  }
  close(pp[0]);
  return r;
}
static void transfer(int fd, char *buf, size_t n, bool sending) {
  while (n) {
    ssize_t k = sending ? send(fd, buf, n, MSG_NOSIGNAL) : recv(fd, buf, n, 0);
    require(k > 0, "IPC closed or timed out");
    buf += k;
    n -= k;
  }
}
void sendJson(int fd, const Json &j) {
  auto s = j.dump();
  require(s.size() <= 2 * 1024 * 1024, "request too large");
  uint32_t n = htonl(s.size());
  transfer(fd, (char *)&n, 4, true);
  transfer(fd, s.data(), s.size(), true);
}
Json recvJson(int fd) {
  uint32_t n;
  transfer(fd, (char *)&n, 4, false);
  n = ntohl(n);
  require(n > 0 && n <= 2 * 1024 * 1024, "invalid frame");
  std::string s(n, 0);
  transfer(fd, s.data(), n, false);
  return Json::parse(s);
}
Json rpc(const Json &j) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  sockaddr_un a{AF_UNIX, "/run/vpnctl/control.sock"};
  try {
    require(connect(fd, (sockaddr *)&a, sizeof a) == 0,
            "vpnctl socket unavailable or access denied");
    timeval t{120, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof t);
    sendJson(fd, j);
    auto r = recvJson(fd);
    require(!r.contains("error"), r.value("error", ""));
    close(fd);
    return r;
  } catch (...) {
    close(fd);
    throw;
  }
}
std::string ruleLine(const Json &r, uid_t uid) {
  auto kind = r.at("kind").get<std::string>(),
       m = r.at("match").get<std::string>(),
       a = r.at("action").get<std::string>();
  require(a == "direct" || a == "vpn", "invalid action");
  std::string expr;
  if (kind == "ip") {
    require(cidr(m), "invalid CIDR");
    expr = (m.contains(':') ? "ip6 daddr " : "ip daddr ") + m;
  } else {
    require(kind == "app" && id(m) &&
                m.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789_") ==
                    m.npos,
            "invalid application slice");
    auto u = std::to_string(uid);
    auto path = "user.slice/user-" + u + ".slice/user@" + u +
                ".service/vpnctl.slice/vpnctl-" + m + ".slice";
    if (!fs::exists(fs::path("/sys/fs/cgroup") / path))
      return "";
    expr = "socket cgroupv2 level 5 \"" + path + "\"";
  }
  return expr + " meta mark set " + (a == "direct" ? "0x7652" : "0x7651") +
         " accept";
}
} // namespace vpn
