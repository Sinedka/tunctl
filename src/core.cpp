#include "vpnctl/core.hpp"
#include <arpa/inet.h>
#include <charconv>
#include <memory>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <regex>
#include <set>
#include <sstream>
namespace vpn {
void require(bool ok, const std::string &e) {
  if (!ok)
    throw std::runtime_error(e);
}
bool id(const std::string &s) {
  static const std::regex re("[A-Za-z0-9][A-Za-z0-9_.-]{0,95}");
  return std::regex_match(s, re);
}
static bool address(const std::string &s, int family) {
  in6_addr a{};
  return inet_pton(family, s.c_str(), &a) == 1 && s.find('\0') == s.npos;
}
bool cidr(std::string s) {
  auto i = s.find('/');
  auto ip = s.substr(0, i);
  int max = address(ip, AF_INET) ? 32 : address(ip, AF_INET6) ? 128 : 0;
  if (!max)
    return false;
  if (i == s.npos)
    return true;
  int n;
  auto [p, e] = std::from_chars(s.data() + i + 1, s.data() + s.size(), n);
  return e == std::errc{} && p == s.data() + s.size() && n >= 0 && n <= max;
}
bool covers(const std::string &broad, const std::string &narrow) {
  if (!cidr(broad) || !cidr(narrow) ||
      broad.contains(':') != narrow.contains(':'))
    return false;
  auto family = broad.contains(':') ? AF_INET6 : AF_INET;
  auto prefix = [&](const std::string &addr) {
    return addr.contains('/')  ? std::stoi(addr.substr(addr.find('/') + 1))
           : family == AF_INET ? 32
                               : 128;
  };
  auto bits = prefix(broad);
  if (bits > prefix(narrow))
    return false;
  unsigned char a[16]{}, b[16]{};
  inet_pton(family, broad.substr(0, broad.find('/')).c_str(), a);
  inet_pton(family, narrow.substr(0, narrow.find('/')).c_str(), b);
  for (int i = 0; i < bits; i++)
    if ((a[i / 8] ^ b[i / 8]) & (128 >> (i % 8)))
      return false;
  return true;
}
bool domain(std::string s) {
  if (s.starts_with("*."))
    s.erase(0, 2);
  static const std::regex label("[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?");
  if (s.empty() || s.size() > 253 || s.back() == '.')
    return false;
  std::istringstream in(s);
  while (std::getline(in, s, '.'))
    if (!std::regex_match(s, label))
      return false;
  return true;
}
std::string digest(const std::string &data) {
  unsigned char bytes[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char *>(data.data()), data.size(),
         bytes);
  static constexpr char hex[] = "0123456789abcdef";
  std::string out;
  for (auto b : bytes) {
    out += hex[b >> 4];
    out += hex[b & 15];
  }
  return out;
}
static void verifyMaterial(const std::map<std::string, std::string> &blobs) {
  auto certificate = [&](const std::string &text) {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(
        BIO_new_mem_buf(text.data(), text.size()), BIO_free);
    return std::unique_ptr<X509, decltype(&X509_free)>(
        bio ? PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr) : nullptr,
        X509_free);
  };
  require(bool(certificate(blobs.at("ca"))), "invalid PEM CA certificate");
  require(blobs.contains("cert") == blobs.contains("key"),
          "client certificate and key must be supplied together");
  if (!blobs.contains("cert"))
    return;
  auto cert = certificate(blobs.at("cert"));
  auto &k = blobs.at("key");
  std::unique_ptr<BIO, decltype(&BIO_free)> bio(
      BIO_new_mem_buf(k.data(), k.size()), BIO_free);
  auto noPrompt = [](char *, int, int, void *) { return 0; };
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
      bio ? PEM_read_bio_PrivateKey(bio.get(), nullptr, noPrompt, nullptr)
          : nullptr,
      EVP_PKEY_free);
  require(cert && key && X509_check_private_key(cert.get(), key.get()) == 1,
          "invalid PEM or mismatched client certificate and key");
}
Profile profile(const std::string &raw) {
  require(raw.size() <= 1024 * 1024, "profile too large");
  Profile p{"client\ndev vpnctl0\ndev-type tun\nremote-cert-tls server\n", "",
            "udp"};
  std::string block, line;
  bool ca = false;
  std::map<std::string, std::string> material;
  size_t number = 0;
  const std::set<std::string> blobs = {
      "ca",        "cert",         "key",           "tls-auth",
      "tls-crypt", "tls-crypt-v2", "auth-user-pass"};
  const std::set<std::string> flags = {"nobind",       "persist-key",
                                       "persist-tun",  "remote-random",
                                       "auth-nocache", "float"};
  const std::set<std::string> scalar = {"auth",
                                        "cipher",
                                        "data-ciphers",
                                        "data-ciphers-fallback",
                                        "tls-version-min",
                                        "key-direction",
                                        "sndbuf",
                                        "rcvbuf",
                                        "resolv-retry",
                                        "tun-mtu",
                                        "mssfix",
                                        "explicit-exit-notify",
                                        "connect-retry-max",
                                        "ping",
                                        "ping-restart"};
  std::istringstream in(raw);
  while (std::getline(in, line)) {
    ++number;
    if (line.ends_with('\r'))
      line.pop_back();
    require(line.size() < 16384 && std::all_of(line.begin(), line.end(),
                                               [](unsigned char c) {
                                                 return c == '\t' ||
                                                        (c >= 32 && c <= 126);
                                               }),
            "invalid profile characters");
    if (!block.empty()) {
      if (line == "</" + block + ">")
        block.clear();
      else {
        material[block] += line + "\n";
        require(line.find_first_of("<>\\") == line.npos, "invalid inline data");
      }
      p.config += line + "\n";
      continue;
    }
    std::istringstream words(line);
    Args w;
    for (std::string t; words >> t;)
      w.push_back(t);
    if (w.empty() || w[0][0] == '#' || w[0][0] == ';')
      continue;
    auto k = w[0];
    if (k.starts_with('<') && k.ends_with('>') && w.size() == 1) {
      block = k.substr(1, k.size() - 2);
      require(blobs.contains(block), "unsupported inline block");
      require(material.emplace(block, "").second, "duplicate inline block");
      ca |= block == "ca";
      p.config += k + "\n";
      continue;
    }
    if ((k == "client" && w.size() == 1) ||
        (k == "dev" && w.size() == 2 && w[1] == "tun") ||
        (k == "remote-cert-tls" && w.size() == 2 && w[1] == "server"))
      continue;
    auto proto = [](const std::string &s) {
      return s == "udp" || s == "udp4" || s == "udp6" || s == "tcp-client" ||
             s == "tcp4-client" || s == "tcp6-client";
    };
    bool ok = flags.contains(k) && w.size() == 1;
    if (k == "remote" && w.size() == 4 && w[3] == "tcp")
      w[3] = "tcp-client";
    if (k == "remote" && w.size() >= 2 && w.size() <= 4) {
      ok =
          (address(w[1], AF_INET6) ||
           (domain(w[1]) && !w[1].starts_with("*."))) &&
          (w.size() < 3 || (w[2].size() <= 5 &&
                            w[2].find_first_not_of("0123456789") == w[2].npos &&
                            !w[2].empty() && std::stoi(w[2]) > 0 &&
                            std::stoi(w[2]) <= 65535)) &&
          (w.size() < 4 || proto(w[3]));
      if (p.endpoint.empty())
        p.endpoint = w[1];
    }
    if (k == "proto" && w.size() == 2) {
      if (w[1] == "tcp")
        w[1] = "tcp-client";
      ok = proto(w[1]);
      p.protocol = w[1];
    }
    if ((k == "verb" || k == "mute") && w.size() == 2)
      continue;
    if (k == "redirect-gateway" || k == "dhcp-option")
      continue; // Replaced by host routing and DNS policy.
    if (k == "explicit-exit-notify" && w.size() == 1)
      ok = true;
    if (scalar.contains(k) && w.size() == 2) {
      static const std::regex value("[A-Za-z0-9][A-Za-z0-9:._-]{0,180}");
      ok = std::regex_match(w[1], value);
    }
    require(ok, "unsupported or invalid profile directive on input line " +
                    std::to_string(number) + " (import aborted)");
    for (size_t i = 0; i < w.size(); i++)
      p.config += (i ? " " : "") + w[i];
    p.config += "\n";
  }
  require(block.empty() && ca && !p.endpoint.empty(),
          "remote and complete inline CA required");
  verifyMaterial(material);
  return p;
}
Json pingMetrics(const std::string &report) {
  static const std::regex summary(
      R"((\d+) packets transmitted, (\d+) received.*?([0-9.]+)% packet loss)");
  static const std::regex rtt(
      R"(= ([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+) ms)");
  static const std::regex sample(R"(time=([0-9.]+) ms)");
  std::smatch m;
  require(std::regex_search(report, m, summary), "ping produced no summary");
  Json result = {{"sent", std::stoi(m[1])},
                 {"received", std::stoi(m[2])},
                 {"loss_pct", std::stod(m[3])}};
  if (std::regex_search(report, m, rtt)) {
    result["min_ms"] = std::stod(m[1]);
    result["avg_ms"] = std::stod(m[2]);
    result["max_ms"] = std::stod(m[3]);
  }
  double last = 0, total = 0;
  int count = 0;
  for (std::sregex_iterator i(report.begin(), report.end(), sample), end;
       i != end; ++i) {
    double n = std::stod((*i)[1]);
    if (count++)
      total += std::abs(n - last);
    last = n;
  }
  if (count > 1)
    result["jitter_ms"] = total / (count - 1);
  return result;
}
} // namespace vpn
