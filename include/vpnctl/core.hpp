#pragma once
#include <filesystem>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
namespace vpn {
using Json = nlohmann::json;
namespace fs = std::filesystem;
using Args = std::vector<std::string>;
void require(bool, const std::string &);
bool id(const std::string &);
bool cidr(std::string);
bool domain(std::string);
bool covers(const std::string &, const std::string &);
struct Profile {
  std::string config, endpoint, protocol;
};
std::string digest(const std::string &);
Profile profile(const std::string &);
std::string read(const fs::path &);
void write(const fs::path &, const std::string &);
struct Result {
  int status;
  std::string output;
};
Json pingMetrics(const std::string &);
enum class ProcessMode { command, desktopDialog };
Result run(const Args &, int seconds = 10, bool (*cancel)() = nullptr,
           ProcessMode mode = ProcessMode::command);
void sendJson(int, const Json &);
Json recvJson(int);
Json rpc(const Json &);
std::string ruleLine(const Json &, uid_t);
} // namespace vpn
