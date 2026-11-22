#pragma once
#include <filesystem>
#include <optional>
#include <string>

namespace vpn {
class Terminal;
enum class PickMode { profile, directory, settings, saveRules };
std::optional<std::filesystem::path>
choosePath(PickMode mode, const std::string &title, Terminal *terminal);
} // namespace vpn
