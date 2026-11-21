#pragma once
#include <filesystem>
#include <optional>
#include <string>

namespace vpn {
enum class PickMode { profile, directory, settings, saveRules };
std::optional<std::filesystem::path>
choosePath(PickMode mode, const std::string &title, bool inTui);
} // namespace vpn
