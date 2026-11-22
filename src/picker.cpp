#include "picker.hpp"
#include "tui.hpp"
#include "vpnctl/core.hpp"
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <unistd.h>

namespace vpn {
namespace {
struct Entry {
  fs::path path;
  bool directory;
};

bool matches(const fs::path &path, PickMode mode) {
  auto ext = path.extension().string();
  std::ranges::transform(ext, ext.begin(),
                         [](unsigned char ch) { return std::tolower(ch); });
  return mode == PickMode::profile ? ext == ".ovpn" || ext == ".zip"
                                   : ext == ".json";
}

std::vector<Entry> entries(const fs::path &dir, PickMode mode, bool hidden) {
  std::vector<Entry> result{{dir.parent_path(), true}};
  for (const auto &item : fs::directory_iterator(dir)) {
    if (!hidden && item.path().filename().string().starts_with('.'))
      continue;
    std::error_code error;
    bool folder = item.is_directory(error);
    if (folder || (mode != PickMode::directory && matches(item.path(), mode) &&
                   item.is_regular_file(error)))
      result.push_back({item.path(), folder});
  }
  std::sort(result.begin() + 1, result.end(),
            [](const Entry &a, const Entry &b) {
              if (a.directory != b.directory)
                return a.directory;
              return a.path < b.path;
            });
  return result;
}

std::optional<fs::path> browse(Terminal &ui, fs::path dir, PickMode mode,
                               const std::string &title) {
  bool hidden = false;
  int index = 0;
  auto list = entries(dir, mode, hidden);
  std::string note;

  while (true) {
    ui.begin(-1, "", title);
    ui.row(1, dir.string());
    int height = std::max(1, ui.height() - 6);
    int top = std::max(0, index - height + 1);
    for (int n = top; n < int(list.size()) && n < top + height; ++n) {
      const auto &item = list[n];
      std::string name =
          n == 0 ? "../"
                 : item.path.filename().string() + (item.directory ? "/" : "");
      ui.row(3 + n - top, (n == index ? "> " : "  ") + name, n);
    }
    ui.notice = note;
    std::string help = "Enter open   Esc cancel   . hidden";
    if (mode == PickMode::directory)
      help += "   Space select current folder";
    if (mode == PickMode::saveRules)
      help += "   n new file";
    ui.actions = {{"Open", '\n'}, {"Cancel", 27}};
    if (mode == PickMode::directory)
      ui.actions.emplace_back("Choose folder", ' ');
    if (mode == PickMode::saveRules)
      ui.actions.emplace_back("New file", 'n');
    ui.footer = help;
    ui.show();
    int key = ui.key(-1);
    if (key == Terminal::RowClick) {
      index = ui.clickedRow;
      continue;
    }
    if (key == 27 || key == 'q')
      return {};
    if (key == Terminal::Up)
      index = std::max(0, index - ui.steps);
    if (key == Terminal::Down)
      index = std::min(int(list.size()) - 1, index + ui.steps);
    if (mode == PickMode::directory && key == ' ')
      return dir;
    if (mode == PickMode::saveRules && key == 'n') {
      auto name = ui.prompt("Filename (empty cancels): ");
      if (!name.empty() && fs::path(name).filename() == name && name != "." &&
          name != "..")
        return dir / name;
      continue;
    }
    if (key != '.' && key != '\n')
      continue;
    auto next = dir;
    if (key == '.')
      hidden = !hidden;
    else if (list[index].directory)
      next = list[index].path;
    else
      return list[index].path;
    try {
      list = entries(next, mode, hidden);
      dir = next;
      index = 0;
      note.clear();
    } catch (const fs::filesystem_error &e) {
      note = e.code().message();
    }
  }
}
} // namespace

std::optional<fs::path> choosePath(PickMode mode, const std::string &title,
                                   Terminal *terminal) {
  require(geteuid() != 0,
          "run the file chooser as a normal user, or specify a path");
  require(isatty(STDIN_FILENO) && isatty(STDOUT_FILENO),
          "specify a path in non-interactive use");
  static fs::path directory = fs::current_path();
  std::error_code ec;
  if (!fs::is_directory(directory, ec))
    directory = fs::current_path();
  std::optional<fs::path> selected;
  if (getenv("WAYLAND_DISPLAY") || getenv("DISPLAY")) {
    Args args{"env",
              "ZENITY_OK=0",
              "ZENITY_CANCEL=42",
              "ZENITY_ESC=42",
              "zenity",
              "--file-selection",
              "--title=" + title,
              "--filename=" +
                  (directory /
                   (mode == PickMode::saveRules ? "vpnctl-rules.json" : ""))
                      .string()};
    if (mode == PickMode::directory)
      args.push_back("--directory");
    else {
      if (mode == PickMode::saveRules)
        args.push_back("--save");
      args.push_back(mode == PickMode::profile
                         ? "--file-filter=OpenVPN | *.ovpn *.zip *.OVPN *.ZIP"
                         : "--file-filter=JSON | *.json");
      args.push_back("--file-filter=All files | *");
    }
    auto result = run(args, 24 * 60 * 60, nullptr, ProcessMode::desktopDialog);
    if (result.status == 42)
      return {};
    if (result.status == 0 && result.output.ends_with('\n')) {
      result.output.pop_back(); // Strip only Zenity's delimiter, preserving
                                // whitespace in the path.
      if (!result.output.empty())
        selected = result.output;
    }
  }
  if (!selected) {
    std::optional<Terminal> standalone;
    if (!terminal)
      terminal = &standalone.emplace();
    selected = browse(*terminal, directory, mode, title);
  }
  if (selected)
    directory =
        mode == PickMode::directory ? *selected : selected->parent_path();
  return selected;
}
} // namespace vpn
