#include "picker.hpp"
#include "vpnctl/core.hpp"
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <curses.h>
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

std::optional<fs::path> browse(fs::path dir, PickMode mode,
                               const std::string &title) {
  bool hidden = false;
  int index = 0;
  auto list = entries(dir, mode, hidden);
  std::string note;
  timeout(-1);
  while (true) {
    erase();
    auto line = [](int y, const std::string &s) {
      if (y >= 0 && y < LINES)
        mvaddnstr(y, 0, s.c_str(), std::max(0, COLS - 1));
    };
    line(0, title);
    line(1, dir.string());
    int height = std::max(1, LINES - 6);
    int top = std::max(0, index - height + 1);
    for (int n = top; n < int(list.size()) && n < top + height; ++n) {
      const auto &item = list[n];
      if (n == index)
        attron(A_REVERSE);
      line(3 + n - top, n == 0 ? "../"
                               : item.path.filename().string() +
                                     (item.directory ? "/" : ""));
      if (n == index)
        attroff(A_REVERSE);
    }
    line(LINES - 2, note);
    std::string help = "Enter open   Esc cancel   . hidden";
    if (mode == PickMode::directory)
      help += "   Space select current folder";
    if (mode == PickMode::saveRules)
      help += "   n new file";
    line(LINES - 1, help);
    refresh();
    int key = getch();
    if (key == 27 || key == 'q')
      return {};
    if (key == KEY_UP)
      index = std::max(0, index - 1);
    if (key == KEY_DOWN)
      index = std::min(int(list.size()) - 1, index + 1);
    if (mode == PickMode::directory && key == ' ')
      return dir;
    if (mode == PickMode::saveRules && key == 'n') {
      move(LINES - 1, 0);
      clrtoeol();
      addstr("Filename (empty cancels): ");
      char name[256]{};
      echo();
      curs_set(1);
      int rc = getnstr(name, sizeof(name) - 1);
      noecho();
      curs_set(0);
      if (rc != ERR && *name && fs::path(name).filename() == name &&
          std::string_view(name) != "." && std::string_view(name) != "..")
        return dir / name;
      continue;
    }
    if (key != '.' && key != '\n' && key != KEY_ENTER)
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
                                   bool inTui) {
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
    if (!inTui) {
      initscr();
      cbreak();
      noecho();
      keypad(stdscr, true);
      curs_set(0);
    }
    struct Restore {
      bool standalone;
      ~Restore() {
        if (standalone)
          endwin();
        else
          touchwin(stdscr);
      }
    } restore{!inTui};
    selected = browse(directory, mode, title);
  }
  if (selected)
    directory =
        mode == PickMode::directory ? *selected : selected->parent_path();
  return selected;
}
} // namespace vpn
