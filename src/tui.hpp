#pragma once
#include <array>
#include <deque>
#include <ftxui/component/app.hpp>
#include <ftxui/component/component.hpp>
#include <ftxui/component/loop.hpp>
#include <map>
#include <optional>

namespace vpn {
class Terminal {
public:
  enum Key { Up = 256, Down, PgUp, PgDown, Home, RowClick };
  Terminal();
  void begin(int page, std::string state, std::string profile);
  void row(int index, std::string value, std::optional<int> item = {});
  std::vector<std::pair<std::string, int>> actions;
  int clickedRow = -1, steps = 1;
  void show();
  int key(int milliseconds);
  std::string prompt(const std::string &label);
  int height() const;
  int width() const;
  struct Server {
    std::string name, country, state, endpoint, protocol, latency, checked;
    bool marked, selected;
    int index;
  };
  std::vector<Server> servers;
  bool light = false;
  std::string footer, notice;

private:
  ftxui::Element render();
  ftxui::App app = ftxui::App::Fullscreen();
  std::deque<ftxui::Event> events;
  std::array<ftxui::Box, 6> buttons{};
  int page = -1;
  std::string state, profile, question, answer;
  std::map<int, std::string> rows;
  std::map<int, int> rowItems;
  struct Target {
    ftxui::Box box;
    int key;
    int item;
  };
  std::deque<Target> targets;
  ftxui::Element clickable(ftxui::Element element, int key, int item = -1);
  ftxui::Component input, root;
  std::optional<ftxui::Loop> loop;
};
} // namespace vpn
