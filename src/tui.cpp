#include "tui.hpp"
#include <chrono>
#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/terminal.hpp>
#include <thread>
using namespace ftxui;
namespace vpn {
namespace {
constexpr std::array names{"Dashboard",   "Servers",  "Routing",
                           "Diagnostics", "Settings", "Logs"};
}
Terminal::Terminal() {
  app.TrackMouse(true);
  root = CatchEvent(Renderer([this] { return render(); }), [this](Event event) {
    if (event.is_mouse() && event.mouse().motion == Mouse::Moved && !input)
      return true;
    if (event != Event::Custom)
      events.push_back(event);
    return true;
  });
  loop.emplace(&app, root);
}
int Terminal::height() const {
  return std::max(8, ftxui::Terminal::Size().dimy - 4);
}
int Terminal::width() const {
  int w = ftxui::Terminal::Size().dimx;
  return std::max(12, w - (w >= 84 && page >= 0 ? 26 : 6));
}
void Terminal::begin(int p, std::string st, std::string name) {
  page = p;
  state = std::move(st);
  profile = std::move(name);
  servers.clear();
  rows.clear();
  actions.clear();
  rowItems.clear();
  footer.clear();
  notice.clear();
}
void Terminal::row(int index, std::string value, std::optional<int> item) {
  if (item)
    rowItems[index] = *item;
  rows[index] = std::move(value);
}
Element Terminal::clickable(Element element, int key, int item) {
  targets.push_back({{}, key, item});
  return element | reflect(targets.back().box);
}
Element Terminal::render() {
  targets.clear();
  auto accent = light ? Color::Blue : Color::CyanLight;
  auto selected = light ? Color::Blue : Color::RGB(34, 76, 91);
  auto label = [&](std::string s) {
    return text(std::move(s)) | color(accent) | bold;
  };
  auto heading =
      hbox({label(" VPNCTL "), separator(), text(" " + profile) | xflex,
            text(state.empty() ? "" : " ● " + state + " ") | bold |
                color(state == "connected"
                          ? (light ? Color::Green : Color::GreenLight)
                          : accent)});
  const bool wide = ftxui::Terminal::Size().dimx >= 84;
  Elements nav;
  if (page >= 0)
    for (int i = 0; i < 6; ++i) {
      auto item =
          text(" " + std::to_string(i + 1) +
               (wide || i == page ? "  " + std::string(names[i]) : "") + " ");
      if (i == page)
        item = item | bgcolor(selected) | color(Color::White) | bold;
      nav.push_back(item | reflect(buttons[i]));
    }
  Elements content;
  if (page == 0) {
    auto metrics = [&](const char *title, std::initializer_list<int> indices) {
      Elements values;
      for (int i : indices) {
        auto it = rows.find(i);
        if (it == rows.end())
          continue;
        const auto &s = it->second;
        auto split = s.find("  ");
        auto value = s.find_first_not_of(' ', split);
        values.push_back(hbox(
            {text(" " + s.substr(0, split)) | dim, filler(),
             text(value == s.npos ? "—" : s.substr(value)) | bold, text(" ")}));
      }
      return window(label(title), vbox(std::move(values))) | xflex;
    };
    auto tunnel = metrics(" Tunnel ", {3, 4, 5, 6});
    auto traffic = metrics(" Traffic ", {8, 9});
    if (width() >= 70)
      content.push_back(hbox({tunnel, traffic}));
    else {
      content.push_back(tunnel);
      content.push_back(traffic);
    }
    content.push_back(metrics(" Diagnostics ", {10, 12, 11}));
  } else {
    for (auto &[i, s] : rows) {
      auto item = text(" " + s);
      if (s.starts_with("> "))
        item = item | bgcolor(selected) | color(Color::White) | bold;
      else if (i == 4 && page != 5)
        item = item | color(accent);
      if (rowItems.contains(i))
        item = clickable(item, RowClick, rowItems.at(i));
      content.push_back(item);
    }
  }
  if (page == 1) {
    auto columns = [&](std::string name, std::string country,
                       std::string status, std::string latency) {
      Elements cells{text(std::move(name)) | xflex};
      if (width() >= 62)
        cells.push_back(text(std::move(country)) | size(WIDTH, EQUAL, 14));
      cells.push_back(text(std::move(status)) | size(WIDTH, EQUAL, 12));
      cells.push_back(text(std::move(latency)) | size(WIDTH, EQUAL, 9));
      return hbox(std::move(cells));
    };
    content.push_back(separator());
    content.push_back(columns("   Profile", "Country", "State", "Latency") |
                      dim);
    const Server *focused = nullptr;
    for (const auto &server : servers) {
      auto entry = columns((server.marked ? " ✓ " : "   ") + server.name,
                           server.country, server.state, server.latency);
      if (server.selected) {
        focused = &server;
        entry = entry | bgcolor(selected) | color(Color::White) | bold;
      }
      content.push_back(clickable(entry, RowClick, server.index));
    }
    if (focused) {
      content.push_back(separator());
      content.push_back(paragraph(" " + focused->protocol + "  " +
                                  focused->endpoint +
                                  "    Last probe: " + focused->checked) |
                        dim);
    }
  }
  auto body =
      window(
          label(" " + (page >= 0 ? std::string(names[page]) : profile) + " "),
          vbox(std::move(content)) | yframe | flex) |
      flex;
  Elements layout{heading, separator()};
  if (page >= 0 && wide)
    layout.push_back(
        hbox({vbox(std::move(nav)) | size(WIDTH, EQUAL, 18), body}) | flex);
  else {
    if (page >= 0)
      layout.push_back(hbox(std::move(nav)));
    layout.push_back(body);
  }
  if (!actions.empty()) {
    Elements bar;
    for (auto &[name, command] : actions)
      bar.push_back(clickable(
          text(" " + name + " ") | bold | color(accent) | inverted, command));
    layout.push_back(flexbox(std::move(bar)));
  }
  if (!notice.empty())
    layout.push_back(paragraph(notice) | size(HEIGHT, LESS_THAN, 4) |
                     color(accent));
  layout.push_back(separator());
  layout.push_back(paragraph(footer) | size(HEIGHT, LESS_THAN, 3));
  auto view = vbox(std::move(layout));
  if (input) {
    // While the editor is open only the dialog handles clicks.
    auto buttons = hbox({clickable(text("  OK  ") | inverted, '\n', -2),
                         text("  "), clickable(text(" Cancel "), 27, -2)});
    view = dbox(
        {view, window(label(" " + question + " "),
                      vbox({input->Render() |
                                size(WIDTH, EQUAL, std::min(52, width() - 2)),
                            separator(), buttons})) |
                   clear_under | center});
  }
  return view;
}
void Terminal::show() {
  app.PostEvent(Event::Custom);
  loop->RunOnce();
}
namespace {
int direction(Event &event) {
  if (event == Event::ArrowUp)
    return Terminal::Up;
  if (event == Event::ArrowDown)
    return Terminal::Down;
  if (event.is_mouse()) {
    if (event.mouse().button == Mouse::WheelUp)
      return Terminal::Up;
    if (event.mouse().button == Mouse::WheelDown)
      return Terminal::Down;
  }
  return 0;
}
} // namespace
int Terminal::key(int ms) {
  steps = 1;
  const auto until =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
  auto dims = ftxui::Terminal::Size();
  do {
    loop->RunOnce();
    if (loop->HasQuitted())
      throw std::runtime_error("terminal closed");
    while (!events.empty()) {
      auto e = events.front();
      events.pop_front();
      if (e == Event::Escape)
        return 27;
      if (e == Event::Return || e == Event::Character('\n'))
        return '\n';
      if (input) {
        if (e.is_mouse() && e.mouse().button == Mouse::Left &&
            e.mouse().motion == Mouse::Pressed)
          for (auto it = targets.rbegin(); it != targets.rend(); ++it) {
            if (it->item != -2)
              break;
            if (it->box.Contain(e.mouse().x, e.mouse().y))
              return it->key;
          }
        input->OnEvent(e);
        app.PostEvent(Event::Custom);
        continue;
      }
      if (int movement = direction(e)) {
        while (!events.empty() && direction(events.front()) == movement) {
          ++steps;
          events.pop_front();
        }
        return movement;
      }
      if (e == Event::PageUp)
        return PgUp;
      if (e == Event::PageDown)
        return PgDown;
      if (e == Event::Home)
        return Home;
      if (page >= 0 && (e == Event::Tab || e == Event::TabReverse))
        return '1' + (page + (e == Event::Tab ? 1 : 5)) % 6;
      if (e.is_mouse()) {
        auto m = e.mouse();
        if (m.button == Mouse::Left && m.motion == Mouse::Pressed) {
          for (auto &target : targets)
            if (target.box.Contain(m.x, m.y)) {
              clickedRow = target.item;
              return target.key;
            }
        }
        if (page >= 0 && m.button == Mouse::Left && m.motion == Mouse::Pressed)
          for (int i = 0; i < 6; ++i)
            if (buttons[i].Contain(m.x, m.y))
              return '1' + i;
      }
      if (e.is_character() && e.character().size() == 1)
        return e.character()[0];
    }
    auto now = ftxui::Terminal::Size();
    if (!input && (dims.dimx != now.dimx || dims.dimy != now.dimy))
      break;
    if (ms == 0)
      break;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  } while (ms < 0 || std::chrono::steady_clock::now() < until);
  return -1;
}
std::string Terminal::prompt(const std::string &label) {
  question = label;
  answer.clear();
  input = Input(&answer, "");
  show();
  int k = key(-1);
  input.reset();
  return k == 27 ? "" : answer;
}
} // namespace vpn
