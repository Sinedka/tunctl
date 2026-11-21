# vpnctl

Терминальный менеджер OpenVPN для Linux с systemd. Пользователь выбирает профиль и правила в TUI. Системный сервис проверяет запрос и управляет туннелем, nftables и policy routing. Поддерживаются IPv4, IPv6, исключения для адресов, DNS-имён и пользовательских cgroups v2.

## Установка через Nix flake

Добавьте VPNCTL в `inputs` **вашей конфигурации**. Nix получит проект с GitHub. Если Home Manager уже подключён, оба `follows` используют версии из вашего lock-файла.

```nix
inputs.vpnctl = {
  url = "github:sinedka/tunctl";
  inputs.nixpkgs.follows = "nixpkgs";
  inputs.home-manager.follows = "home-manager";
};
```

Без Home Manager опустите строку `inputs.home-manager.follows`. В примерах ниже `inputs` доступен внутри `outputs = inputs@{ nixpkgs, ... }: ...`.

### NixOS — клиент и системный сервис

Добавьте эти элементы в `nixosConfigurations.<имя>.modules`. Замените `alice` именем существующего пользователя. Модуль установит команду `vpnctl`, создаст сокет и предоставит оператору доступ к backend.

```nix
modules = [
  # ... ваши модули
  inputs.vpnctl.nixosModules.default
  {
    services.vpnctl = {
      enable = true;
      operators = [ "alice" ];
      policyUser = "alice";
      routing.killSwitch = false;
    };
  }
];
```

Выполните из каталога вашей конфигурации, подставив имя хоста:

```sh
sudo nixos-rebuild switch --flake .#myhost
```

Войдите в сессию заново для получения группы `vpnctl`, затем запустите `vpnctl status` или `vpnctl`. В этом примере kill switch выключен для первого запуска. Значение `true` блокирует обычный трафик даже до подключения VPN.

### Home Manager — настройки пользователя

В список модулей Home Manager добавьте `inputs.vpnctl.homeModules.default`, а в `home.nix` включите `programs.vpnctl.enable = true;`. Для импортирования прямо из `home.nix` передайте `inputs` через `extraSpecialArgs`:

```nix
{ inputs, ... }: {
  imports = [ inputs.vpnctl.homeModules.default ];
  programs.vpnctl.enable = true;
}
```

Для отдельного Home Manager примените `home-manager switch --flake .#alice`. При интеграции в NixOS достаточно `nixos-rebuild switch`. Если ваш lock-файл закрепляет ревизию до появления `homeModules`, используйте `inputs.vpnctl.homeManagerModules.default` — это имя также поддерживается в новых ревизиях. Полный пример с обоими модулями и варианты настройки правил приведены в [examples/flake.nix](examples/flake.nix) и [examples/home.nix](examples/home.nix).

### Только пакет или разовый запуск

В модуле, получающем `inputs` и `pkgs`, используйте пакет напрямую:

```nix
environment.systemPackages = [
  inputs.vpnctl.packages.${pkgs.stdenv.hostPlatform.system}.default
];
```

В Home Manager тот же пакет можно добавить в `home.packages`. Для разового запуска выполните `nix run github:sinedka/tunctl`. Для постоянной установки клиента в профиль — `nix profile add github:sinedka/tunctl`. Управление VPN требует включённого системного сервиса. Чтобы обновить закреплённую версию во flake конфигурации, выполните `nix flake update vpnctl` и пересоберите конфигурацию.

## Arch Linux, Debian и другие дистрибутивы

Выберите **AppImage** или **tar.gz с готовыми бинарниками**. Оба варианта включают клиент, backend и systemd units. На x86_64 клиент запускается так:

```sh
chmod +x vpnctl-0.1.0-x86_64.AppImage
./vpnctl-0.1.0-x86_64.AppImage
```

Для управления сетью администратор один раз устанавливает backend из того же файла и добавляет пользователя в список операторов. Команды для обоих форматов, зависимости и порядок удаления приведены в [руководстве для Linux](docs/linux.md).

## Профили

```sh
vpnctl import                     # открыть окно выбора файла
vpnctl validate ~/Downloads/servers.zip
vpnctl import ~/Downloads/servers.zip
vpnctl import ~/Downloads/single.ovpn
vpnctl import ~/Downloads/profile-directory
vpnctl status
vpnctl connect Germany_Berlin
vpnctl disconnect
vpnctl remove Germany_Berlin
```

В Wayland и X11 открывается графический диалог выбора. В терминале без графической сессии работает файловый браузер: стрелки перемещают выделение, Enter открывает каталог или файл, пробел выбирает текущую папку при импорте каталога, Esc отменяет выбор. В диалоге сохранения клавиша `n` задаёт новое имя. Интерактивные команды `vpnctl validate` и `vpnctl check-settings` также открывают выбор файла. Для скриптов указывайте путь аргументом.

Имя берётся из имени файла. Пробелы заменяются на `_`. Импорт папки рекурсивный. Сертификаты, ключи и файл `auth-user-pass` по относительным путям упаковываются в профиль до передачи backend. Для общих сертификатов в соседней директории импортируйте весь родительский каталог. Поддерживаются встроенные `ca`, `cert`, `key`, `tls-auth`, `tls-crypt`, `tls-crypt-v2` и `auth-user-pass`. Интерактивные запросы пароля, зашифрованные приватные ключи, PKCS#11, прокси и произвольные хуки требуют других способов аутентификации и не входят в поддерживаемый формат.

Одинаковые имена вызывают ошибку. Пакет импортируется по одному профилю. Ранее завершённые импорты доступны при ошибке в следующем файле. Валидатор проверяет допустимые директивы, PEM и соответствие ключа сертификату. Перед подключением проверяется SHA-256. Сервер проверяется OpenVPN во время TLS-handshake.

## Управление в терминале

| Экран | Действия |
|---|---|
| 1 Dashboard | Состояние handshake, профиль, интерфейс, время, байты и текущий RX/TX. Публичный IP и ping появляются после ручного измерения в Diagnostics. |
| 2 Servers | Стрелки выбирают строку, Enter подключает или переключает, `d` отключает, `i` выбирает .ovpn или ZIP, `I` — каталог для импорта, `v` / `V` — файл / каталог для проверки, `x` удаляет, `c` задаёт страну, `/` фильтрует имя и страну. |
| 2 Servers, измерения | `p` измеряет endpoint по физической сети, Space отмечает серверы, `P` проверяет отмеченные строки текущего фильтра. `o` сортирует по задержке, `f` выбирает самый быстрый из измеренных. |
| 3 Routing | `[` и `]` переключают IP, домены, приложения, таблицы, DNS и kill switch. `a` создаёт правило, `e` редактирует, Space переключает, `x` удаляет. |
| 4 Diagnostics | `g` выбирает цель, `h` переключает VPN/DIRECT, `p` запускает ping, `i` получает публичный IP, `n` проверяет DNS, `l` запрашивает адрес резолвера, `v` проверяет IPv6 HTTPS, `t` показывает lookup с меткой. `b` и `u` запускают измерения скорости. Esc отменяет тест. |
| 5 Settings | `e` сохраняет правила в выбранный JSON-файл, `t` меняет тему, `g` сохраняет цель ping, `s` синхронизирует правила, `r` возвращает декларативные правила. |
| 6 Logs | Журнал импорта, подключений и ошибок переключения. Системные подробности доступны администратору через `journalctl -u vpnctl-tunnel`. |

## Правила и DNS

Чтобы добавить DIRECT, откройте IP или Domain на экране Routing и нажмите `a`. Введите, например, `192.168.0.0/16` или `*.example.org`, затем `direct`. Изменения применяются ко всему хосту. Администратор делегирует это право одному аккаунту через `services.vpnctl.policyUser`. Членство в `operators` разрешает переключение системного VPN и импорт профилей.

Для изучения доменных ответов включите `services.vpnctl.dns.enable = true;`. Системный список `routing.directDomains` также включает интеграцию. dnsmasq принимает локальные запросы. Его upstream на loopback сопоставляет DNS-ответ и TTL с правилами, обновляет nft sets до передачи ответа приложению. Обычные upstream-запросы направляются через VPN. Если DNS-интеграция выключена, модуль оставляет выбор резолвера системе. Для NetworkManager с собственным DNS-плагином или DHCP DNS проверьте `/etc/resolv.conf` и фактический сервер в `dig`. Доменная классификация требует использования локального dnsmasq. При активном systemd-resolved выберите резолвер явно в конфигурации хоста.

Для приложений Home Manager создаёт desktop entry с запуском в пользовательском systemd scope. Для Firefox выберите в примере действие `direct`, примените Home Manager, полностью закройте браузер и снова запустите из меню. Аналог для терминала:

```sh
vpnctl sync
vpnctl launch firefox firefox
```

GUI и дочерние процессы сохраняют пользовательскую сессию, D-Bus, Wayland/X11, домашнюю директорию и UID. При несовпадении ID значка задайте `desktopId`. Для существующего user service укажите `Slice=vpnctl-firefox.slice` и `ExecStartPre=/путь/к/vpnctl refresh`. Имя slice для Telegram — `vpnctl-telegram_desktop.slice`. Уже запущенный экземпляр приложения может принять запрос нового запуска через D-Bus и продолжить использовать прежние сокеты. Подробности в [docs/routing.md](docs/routing.md).

## Проверка соединения

```sh
vpnctl diag ping 1.1.1.1 vpn
vpnctl diag endpoint 192.0.2.10 direct
vpnctl diag route 1.1.1.1 vpn
vpnctl diag dns example.org vpn
vpnctl diag dns-leak example.org vpn
vpnctl diag public-ip example.org vpn
vpnctl diag public-ip example.org direct
vpnctl diag ipv6 example.org vpn
vpnctl diag download example.org vpn --confirm
vpnctl diag upload example.org direct --confirm
```

Для endpoint замените тестовый IP адресом VPN-сервера. DIRECT-измерения требуют делегирования `policyUser` и пользовательского systemd. У диагностик DNS путь задаёт системный резолвер. Сравните адрес рекурсивного сервера из `whoami.akamai.net` с ожидаемым. Для проверки утечки IPv6 сравните внешний IPv6 и состояние маршрута при работающем и отключённом VPN. Единичный запрос проверяет только использованный клиент и семейство адресов.

RTT и потери рассчитываются по ICMP, jitter — среднее абсолютное изменение соседних RTT. Сетевые тесты имеют ограничение времени. В TUI доступна отмена, в CLI — Ctrl-C. Speedtest связывает HTTPS-соединение с конкретным интерфейсом через curl и передаёт 1 МиБ полезных данных. Скорость включает установку соединения. Трафик заголовков, TLS и повторных передач добавляется к этому объёму. По умолчанию запросы идут к Cloudflare и ipify. Для собственного сервера задайте HTTPS URL в `programs.vpnctl.settings.diagnostics.{downloadUrl,uploadUrl,publicIPUrl}`. Загрузка ожидает ровно 1048576 байт, отправка использует POST. Аргумент цели в CLI применяется к ping, DNS и route. HTTPS использует настроенные URL.

## Слои настроек

Home Manager генерирует `$XDG_CONFIG_HOME/vpnctl/settings.json` и проверяет его при сборке. После первой правки списка TUI сохраняет полный снимок правил в `$XDG_STATE_HOME/vpnctl/overrides.json`. Этот снимок имеет приоритет над всем декларативным списком до сброса. Тема и цель диагностики хранятся отдельно в `preferences.json`. Для XDG действуют стандартные значения `~/.config` и `~/.local/state`.

```sh
vpnctl export > routing-backup.json
vpnctl sync
vpnctl reset
```

`sync` передаёт итоговый список через Unix socket, `reset` повторно применяет правила из Home Manager и удаляет снимок. Для восстановления снимка положите сохранённый JSON в `overrides.json` и выполните `vpnctl sync`. Backend заново проверяет правила, сохраняет владельца политики и сериализует изменения. `syncOnLogin` отправляет конфигурацию при входе. Файл `home.nix` редактируется пользователем.

## Эксплуатация

Миграция, восстановление сети и удаление описаны в [docs/migration.md](docs/migration.md). Устройство IPC и модель доверия — в [docs/architecture.md](docs/architecture.md) и [docs/security.md](docs/security.md). Проверки и границы покрытия перечислены в [docs/testing.md](docs/testing.md).
