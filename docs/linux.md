# VPNCTL на Linux с systemd

На Debian и Arch используйте обычные системные пакеты. Устанавливаются TUI, привилегированный backend, OpenVPN unit, фильтр исходящего трафика, таймер обновления правил и DNS upstream. Команды сборки ниже выполняются в корне checkout VPNCTL.

## Debian 13

```sh
sudo apt update
sudo apt install build-essential cmake dpkg-dev file libssl-dev libncurses-dev nlohmann-json3-dev openssl python3
cmake -S . -B build/debian -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr
cmake --build build/debian --parallel
ctest --test-dir build/debian --output-on-failure
(cd build/debian && cpack -G DEB)
sudo apt install ./build/debian/vpnctl_*.deb
```

APT установит зависимости из репозиториев Debian. Если нужен локальный DNS-маршрутизатор, отдельно установите пакет `dnsmasq`.

## Arch Linux

Соберите пакет из текущего рабочего дерева. В архив попадают только перечисленные ниже файлы проекта под контролем Git. Запускайте `makepkg` от обычного пользователя.

```sh
sudo pacman -S --needed base-devel git
mkdir -p build/arch
cp packaging/arch/PKGBUILD build/arch/
git ls-files -z -- CMakeLists.txt LICENSE include src packaging tests |
  tar --null --transform='s,^,vpnctl-0.1.0/,' -czf build/arch/vpnctl-0.1.0.tar.gz -T -
(cd build/arch && makepkg --syncdeps --install)
```

При установке готового пакета используйте `sudo pacman -U ./vpnctl-0.1.0-1-*.pkg.tar.zst`. Для локального DNS установите `dnsmasq`.

## Другие дистрибутивы

Нужны Linux с TUN, cgroup v2 и nftables socket cgroupv2, системный и пользовательский systemd, OpenVPN 2.6+ с systemd notify, nft с командой `destroy`, iproute2, Python 3 с dnspython, curl 8.9+ и утилиты ping, dig, getent. Для сборки нужны компилятор C++23, CMake 3.20+, заголовки OpenSSL, ncurses и nlohmann/json. Версия curl важна для привязки теста к конкретному интерфейсу. Проверены форматы упаковки, описанные выше. Для другого дистрибутива сопоставьте названия зависимостей с его пакетами.

```sh
cmake -S . -B build/linux -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr
cmake --build build/linux --parallel
ctest --test-dir build/linux --output-on-failure
sudo cmake --install build/linux
```

## Первый запуск

1. Создайте системную группу и рабочие каталоги. На новой установке скопируйте образец политики.

   ```sh
   sudo systemd-sysusers /usr/lib/sysusers.d/vpnctl.conf
   sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/vpnctl.conf
   sudo install -d -m 0755 /etc/vpnctl
   sudo cp --no-clobber /usr/share/vpnctl/policy.example.json /etc/vpnctl/policy.json
   sudo usermod -aG vpnctl "$(id -un)"
   sudoedit /etc/vpnctl/policy.json
   ```

2. Впишите имя своей учётной записи в массив `operators`. Чтобы разрешить ей менять правила для всего хоста и запускать DIRECT-тесты, укажите то же имя в `policyUser`. Образец начинает с пустого списка операторов и `killSwitch: false`. Значение `true` блокирует обычный исходящий трафик сразу после включения службы, включая время до первого подключения.

3. Для VPNCTL зарезервированы устройство `vpnctl0`, приоритет и таблица маршрутов 30201 и таблицы nftables `inet vpnctl` и `inet vpnctl_session`. Убедитесь, что системный firewall при обновлении сохраняет чужие таблицы. Глобальный `flush ruleset` удаляет также защиту VPNCTL. Включите маршрутизацию и сокет после проверки конфигурации.

   ```sh
   sudo systemctl daemon-reload
   sudo systemctl enable --now vpnctl-routing.service vpnctl.socket vpnctl-refresh.timer
   ```

4. После нового входа в пользовательскую сессию импортируйте профиль и выберите сервер в TUI.

   ```sh
   vpnctl status
   vpnctl import ~/Downloads/server.ovpn
   vpnctl
   ```

Для автоподключения последнего выбранного профиля выполните `sudo systemctl enable vpnctl-tunnel.service`. После изменения системного списка IP или kill switch используйте `sudo systemctl reload vpnctl-routing.service`. Вкладка Routing позволяет управлять пользовательскими исключениями. Для маршрутизации приложения добавьте его там и запустите, например, `vpnctl launch firefox firefox`. Для запуска из графического меню используйте ту же команду в пользовательском desktop entry.

## Доменная маршрутизация

По умолчанию продолжает работать системный DNS. Для доменных правил задайте `"dns": true` в политике, при необходимости укажите `directDomains` и IP-адреса upstream-серверов. Служба `vpnctl-dns` слушает UDP/TCP на `127.0.0.1:53071`. Включите её и настройте **локальный** dnsmasq для пересылки запросов:

```ini
listen-address=127.0.0.1
bind-interfaces
no-resolv
server=127.0.0.1#53071
cache-size=0
max-ttl=300
```

```sh
sudo systemctl enable --now vpnctl-dns.service
sudo systemctl restart dnsmasq.service
dig @127.0.0.1 example.org
```

Выберите 127.0.0.1 как DNS в используемом сетевом менеджере. Проверьте отсутствие конфликтов на порту 53 и upstream-записей dnsmasq, через которые запросы могут уйти в обход классификатора. Для проверки сделайте запрос к домену из политики и посмотрите его TTL в Routing → DNS.

## Остановка и удаление

Если меняли системный резолвер, сначала верните его прежнюю конфигурацию. Выполните `vpnctl disconnect`. Для полного снятия политики и отключения её загрузки:

```sh
sudo systemctl disable --now vpnctl.socket vpnctl-refresh.timer vpnctl-tunnel.service vpnctl-dns.service
sudo systemctl stop vpnctl-session.service vpnctl-refresh.service
sudo systemctl disable --now vpnctl-routing.service
```

Удалите пакет через `sudo apt remove vpnctl` или `sudo pacman -R vpnctl`. Профили и ключи сохраняются в `/var/lib/vpnctl`. Если устанавливали напрямую через CMake, список установленных файлов находится в `build/linux/install_manifest.txt`.
