# VPNCTL на Linux с systemd

## Запуск клиента

Готовые файлы для x86_64 рассчитаны на Linux с glibc 2.36 и новее. Nix, компилятор и отдельный пакет VPNCTL не нужны. Выберите один формат.

**AppImage**

```sh
chmod +x vpnctl-0.1.0-x86_64.AppImage
./vpnctl-0.1.0-x86_64.AppImage
```

Обычный запуск использует FUSE и утилиту `fusermount3` (пакет `fuse3`). Если FUSE недоступен, используйте `TMPDIR="${XDG_RUNTIME_DIR:-$HOME}" ./vpnctl-0.1.0-x86_64.AppImage --appimage-extract-and-run`.

**Архив с бинарником**

```sh
tar -xzf vpnctl-0.1.0-x86_64.tar.gz
cd vpnctl-0.1.0-x86_64
./vpnctl
```

Архив можно распаковать в домашний каталог. Перемещайте каталог целиком, чтобы рядом с бинарником оставались библиотеки и импортёр профилей. После установки backend на том же компьютере любая копия клиента может обращаться к его сокету.

## Первый запуск VPN

1. Администратору нужны systemd, cgroups v2, TUN, OpenVPN 2.6+, nftables с поддержкой `destroy`, iproute2 и Python 3 с dnspython. Для диагностики нужны curl 8.9+, ping, dig и getent. На Arch зависимости устанавливаются следующей командой.

   ```sh
   sudo pacman -S --needed openvpn nftables iproute2 python python-dnspython curl iputils bind
   ```

   На Debian 13:

   ```sh
   sudo apt install openvpn nftables iproute2 python3-dnspython curl iputils-ping bind9-dnsutils
   ```

2. Установите backend **одним** из способов. Используйте файл сборки, которому доверяет администратор. Для AppImage:

   ```sh
   sudo env TMPDIR=/root ./vpnctl-0.1.0-x86_64.AppImage --appimage-extract-and-run --install-backend
   ```

   Из распакованного tar:

   ```sh
   sudo ./install-backend
   ```

   Установщик размещает исполняемые файлы в `/opt/vpnctl`, регистрирует службы systemd и создаёт начальную политику. Он сохраняет существующую политику при обновлении. Укажите имя пользователя в массиве `operators`. Чтобы разрешить этому пользователю менять правила для всего хоста и запускать DIRECT-тесты, укажите его имя и в `policyUser`.

   ```sh
   sudo usermod -aG vpnctl "$(id -un)"
   sudoedit /etc/vpnctl/policy.json
   ```

   По умолчанию kill switch выключен. Значение `"killSwitch": true` блокирует обычный трафик с момента включения службы, включая время до первого подключения.

3. Для VPNCTL зарезервированы устройство `vpnctl0`, приоритет и таблица маршрутов 30201 и таблицы nftables `inet vpnctl` и `inet vpnctl_session`. Убедитесь, что системный firewall при обновлении сохраняет чужие таблицы. Глобальный `flush ruleset` удаляет также защиту VPNCTL. Включите маршрутизацию и сокет после проверки конфигурации.

   ```sh
   sudo systemctl daemon-reload
   sudo systemctl enable --now vpnctl-routing.service vpnctl.socket vpnctl-refresh.timer
   ```

4. После нового входа в пользовательскую сессию импортируйте профиль и выберите сервер в TUI.

   ```sh
   /opt/vpnctl/current/bin/vpnctl status
   /opt/vpnctl/current/bin/vpnctl import ~/Downloads/server.ovpn
   /opt/vpnctl/current/bin/vpnctl
   ```

Для вызова команды по имени добавьте `/opt/vpnctl/current/bin` в пользовательский `PATH`.

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

Удалите ссылки установщика и выбранную сборку после остановки служб. Каталог `/opt/vpnctl` содержит установленные этим способом версии. Системная политика хранится в `/etc/vpnctl`, профили и ключи — в `/var/lib/vpnctl`.

```sh
sudo find /etc/systemd/system /etc/tmpfiles.d /etc/sysusers.d -maxdepth 1 \
  -type l -lname '/opt/vpnctl/lib/*' -delete
sudo rm -r /opt/vpnctl
sudo systemctl daemon-reload
```

## Сборка обоих файлов из исходников

В Debian 12 установите зависимости сборки:

```sh
sudo apt install g++ cmake make nlohmann-json3-dev libssl-dev libncurses-dev \
  patchelf squashfs-tools python3 openssl curl
```

В корне проекта скачайте закреплённый runtime для архитектуры сборочной машины. Скрипт сверяет его SHA-256 перед упаковкой. Затем CMake собирает клиент и backend, CTest выполняет проверки, а скрипт записывает оба готовых файла в `build/portable`.

```sh
case "$(uname -m)" in
  x86_64) asset=657374641 ;;
  aarch64) asset=657373827 ;;
  *) exit 1 ;;
esac
mkdir -p build/portable
curl -fL -H 'Accept: application/octet-stream' \
  "https://api.github.com/repos/AppImage/type2-runtime/releases/assets/$asset" \
  -o build/portable/runtime
packaging/portable/build.sh build/portable/runtime build/portable
```
