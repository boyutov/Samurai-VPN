# WireGuard на macOS — версия 0.3 (не проверено на устройстве)

Код macOS-клиента готов и покрыт тестами, но **ещё ни разу не запускался на настоящем
Mac**. Тесты моделируют wireguard-go, wg, ifconfig, route и netstat; разбор вывода
netstat и ifconfig проверен на образцах формата macOS 14.

## Устройство

Официальное приложение WireGuard для macOS работает как Network Extension и не
управляется из других программ. Поэтому служба делает то же, что `wg-quick`, но без bash:

1. `wireguard-go utun` создаёт интерфейс utunN (номер выбирает ядро);
2. `wg setconf` задаёт ключи и участников;
3. `ifconfig` назначает адрес /32 и MTU 1280, `route` добавляет /32 к каждому участнику.

DNS, основной маршрут и firewall не меняются. Перед подключением служба проверяет
маршруты (`netstat -rn`) и адреса (`ifconfig -a`) на пересечение с сетью 10.203.

Служба Samurai VPN — Java-процесс от root, его запускает launchd
(`/Library/LaunchDaemons/dev.samurai.vpn.service.plist`). Протокол и сокет те же, что
у samurai-vpnd на Linux (`/var/run/samurai-vpnd/daemon.sock`): UID вызывающего
сообщает ядро (LOCAL_PEERCRED), и каждый пользователь управляет только своими
туннелями. Отключение удаляет управляющий сокет wireguard-go, после чего тот закрывает
utun и завершается — так же делает `wg-quick down`.

**Почему копии инструментов.** Homebrew-папка принадлежит пользователю. Если root
запускает оттуда программу, любой процесс пользователя может подменить её и получить
root. Установщик копирует `wireguard-go` и `wg` в `/Library/Application Support/SamuraiVPN/bin`
(владелец root) и отказывается, если они подключают библиотеки вне `/usr/lib` и `/System`.
После `brew upgrade` установку нужно повторить, чтобы обновить копии.

## Установка

    brew install wireguard-go wireguard-tools
    ./build.sh && ./package.sh                     # dist/SamuraiVPN.app
    sudo ./native/macos/install-service.sh dist/SamuraiVPN.app

Нужны macOS 12.3+ и Xcode Command Line Tools (otool). Удаление (туннели Samurai
отключаются, инструменты Homebrew остаются):

    sudo ./native/macos/uninstall-service.sh

## Первая проверка на устройстве

1. Установка проходит, `/var/run/samurai-vpnd/daemon.sock` появляется, ошибок нет в `/var/log/samurai-vpn.log`.
2. Окно: подсказки «Служба не запущена» нет; «Подключить» → в `ifconfig` появился utunN
   с адресом 10.203.x.y, `netstat -rn | grep 10.203` показывает только /32 к участникам.
3. `ping` до участника; второй пользователь Mac не видит и не отключает чужой туннель.
4. Новый участник появляется без переподключения; прямое соединение (колонка «Соединение»).
5. «Отключить» убирает utun; перезагрузка — служба стартует сама.

**Главный риск:** что JDK на macOS отдаёт UID через SO_PEERCRED так же, как на Linux.
Если нет, служба откажет во всех запросах (безопасный отказ), и это первое, что надо проверить.
