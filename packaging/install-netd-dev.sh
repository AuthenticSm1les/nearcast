#!/bin/sh
# Installs a development build of nearcast-netd system-wide, under /usr/local
# where the system allows it (polkit only reads actions from /usr/share).
# Run as root from the project directory after `cargo build --release`.
# Undo with: install-netd-dev.sh --uninstall
set -e
files="/usr/local/bin/nearcast-netd
/etc/systemd/system/nearcast-netd.service
/etc/dbus-1/system.d/org.nearcast.Netd1.conf
/usr/local/share/dbus-1/system-services/org.nearcast.Netd1.service
/usr/share/polkit-1/actions/org.nearcast.netd.policy"
if [ "$1" = --uninstall ]; then
    systemctl stop nearcast-netd.service 2>/dev/null || true
    rm -f $files
    systemctl daemon-reload
    busctl call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ReloadConfig
    exit
fi
install -Dm755 target/release/nearcast-netd /usr/local/bin/nearcast-netd
sed 's|/usr/bin/nearcast-netd|/usr/local/bin/nearcast-netd|' packaging/nearcast-netd.service \
    | install -Dm644 /dev/stdin /etc/systemd/system/nearcast-netd.service
install -Dm644 packaging/dbus/org.nearcast.Netd1.conf /etc/dbus-1/system.d/org.nearcast.Netd1.conf
install -Dm644 packaging/dbus/org.nearcast.Netd1.service /usr/local/share/dbus-1/system-services/org.nearcast.Netd1.service
install -Dm644 packaging/polkit/org.nearcast.netd.policy /usr/share/polkit-1/actions/org.nearcast.netd.policy
systemctl daemon-reload
busctl call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ReloadConfig
systemctl restart nearcast-netd.service 2>/dev/null || true
