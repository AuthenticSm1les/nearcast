# Installs nearcast system-wide. Build first with `cargo build --release`.
#
#   make install                 # to /usr/local
#   make PREFIX=/usr DESTDIR=pkg install   # for packaging
#
# Then reload the services:
#   systemctl daemon-reload
#   busctl call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ReloadConfig
#   systemctl --user enable --now nearcastd

PREFIX ?= /usr/local
DESTDIR ?=
BINDIR = $(PREFIX)/bin
DATADIR = $(PREFIX)/share
# D-Bus only reads system bus policy from /usr/share and /etc, and polkit
# only reads actions from /usr/share, whatever the prefix.
DBUS_POLICY_DIR ?= /usr/share/dbus-1/system.d
POLKIT_ACTION_DIR ?= /usr/share/polkit-1/actions
SYSTEMD_SYSTEM_DIR ?= $(PREFIX)/lib/systemd/system
SYSTEMD_USER_DIR ?= $(PREFIX)/lib/systemd/user

BINS = nearcastd nearcast nearcast-netd

.PHONY: all install uninstall

all:
	cargo build --release --locked

install:
	for b in $(BINS); do install -Dm755 target/release/$$b $(DESTDIR)$(BINDIR)/$$b; done
	sed 's|/usr/bin/|$(BINDIR)/|' packaging/nearcastd.service \
		| install -Dm644 /dev/stdin $(DESTDIR)$(SYSTEMD_USER_DIR)/nearcastd.service
	sed 's|/usr/bin/|$(BINDIR)/|' packaging/nearcast-netd.service \
		| install -Dm644 /dev/stdin $(DESTDIR)$(SYSTEMD_SYSTEM_DIR)/nearcast-netd.service
	sed 's|/usr/bin/|$(BINDIR)/|' packaging/dbus/org.nearcast.Netd1.service \
		| install -Dm644 /dev/stdin $(DESTDIR)$(DATADIR)/dbus-1/system-services/org.nearcast.Netd1.service
	install -Dm644 packaging/dbus/org.nearcast.Netd1.conf $(DESTDIR)$(DBUS_POLICY_DIR)/org.nearcast.Netd1.conf
	install -Dm644 packaging/polkit/org.nearcast.netd.policy $(DESTDIR)$(POLKIT_ACTION_DIR)/org.nearcast.netd.policy

uninstall:
	for b in $(BINS); do rm -f $(DESTDIR)$(BINDIR)/$$b; done
	rm -f $(DESTDIR)$(SYSTEMD_USER_DIR)/nearcastd.service \
		$(DESTDIR)$(SYSTEMD_SYSTEM_DIR)/nearcast-netd.service \
		$(DESTDIR)$(DATADIR)/dbus-1/system-services/org.nearcast.Netd1.service \
		$(DESTDIR)$(DBUS_POLICY_DIR)/org.nearcast.Netd1.conf \
		$(DESTDIR)$(POLKIT_ACTION_DIR)/org.nearcast.netd.policy
