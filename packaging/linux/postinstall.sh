#!/bin/sh
# rpm passes 1 on an install and 2 or more on an upgrade.
#
# OpenKCA does not start without a server password, so a configuration that
# has none yet gets a random one: its hash goes into the configuration, the
# password itself into initial-password, readable by root alone. A
# configuration with a password is left as it is.
#
# Then the service is enabled and started on an install, and restarted into
# the new binary on an upgrade, unless it had been stopped. Without systemd
# running, in a container build for instance, there is nothing to start.
# Packages cannot ask questions, so the install points to openkca setup.
config=/etc/openkca/config.yaml
initial=/etc/openkca/initial-password

if grep -qx '  password_hash: ""' "$config" 2>/dev/null; then
    pw=$(head -c 18 /dev/urandom | base64)
    if line=$(printf '%s\n' "$pw" | /usr/bin/openkca set-password) && [ -n "$line" ]; then
        (umask 077 && printf '%s\n' "$pw" > "$initial")
        chown root:root "$initial"
        # the hash holds $ and /, but no |
        sed -i "s|^  password_hash: \"\"\$|$line|" "$config"
        echo "openkca: the initial server password is in $initial"
    else
        echo "openkca: no server password set; run openkca set-password and put its line into $config"
    fi
fi

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || :
    if [ "${1:-1}" -eq 1 ]; then
        systemctl enable --now openkca.service >/dev/null 2>&1 || :
    else
        systemctl try-restart openkca.service >/dev/null 2>&1 || :
    fi
fi
# the port of general.listen, the first listen line
port=$(sed -n 's/^  listen: *"\{0,1\}[^"]*:\([0-9]*\)"\{0,1\}.*/\1/p' "$config" 2>/dev/null | head -n 1)
scheme=https
grep -qx '  https: false' "$config" 2>/dev/null && scheme=http
echo "openkca: the web UI is available at $scheme://<this host>:${port:-9443}/"
if [ "${1:-1}" -eq 1 ]; then
    echo "openkca: to choose HTTPS or HTTP, the ports and the server password, run: sudo openkca setup"
fi
exit 0
