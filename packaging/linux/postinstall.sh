#!/bin/sh
# rpm passes 1 on an install and 2 or more on an upgrade.
#
# The configuration is /var/lib/openkca/config.yaml, the data folder
# /var/lib/openkca/data. Before 0.13.0 the configuration was
# /etc/openkca/config.yaml and the databases were in /var/lib/openkca
# itself: an upgrade from there moves them. The old package's
# /etc/openkca/config.yaml is removed by rpm after this script, or kept as
# config.yaml.rpmsave if it had been changed.
#
# A first install has no configuration: OpenKCA does not start without a
# server password, so openkca setup writes the default configuration with a
# random one, which goes into initial-password, readable by root alone.
#
# Then the service is enabled and started on an install, and restarted into
# the new binary on an upgrade, unless it had been stopped. Without systemd
# running, in a container build for instance, there is nothing to start.
# Packages cannot ask questions, so the install points to openkca setup.
dir=/var/lib/openkca
config=$dir/config.yaml
initial=$dir/initial-password
old_dir=/etc/openkca

mkdir -p "$dir"
chown openkca:openkca "$dir"
chmod 0700 "$dir"

if [ ! -e "$config" ] && [ -f "$old_dir/config.yaml" ]; then
    # the upgrade from /etc/openkca: everything in the old data folder goes
    # into data/
    mkdir -p "$dir/data"
    for f in "$dir"/* "$dir"/.[!.]* "$dir"/..?*; do
        [ -e "$f" ] || [ -L "$f" ] || continue
        case "${f##*/}" in
            data|config.yaml|initial-password) continue ;;
        esac
        mv "$f" "$dir/data/" && echo "openkca: moved $f to $dir/data/"
    done
    chown openkca:openkca "$dir/data"
    chmod 0700 "$dir/data"
    # data_dir is always data/ now
    sed '/^  data_dir:/d' "$old_dir/config.yaml" > "$config.new" &&
        chown openkca:openkca "$config.new" && chmod 0600 "$config.new" &&
        mv "$config.new" "$config" &&
        echo "openkca: moved the configuration $old_dir/config.yaml to $config"
    if [ -f "$old_dir/initial-password" ]; then
        mv "$old_dir/initial-password" "$initial"
        chown root:root "$initial"
        chmod 0600 "$initial"
    fi
fi

if [ ! -e "$config" ]; then
    pw=$(head -c 18 /dev/urandom | base64)
    if printf '%s\n' "$pw" | runuser -u openkca -- /usr/bin/openkca setup --config "$config" --password-stdin >/dev/null 2>&1; then
        (umask 077 && printf '%s\n' "$pw" > "$initial")
        chown root:root "$initial"
        echo "openkca: the initial server password is in $initial"
    else
        echo "openkca: no configuration written; run: sudo -u openkca openkca setup"
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
scheme=http
grep -qx '  https: true' "$config" 2>/dev/null && scheme=https
echo "openkca: the web UI is available at $scheme://<this host>:${port:-9080}/"
if [ "${1:-1}" -eq 1 ]; then
    echo "openkca: to choose HTTPS or HTTP, the ports and the server password, run: sudo openkca setup"
fi
exit 0
