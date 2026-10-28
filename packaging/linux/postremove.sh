#!/bin/sh
# The unit file is gone, or replaced, so systemd reads its units again. The
# configuration, the databases and the openkca account are kept: they are the
# data of whoever ran the CA.
[ -d /run/systemd/system ] || exit 0
systemctl daemon-reload >/dev/null 2>&1 || :
exit 0
