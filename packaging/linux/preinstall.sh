#!/bin/sh
# The account the service runs as, made before the files are put in place,
# since they are owned by it. rpm passes 1 on an install and 2 on an upgrade;
# either way an account that is there already is kept as it is.
getent group openkca >/dev/null || groupadd --system openkca
getent passwd openkca >/dev/null || useradd --system --gid openkca \
    --home-dir /var/lib/openkca --no-create-home --shell /sbin/nologin \
    --comment "OpenKCA certificate authority" openkca
exit 0
