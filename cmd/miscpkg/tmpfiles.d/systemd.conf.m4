#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.

# See tmpfiles.d(5) for details

d /run/user 0755 root root -
F! /run/utmp 0664 root utmp -

d @SVC_PKGRUNSTATEDIR@/ask-password 0755 root root -
d @SVC_PKGRUNSTATEDIR@/seats 0755 root root -
d @SVC_PKGRUNSTATEDIR@/sessions 0755 root root -
d @SVC_PKGRUNSTATEDIR@/users 0755 root root -
d @SVC_PKGRUNSTATEDIR@/machines 0755 root root -
d @SVC_PKGRUNSTATEDIR@/shutdown 0755 root root -
m4_ifdef(`ENABLE_NETWORKD',
d @SVC_PKGRUNSTATEDIR@/netif 0755 systemd-network systemd-network -
d @SVC_PKGRUNSTATEDIR@/netif/links 0755 systemd-network systemd-network -
d @SVC_PKGRUNSTATEDIR@/netif/leases 0755 systemd-network systemd-network -
)m4_dnl

d /run/log 0755 root root -

z /run/log/journal 2755 root systemd-journal - -
Z /run/log/journal/%m ~2750 root systemd-journal - -
m4_ifdef(`HAVE_ACL',``
a+ /run/log/journal/%m - - - - d:group:adm:r-x,d:group:wheel:r-x
A+ /run/log/journal/%m - - - - group:adm:r-x,group:wheel:r-x
'')m4_dnl

z /var/log/journal 2755 root systemd-journal - -
z /var/log/journal/%m 2755 root systemd-journal - -
z /var/log/journal/%m/system.journal 0640 root systemd-journal - -
m4_ifdef(`HAVE_ACL',``
a+ /var/log/journal    - - - - d:group:adm:r-x,d:group:wheel:r-x
a+ /var/log/journal    - - - - group:adm:r-x,group:wheel:r-x
a+ /var/log/journal/%m - - - - d:group:adm:r-x,d:group:wheel:r-x
a+ /var/log/journal/%m - - - - group:adm:r-x,group:wheel:r-x
a+ /var/log/journal/%m/system.journal - - - - group:adm:r--,group:wheel:r--
'')m4_dnl

d @SVC_PKGLOCALSTATEDIR@ 0755 root root -
d @SVC_PKGLOCALSTATEDIR@/coredump 0755 root root 3d
