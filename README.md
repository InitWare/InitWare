![InitWare](http://brand.initware.com/assets/page-logo-bg.png)

**Please note that InitWare is still alpha software**. But all disclosed
security concerns have now been addressed. Running InitWare as an auxiliary
service manager under NetBSD can now, then, be regarded as safe; but beware
relying on this in production until a first stable release is made.

The InitWare Suite of Middleware allows you to manage services and system
resources as logical entities called units. It runs on NetBSD, GNU/Linux, and
all the other modern BSD systems.

Units are automatically scheduled by a job scheduler according to their
dependency specifications. A user session manager facilitates tracking of users'
login sessions, with each user provided their own dedicated service manager.
Finally the InitWare System Log provides a system-wide event log aggregating
diverse log sources.

The Suite may run either as an init system or as an auxiliary service management
system under another init system. InitWare originates as a fork of systemd and
retains compatibility with many systemd interfaces, even on non-Linux platforms.

| Platform | Build Status |
|----------|--------------|
|GNU/Linux (Alpine)   |[![builds.sr.ht status](https://builds.sr.ht/~netbsduser/initware/commits/alpine.yaml.svg)](https://builds.sr.ht/~netbsduser/initware/commits/alpine.yaml?)|
|FreeBSD   |[![builds.sr.ht status](https://builds.sr.ht/~netbsduser/initware/commits/freebsd.yaml.svg)](https://builds.sr.ht/~netbsduser/initware/commits/freebsd.yaml?)|
|NetBSD    |[![builds.sr.ht status](https://builds.sr.ht/~netbsduser/initware/commits/netbsd.yaml.svg)](https://builds.sr.ht/~netbsduser/initware/commits/netbsd.yaml?)|
|OpenBSD   |[![builds.sr.ht status](https://builds.sr.ht/~netbsduser/initware/commits/openbsd.yaml.svg)](https://builds.sr.ht/~netbsduser/initware/commits/openbsd.yaml?)|

## Frequently Asked Questions

#### How does InitWare differ from systemd?

In three ways: InitWare is highly portable, it is more modular, and it is of a
much more clearly-defined scope. See [The InitWare philosophy].

Some components of systemd failing to provide compelling benefits are dropped;
see [Dropped components].

[The InitWare philosophy]: https://github.com/InitWare/InitWare/wiki/The-InitWare-philosophy

[Dropped components]: https://github.com/InitWare/InitWare/wiki/Dropped-components

#### How compatible is InitWare with systemd?

Unit-files, the `systemctl`, `loginctl`, and `journalctl` commands (provided as
`svcctl`, `sessionctl`, and `syslogctl` respectively), the systemd1 and Login1
D-Bus APIs, the sd_notify API, the journald stream and datagram socket
protocols, and several other interfaces are largely supported on all ports.
Some details differ by port. See [Systemd compatibility].

[Systemd compatibility]: https://github.com/InitWare/InitWare/wiki/Systemd-compatibility

#### On what platforms does InitWare run?

InitWare is native to NetBSD. It runs on NetBSD, FreeBSD, and GNU/Linux - its
first-class targets - as an init system; on macOS, DragonFly BSD and OpenBSD, it
runs as an auxiliary service manager. See
[Support matrix].

[Support Matrix]: https://github.com/InitWare/InitWare/wiki/Support-Matrix

#### Under what licence is InitWare released?

Most code is under the GNU Library GPL v2.1, some of it is under liberal licences.

#### How does one build InitWare?

Install the dependencies first: these are a C toolchain, cmake, gperf, m4, awk,
pkg-config or pkgconf, and on BSD platforms, libinotify. Then run:

```git submodule update --init --recursive && cmake && make && make install```

See [Building] for further details.

[Building]: https://github.com/InitWare/InitWare/wiki/Building

#### Where will InitWare go from here?

Check the Issues and Projects tabs, or the
[Roadmap](https://github.com/InitWare/InitWare/wiki/Roadmap).

#### How can I contribute?

See [Contributing](https://github.com/InitWare/InitWare/wiki/Contributing).

#### Where can I find out more?

Check [the Wiki]. The [Myths and Truths] page is a good place to start.

[The Wiki]: https://github.com/InitWare/InitWare/wiki
[Myths and Truths]: https://github.com/InitWare/InitWare/wiki/Myths-and-Truths
