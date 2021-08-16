![InitWare](http://brand.initware.com/assets/page-logo-bg.png)

***InitWare isn't ready to use yet!!***
Unless you are doing so for fun, to experiment, or to contribute, you most
likely do **not** want to try to install InitWare until a first stable 
release is made!

***Installation is not yet automatic even on 'supported' platforms!!***
It is a complex and involved process requiring an understanding of the
intricacies of how the platform boots, and it is quite easy to render the
system unbootable.

The **InitWare Suite of Middleware** allows you to manage services and system
resources as logical entities called units.

Units are manageable by a uniform interface, may specify dependencies and other
relationships to other units, and are automatically scheduled by the InitWare
Manager, a service management (or "init") system, which may run as either the
system service manager or as an auxiliary service manager under another init
system.

Added to this is a user session manager which facilitates the tracking and
management of users' login sessions, integrating with the InitWare manager to
assist in tracking. A dedicated user service manager is provided each user so
that they may manage services of their own.

The suite is completed by the optional Event Log system, which aggregates events
from many sources into a system-wide (and optionally per-user) Event Log, with
extensive metadata to facilitate querying.

#### Origin

InitWare is a fork of [systemd].

The systemd project is comprised by many programs and utilities. InitWare
excludes from its scope a number of these. See [Dropped components] for details
on these.

[systemd]: http://www.freedesktop.org/wiki/Software/systemd
[Dropped components]: https://github.com/InitWare/InitWare/wiki/Dropped-components

#### Compatibility with systemd

InitWare aims for a high level of compatibility with the core interfaces of
systemd. Unit-files, the `systemctl`, `loginctl`, and `journalctl` commands
(provided as `svcctl`, `sessionctl`, and `evlogctl` respectively), the systemd1
and Login1 D-Bus APIs, the sd_notify API, the journald stream and datagram
socket protocols, and several other interfaces are all subject to this aim.

Comprehensive compatibility with every interface is impractical on some
platforms; some unit options are entirely GNU/Linux-specific and while most have
alternatives in spirit on other platforms (e.g. Linux namespaces and FreeBSD
jails), a perfect mapping of semantics between these is not practical.
Nonetheless, it is important to us that InitWare should be able to run with
little or no modification the vast majority of systemd unit-files, and that they
should behave reasonably.

#### Differences from systemd

InitWare differs from systemd in three principal manners:
1. InitWare is highly portable.
2. InitWare aims to be significantly more modular.
3. InitWare is of significantly smaller scope, concerning itself only with
   system, service, and session management, and matters ancillary to these, such
   as event log management.

The [Roadmap](https://github.com/InitWare/InitWare/wiki/Roadmap) details some
plans for the future development of the InitWare Suite.


Platform Support
----------------

The following platforms are supported:

- NetBSD (9.0+): InitWare's native platform. All functions supported.
- FreeBSD (13.0+): All functions.
- DragonFly BSD (5.8+): No system management.
- OpenBSD (6.9+): No system and session management.
- GNU/Linux (3.6+): All functions (but note below that the build system is not
  yet properly set up.)

*n.b.* GNU/Linux support is complete but the new CMake build system for
InitWare hasn't been adapted for Linux yet. This will be completed in the
near future. In the meantime, the builds are likely to be broken.

Support for running as an auxiliary service manager on macOS is underway, and we
hope to support Illumos in the near future. Please see the [Support Matrix] for
further information on platform support.

[Support Matrix]: https://github.com/InitWare/InitWare/wiki/Support-Matrix

**Required runtime dependencies**:

- D-Bus 1.4+
- On all BSD platforms:
    - *[libinotify-kqueue](https://github.com/libinotify-kqueue/libinotify-kqueue)*
      v0.0.20180201+ (provided as `libinotify` in Ports, pkgsrc, and OpenPorts)

**Optional runtime dependencies**:

- On GNU/Linux:
    - UDev or Eudev (for `.device` unit support)
- On DragonFly BSD:
    - `udevd` running (for `.device` unit support)
- On FreeBSD:
    - *libudev-devd* (for `.device` unit support)

To build InitWare, any libraries listed above must be present complete with
their associated development libraries. Additionally required are the
following:

- a C toolchain supporting GNU C extensions, e.g. GNU CC or LLVM/Clang
- Typical build prerequisites (e.g. `build-essential` on Debian)
- CMake 3.9+
- GPerf
- Pkg-Config or pkgconf
- M4, Awk

For building the index manual page, Python 3 is required. To build HTML
documentation, DocBook stylesheets and LibXML's `xsltproc` are required.

Building is done in the typical CMake way, i.e.
`git submodule update --init --recursive && cmake && make && make install`.

Licencing
---------

Most of InitWare is licensed under the GNU Library GPL, version 2.1 or later,
but some files are under other terms. See [doc/Licences.md](doc/Licences.md)
for details. In particular, where a file does not implement any algorithm or
technology eligible for copyright (e.g. where the functionality is basic and
obviously implementable only in one way), these are released explicitly into
the public domain.

Further reading
---------------

- [Repository Tour](https://github.com/InitWare/InitWare/wiki/Repository-Tour):
  A brief overview of the layout of the repository.
- [General Style Guide](doc/Style.md): Standards of style by which code and
  documentation alike are written in InitWare.
- [C Style Guide](doc/CStyle.md): The standards of style by which code in C-like
  languages is written in InitWare.
- [Roadmap](https://github.com/InitWare/InitWare/wiki/Roadmap):
  Future plans for InitWare.
- [PTGroups](https://github.com/InitWare/InitWare/wiki/PTGroups):
  Describes PTGroups, the simple abstraction layer over the PROC filter for
  Kernel Queues, which provides advanced (CGroups-like) process tracking on the
  BSD ports of InitWare.
- [Porting Notes](https://github.com/InitWare/InitWare/wiki/Porting-Notes):
  Informal notes on how InitWare's initial port (from GNU/Linux to NetBSD) was
  carried out.
- [Contributors' Study Guide](https://github.com/InitWare/InitWare/wiki/Contributors'-Study-Guide):
  A short reading list mainly focused on problems of service management on
  Unix-like systems, written with potential contributors in mind.

<!-- - [Changes](https://github.com/InitWare/InitWare/wiki/Changes):
  Enumerates in summary significant changes made to InitWare. A page worth
  reading for anyone who wants to know in what respects InitWare differs from
  systemd.-->
