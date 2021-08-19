![InitWare](http://brand.initware.com/assets/page-logo-bg.png)

***InitWare isn't ready to use yet!!***
Unless you are doing so for fun, to experiment, or to contribute, you most
likely do **not** want to try to install InitWare until a first stable 
release is made!

The InitWare Suite of Middleware allows you to manage services and system
resources as logical entities called units. It runs on GNU/Linux and most BSDs.

Units are automatically scheduled by a job scheduler according to their
dependency specifications. A user session manager facilitates tracking of users'
login sessions, with each user getting their own dedicated service manager.
Finally the Event Log System provides a system-wide Event Log aggregating
diverse log sources.

The Suite may run either as an init system or as an auxiliary service management
system under another init system. InitWare originates as a fork of systemd and
retains compatibility with many systemd interfaces.

## Frequently Asked Questions

#### How does InitWare differ from systemd?

In three ways: InitWare is highly portable, it is more modular, and it is of a
much more clearly-defined scope. See [The InitWare philosophy]. Some components
of systemd failing to provide compelling benefits are dropped; see
[Dropped components].

[The InitWare philosophy]: https://github.com/InitWare/InitWare/wiki/The-InitWare-philosophy

[Dropped components]: https://github.com/InitWare/InitWare/wiki/Dropped-components


#### How compatible is InitWare with systemd?

Unit-files, the `systemctl`, `loginctl`, and `journalctl` commands (provided as
`svcctl`, `sessionctl`, and `evlogctl` respectively), the systemd1 and Login1
D-Bus APIs, the sd_notify API, the journald stream and datagram socket
protocols, and several other interfaces are largely supported on all ports.
Some details differ by port. See [Systemd compatibility].

[Systemd compatibility]: https://github.com/InitWare/InitWare/wiki/Systemd-compatibility

#### On what platforms does InitWare run?

On NetBSD, FreeBSD, and GNU/Linux as an init system and on DragonFly BSD and
OpenBSD as an auxiliary service manager. See [Support matrix].

[Support Matrix]: https://github.com/InitWare/InitWare/wiki/Support-Matrix

#### Under what licence is InitWare released?

Most code is under the GNU LGPL v2.1, some of it is under liberal licences.

#### How does one build InitWare?

Install the dependencies first: these are a C toolchain, CMake, GPerf, M4, Awk,
Pkg-Config or pkgconf, DBus, and on BSD platforms, libinotify. Then run:

```git submodule update --init --recursive && cmake && make && make install```

See [Building] for further details.

[Building]: https://github.com/InitWare/InitWare/wiki/Building

#### Where will InitWare go from here?

Check the Issues and Projects tabs, or the
[Roadmap](https://github.com/InitWare/InitWare/wiki/Roadmap).

#### How can I contribute?

See [Contributing](https://github.com/InitWare/InitWare/wiki/Contributing).

## Myths and Truths

#### Myth: *InitWare was conceived to subvert OpenBSD*

One critic sent me an email asserting that:

>[...] you conceived this project as a plot to undermine OpenBSD, the last
 place of refuge from Poetteringware. This is a project inspired by the biblical
 Jezebel who sought to destroy Israel in a day with false Gods.

*Truth*: InitWare was conceived to satisfy personal interest, and after early
successes in the porting process, to prove that advanced service management is
viable on BSD platforms and to show how much of systemd's featureset could be
provided by a project of a differing philosophy.

#### Myth: *BSD is irrelevant and should be treated like a "dead dog"*

*Truth*: The epigones making these statements are irrelevant. BSD platforms are
prolific. BSD systems (both genetically by descent from 4.3 BSD via Mach 2.5 and
practically by provision of a standard BSD environment) called macOS and iOS
have the 2nd greatest market share of desktop and mobile operating systems. Free
and open-source BSD variants are also popular, and have a distinguished history
as pioneers of free software.

#### Myth: *Systemd cannot be ported to other systems*

*Truth*: All things are possible in software, and as systemd ultimately did not
depend on many completely Linux-specific interfaces, the process of porting it
to the BSD systems was not terribly difficult. Most Linux interfaces on which
systemd really did depend had comparable alternatives available on BSD systems.
See the [Porting notes](https://github.com/InitWare/InitWare/wiki/Porting-Notes).

#### Myth: *InitWare has no `.device` units as it doesn't include udev*

*Truth*: InitWare can integrate with udev, eudev, or even with other device
event systems to provide `.device` units. Note also the next myth.

#### Myth: *As InitWare has less code than systemd, it's less powerful*

*Truth*: The opposite is true. InitWare adopts the principle of modularity,
which requires that functionality be analysed and split across multiple modules,
each to provide one functionality. Interfaces are defined between modules to
allow their interchange and enhance fault-tolerance. The modularity principle is
considered an essential feature of good software engineering. 

Modularity makes InitWare more powerful. For example, one ongoing project
(Delegated Restarters) will ultimately allow InitWare to connect to other
daemons that provide new classes of unit (e.g. network interfaces) so that they
may be depended on and managed the same way as the built-in classes of unit.
This kind of power is currently absent from systemd.
