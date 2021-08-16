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

# Frequently Asked Questions

## How does InitWare differ from systemd?

In three ways: InitWare is highly portable, it is more modular, and it is of a
much more clearly-defined scope. See [The InitWare philosophy]. Some components
of systemd failing to provide compelling benefits are dropped; see
[Dropped components].

[The InitWare philosophy]: https://github.com/InitWare/InitWare/wiki/The-InitWare-philosophy

[Dropped components]: https://github.com/InitWare/InitWare/wiki/Dropped-components


## How compatible is InitWare with systemd?

Unit-files, the `systemctl`, `loginctl`, and `journalctl` commands (provided as
`svcctl`, `sessionctl`, and `evlogctl` respectively), the systemd1 and Login1
D-Bus APIs, the sd_notify API, the journald stream and datagram socket
protocols, and several other interfaces are largely supported on all ports.
Some details differ by port. See [Systemd compatibility].

[Systemd compatibility]: https://github.com/InitWare/InitWare/wiki/Systemd-compatibility

## On what platforms does InitWare run?

On NetBSD, FreeBSD, and GNU/Linux as an init system and on DragonFly BSD and
OpenBSD as an auxiliary service manager. See [Support matrix].

[Support Matrix]: https://github.com/InitWare/InitWare/wiki/Support-Matrix

## But isn't systemd unportable software?

Not if you would make the effort to change that. The BSDs are powerful and
sophisticated platforms with functionality more than sufficient to provide most
features of systemd. See
[Porting notes](https://github.com/InitWare/InitWare/wiki/Porting-Notes).

## Under what licence is InitWare released?

Most code is under the GNU LGPL v2.1, some of it is under liberal licences.

## How does one build InitWare?

Install the dependencies first: these are a C toolchain, CMake, GPerf, M4, Awk,
Pkg-Config or pkgconf, DBus, and on BSD platforms, libinotify. Then run:

```git submodule update --init --recursive && cmake && make && make install```

See [Building] for further details.

[Building]: https://github.com/InitWare/InitWare/wiki/Building

## Where will InitWare go from here?

Check the Issues and Projects tabs, or the
[Roadmap](https://github.com/InitWare/InitWare/wiki/Roadmap).

## How can I contribute?

See [Contributing](https://github.com/InitWare/InitWare/wiki/Contributing).

## Why was InitWare conceived?

One critic sent to me an email asserting that:

>[...] you conceived this project as a plot to undermine OpenBSD, the last
 place of refuge from Poetteringware. This is a project inspired by the biblical
 Jezebel who sought to destroy Israel in a day with false Gods.

This is untrue. InitWare was conceived as a reproach to the epigones who treat
BSD as a "dead dog". I decided to bring systemd to BSD as a demonstration in
fact and not in empty words of the power and sophistication of the BSD systems,
by showing that an advanced service manager can run on BSD systems.

The project also serves as an attempt to explore how systemd could be refactored
and altered in line with a different philosophy. See
[the first FAQ entry](#how-does-initware-differ-from-systemd).