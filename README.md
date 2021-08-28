# Proone Worm Project
**Proone** is a Linux worm designed to target unconfigured IoT embedded devices
with MMU. It features self-contained breaking and entering, replicating, IPv6
support and CNC using DNS over TLS.

Copyright (c) 2019-2021 David Timber &lt;mieabby@gmail.com&gt;

## Foreword
In a nutshell, this project is a reengineered version of Mirai, but in a serious
tone and with some extras. Inspired by the work of original authors of Mirai,
I started this project on the new year's eve of 2020. I don't mean any harm to
this world. This is merely one of my "art projects" and I hope it will stay that
way.

I named this project "**Proone**" because the first idea as to what to do with
this worm was "pruning" bad devices off this big tree called the Internet. The
bad devices I refer to here are neglected/obsolete devices running unpatched
software and poorly made devices with built-in security vulnerabilities like
predictible default logins and unlocked maintenance backdoors. Especially, these
vulnerable devices running on a network without a firewall fall victim of being
botnets for nefarious purposes. My original idea was a "search and destroy"
operation against these devices for a good cause.

During the development, I came to realise that this is a bad idea and that I
lack the balls to pull this off. Therefore I hereby abandon the idea by
publishing my work online.

Call this whatever you want: reinventing the wheel, copycat, waste of time...
Whatever you want to call it, working on this project helped me a lot.

## Message to General Public
**This software is a malware**. This software has been tested to work in an
orchestrated virtual environment. In principle, it works by scanning the
Internet and local network for computers with security vulnerabilities. This
software is programmed to do something illegal! If you wish to use this
software, please do so in a controlled environment safely isolated from the
Internet.

## Index of Documents
Where to go from here

* [User Guide](doc/user_guide.md)
* [Software Design Spec](doc/sws.md)
* [Protocol Spec](doc/proto.md)
* [Dev Notes](doc/dev_notes.md)

## Subprojects
* proone-xcomp: Infrastructure for building and testing cross-compiled builds (TODO)
