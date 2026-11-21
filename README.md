mag
===

The package manager, one C file. It installs prebuilt packages from apk repos: it reads their signed index,
works out what a package needs, checks every download against the index and the package's own hash, and puts
the files in place. gzip, tar and the rsa check are in mag itself, the only thing it runs is a download
command (curl, else wget, else ftp).

    ./build.sh               builds ./mag on c.h (x86_64)
    cc -DLIBC -static mag.c  builds it on a libc, for any other cpu

    mag update               gets the index of every repo
    mag install tmux         tmux and what it needs
    mag remove tmux          mag help has the rest

`/etc/mag/repos` has one repo a line (the url above the arch directory), `/etc/mag/keys` the public keys the
indexes are signed with, `/etc/mag/arch` which builds to get, `x86_64` or `x86` and so on. It is written on
the first install, and without it mag goes by the machine.

CRUX ports work too. A line `crux https://crux.nu/ports/crux-3.8/opt` in `/etc/mag/repos` is a port tree: `mag
update` gets the files that changed, as httpup does, and `mag build foo` builds the port and installs it. The
`.signature` of the port is checked with its key (`opt.pub` in `/etc/mag/keys`, ed25519 is in mag too), then
the sources against it, and `build()` runs with bash. What a repo has built wins over a port of the same name;
`mag install` takes a port only when no repo has it. A port gets build-base, pkgconf and bash, and the `-dev`
package of every dependency that comes built.

What it does on the way: files are checked against what other packages own before anything is touched, they
are put in place with a rename so a running program is never half written, and a changed file under /etc is
left alone (the new one comes as `.new`). A package's scripts run inside the root; one whose interpreter is not
installed yet waits until the end. Every package keeps its file list in `var/lib/mag`, so `remove`, `files`,
`owns` and `autoremove` need nothing else.

`MAG_ROOT` installs somewhere else than /, `MAG_ARCH` overrides the arch, `MAG_FETCH` is the download command.
