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

What it does on the way: files are checked against what other packages own before anything is touched, they
are put in place with a rename so a running program is never half written, and a changed file under /etc is
left alone (the new one comes as `.new`). A package's scripts run inside the root; one whose interpreter is not
installed yet waits until the end. Every package keeps its file list in `var/lib/mag`, so `remove`, `files`,
`owns` and `autoremove` need nothing else.

`MAG_ROOT` installs somewhere else than /, `MAG_ARCH` overrides the arch, `MAG_FETCH` is the download command.
