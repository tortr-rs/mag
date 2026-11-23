mag
===

The package manager, one C file. It installs prebuilt packages from apk and pacman repos: it reads their signed
index, works out what a package needs, checks every download against the index and its signature, and puts
the files in place. gzip, zstd, tar, rsa, ed25519 and OpenPGP are in mag itself, the only thing it runs is a
download command (curl, else wget, else ftp).

    ./build.sh               builds ./mag on c.h (x86_64)
    cc -DLIBC -static mag.c  builds it on a libc, for any other cpu

    mag update               gets the index of every repo
    mag install tmux         tmux and what it needs, after a y
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

Void and Exherbo work as well: `void https://github.com/void-linux/void-packages` and `exherbo
https://gitlab.exherbo.org/exherbo/arbor`. `mag update` gets the tree as a tarball. A Void template is run with
the helpers in the tree's `common/`, as xbps-src runs it, and its sources are checked against the template's sha256.
An exheres is run on a small exheres-0 in mag, with the tree's exlibs. Neither tree is signed, and exheres have no
checksums for their sources.

pacman repos are read as they are: `pacman https://geo.mirror.pkgbuild.com/extra/os` (the url above the arch
directory). mag reads the database, checks a package against its sha256 there and its OpenPGP signature (RSA or
ed25519) with the keyrings in `/usr/share/pacman/keyrings` and any `*.gpg` in `/etc/mag/keys`, runs its
`.INSTALL` and, after the run, the hooks in `/usr/share/libalpm/hooks` as pacman does. A name in two pacman repos
comes from the first, as in pacman. `aur https://aur.archlinux.org` adds the AUR: its metadata dump is the index,
and a package is built with makepkg as nobody, with its build dependencies from the binary repos first.

What it does on the way: files are checked against what other packages own before anything is touched, they
are put in place with a rename so a running program is never half written, and a changed file under /etc is
left alone (the new one comes as `.new`). A package's scripts run inside the root; one whose interpreter is not
installed yet waits until the end. Every package keeps its file list in `var/lib/mag`, so `remove`, `files`,
`owns` and `autoremove` need nothing else.

`MAG_ROOT` installs somewhere else than /, `MAG_ARCH` overrides the arch, `MAG_FETCH` is the download command.
