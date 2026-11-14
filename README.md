mag
===

The package manager, one C file on c.h, built with clang and lld. No libc under it, no GNU in it.

A recipe is a plain file in a repo, `category/name`, like `dev-vcs/git`:

    desc: the stupid content tracker
    version: 2.47.0
    url: https://mirrors.edge.kernel.org/pub/software/scm/git/git-${version}.tar.xz
    sha256: 1ce114da88704271b43e027c51e04d9399f8c88e9ef7542dae7aebae7d87bc4e
    deps: sys-libs/zlib
    steps:
    	make -j$JOBS prefix=$PREFIX all
    	make prefix=$PREFIX DESTDIR=$DESTDIR install

`url`, `sha256`, `deps` and `steps` are the ones that matter. The steps are plain sh, run with `sh -e` inside
the unpacked source (leading components stripped), with `$DESTDIR` (everything goes there), `$PREFIX` (/usr),
`$JOBS`, `$NAME`, `$VERSION`, `$SRC` and `$RECIPE_DIR` set. If the recipe is a directory with a file called
`recipe` in it, whatever else is in there (patches) is at `$RECIPE_DIR`.

    ./build.sh               builds ./mag
    mag install git          fetches, checks the sha256, builds, installs, dependencies first
    mag remove git           mag help has the rest
    tests/run.sh             a fake repo with local tarballs, install to remove in a scratch root

What it does on the way: files are checked against what other packages own before anything is touched, they
are put in place with a rename so a running program is never half written, and anything under /etc that is
already there is left alone (a changed one comes as `.new`). Every package keeps its file list in
`var/lib/mag`, so `remove`, `files`, `owns` and `autoremove` need nothing else.

`MAG_ROOT` installs somewhere else than /, `MAG_REPO` is a list of repos split by colons, `MAG_FETCH` is the
download command (it needs https, which mag doesn't do itself: curl by default). tar and rm come from the
system, which here means rifle and a tar.
