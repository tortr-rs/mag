#!/bin/sh
# builds a fake repo with local tarballs and goes through install, upgrade, remove and the rest in a scratch root.
# needs curl (for file:// urls), tar and the rifle tools in PATH
cd "$(dirname "$0")/.."
MAG=$PWD/mag
T=$(mktemp -d /var/tmp/mag-test.XXXXXX)
trap 'rm -rf "$T"' EXIT
export MAG_ROOT=$T/root MAG_REPO=$T/repo MAG_FETCH='curl -fsSL -o'
mkdir -p "$T/root" "$T/repo/lib" "$T/repo/app" "$T/src"
pass=0; fail=0
check() {
	if [ "$2" = "$3" ]; then pass=$((pass+1)); else fail=$((fail+1)); printf 'FAIL: %s\n  want: %s\n  got:  %s\n' "$1" "$2" "$3"; fi
}

mktar() {
	d=$T/src/$1-$2; mkdir -p "$d"; printf '%s\n' "$3" >"$d/hello.txt"
	tar -C "$T/src" -cf "$T/src/$1-$2.tar" "$1-$2"
	sha256sum "$T/src/$1-$2.tar" | cut -d' ' -f1
}

recipe() {
	# recipe CATEGORY/NAME VERSION DEPS
	n=${1#*/}; sum=$(mktar "$n" "$2" "$n $2")
	cat >"$T/repo/$1" <<R
desc: the $n test package
version: $2
url: file://$T/src/$n-\${version}.tar
sha256: $sum
deps: $3
steps:
	mkdir -p \$DESTDIR\$PREFIX/share/$n \$DESTDIR/etc
	cp hello.txt \$DESTDIR\$PREFIX/share/$n/hello.txt
	echo conf-$2 >\$DESTDIR/etc/$n.conf
	ln -s hello.txt \$DESTDIR\$PREFIX/share/$n/link
R
}

recipe lib/zlib 1.0 ""
recipe app/tool 1.0 "lib/zlib"

check 'info' "app/tool 1.0
  the tool test package
  source: file://$T/src/tool-1.0.tar
  deps: lib/zlib
  recipe: $T/repo/app/tool
  not installed" "$($MAG info tool)"
check 'search' "lib/zlib 1.0  the zlib test package" "$($MAG search zlib)"
check 'deps' "lib/zlib" "$($MAG deps app/tool)"
check 'dry run' "will install: lib/zlib app/tool" "$($MAG -n install tool)"

$MAG install tool >"$T/out" 2>&1; check 'install exit' 0 $?
check 'file in root' "tool 1.0" "$(cat "$T/root/usr/share/tool/hello.txt")"
check 'dep installed' "zlib 1.0" "$(cat "$T/root/usr/share/zlib/hello.txt")"
check 'symlink' "hello.txt" "$(readlink "$T/root/usr/share/tool/link")"
check 'list' "app/tool 1.0
lib/zlib 1.0" "$($MAG list)"
check 'files' "/etc/tool.conf
/usr/share/tool/hello.txt
/usr/share/tool/link" "$($MAG files tool)"
check 'owns' "$T/root/usr/share/tool/hello.txt is owned by app/tool" "$($MAG owns "$T/root/usr/share/tool/hello.txt" | sed "s|$T/root/usr/share/tool/hello.txt is|$T/root/usr/share/tool/hello.txt is|")"
check 'rdeps' "app/tool" "$($MAG rdeps zlib)"
check 'again' "app/tool 1.0 is installed already" "$($MAG install tool)"
check 'build dir gone' "" "$(ls "$T/root/var/tmp/mag" 2>/dev/null)"

$MAG remove zlib >"$T/out" 2>&1; check 'remove needed' 1 $?
check 'still there' 1 "$(test -f "$T/root/usr/share/zlib/hello.txt" && echo 1)"

echo changed >"$T/root/etc/tool.conf"
recipe app/tool 2.0 "lib/zlib"
$MAG upgrade >"$T/out" 2>&1; check 'upgrade exit' 0 $?
check 'upgraded' "tool 2.0" "$(cat "$T/root/usr/share/tool/hello.txt")"
check 'etc kept' "changed" "$(cat "$T/root/etc/tool.conf")"
check 'etc new' "conf-2.0" "$(cat "$T/root/etc/tool.conf.new")"
check 'upgrade again' "everything is up to date" "$($MAG upgrade)"

printf 'x' >"$T/root/usr/share/zlib/hello.txt"
$MAG -n remove tool >/dev/null; check 'dry remove keeps' "tool 2.0" "$(cat "$T/root/usr/share/tool/hello.txt")"
$MAG remove tool >"$T/out" 2>&1; check 'remove exit' 0 $?
check 'gone' "" "$(ls "$T/root/usr/share/tool" 2>/dev/null)"
check 'dir gone' "" "$(ls -d "$T/root/usr/share/tool" 2>/dev/null)"
check 'dep left' "lib/zlib 1.0" "$($MAG list)"
$MAG autoremove >"$T/out" 2>&1; check 'autoremove exit' 0 $?
check 'orphan gone' "" "$($MAG list)"

$MAG install zlib >/dev/null 2>&1
mkdir -p "$T/root/usr/share/tool"; echo mine >"$T/root/usr/share/tool/hello.txt"
$MAG install tool >"$T/out" 2>&1; check 'clash' 1 $?
check 'clash kept' "mine" "$(cat "$T/root/usr/share/tool/hello.txt")"

printf 'x\n' >"$T/f"
check 'hash' "$(sha256sum "$T/f" | cut -d' ' -f1)  $T/f" "$($MAG hash "$T/f")"

cat >"$T/repo/lib/bad" <<R
version: 1
url: file://$T/src/zlib-1.0.tar
sha256: 0000000000000000000000000000000000000000000000000000000000000000
steps:
	true
R
$MAG install bad >"$T/out" 2>&1; check 'bad sum' 1 $?
cat >"$T/repo/lib/loop1" <<R
deps: lib/loop2
R
cat >"$T/repo/lib/loop2" <<R
deps: lib/loop1
R
$MAG install loop1 >"$T/out" 2>&1; check 'cycle' 1 $?
$MAG install nosuch >"$T/out" 2>&1; check 'missing' 1 $?
cat >"$T/repo/lib/fails" <<R
steps:
	exit 3
R
$MAG install fails >"$T/out" 2>&1; check 'failing steps' 1 $?
check 'not recorded' "" "$($MAG list | grep fails)"

# pkgsrc builds with bmake: a stand-in that runs the host make
mkdir -p "$T/repo/devel"
sum=$(mktar bmake 1.0 "bmake 1.0")
cat >"$T/repo/devel/bmake" <<R
desc: bmake stand-in
version: 1.0
url: file://$T/src/bmake-\${version}.tar
sha256: $sum
deps:
steps:
	mkdir -p \$DESTDIR\$PREFIX/bin
	printf '#!/bin/sh\nexec make "\$@"\n' >\$DESTDIR\$PREFIX/bin/bmake
	chmod 755 \$DESTDIR\$PREFIX/bin/bmake
R

# pkgsrc packages: a Makefile and a distinfo, read in place
mkdir -p "$T/repo/mk/fetch" "$T/repo/devel/hello" "$T/repo/devel/hello/patches" "$T/repo/devel/base" "$T/src/hello-2.1"
printf 'MASTER_SITE_LOCAL+=\tfile://%s/src/\n' "$T" >"$T/repo/mk/fetch/sites.mk"
printf 'all:\n\t@echo built\ninstall:\n\tmkdir -p $(DESTDIR)$(PREFIX)/share/hello\n\tcp hello.txt $(DESTDIR)$(PREFIX)/share/hello/hello.txt\n' >"$T/src/hello-2.1/Makefile"
echo 'hello 2.1' >"$T/src/hello-2.1/hello.txt"
tar -C "$T/src" -cf "$T/src/hello-2.1.tar" hello-2.1
hsum=$(sha512sum "$T/src/hello-2.1.tar" | cut -d' ' -f1)
cat >"$T/repo/devel/hello/Makefile" <<R
# \$NetBSD\$

DISTNAME=	hello-2.1
CATEGORIES=	devel
MASTER_SITES=	file://$T/src/
EXTRACT_SUFX=	.tar
COMMENT=	a pkgsrc test package
DEPENDS+=	base>=1.0:../../devel/base
MAKE_ENV+=	PREFIX=/usr
.if \${OPSYS} == "Linux"
MAKE_FLAGS+=	PREFIX=/usr
.endif
.include "../../mk/bsd.pkg.mk"
R
printf 'SHA512 (hello-2.1.tar) = %s\nSize (hello-2.1.tar) = 1 bytes\n' "$hsum" >"$T/repo/devel/hello/distinfo"
printf 'DISTNAME=\tbase-1.0\nCOMMENT=\tthe base\nEXTRACT_SUFX=\t.tar\nMASTER_SITES=\tfile://%s/src/\n' "$T" >"$T/repo/devel/base/Makefile"
mkdir -p "$T/src/base-1.0"; echo b >"$T/src/base-1.0/hello.txt"; printf 'install:\n\tmkdir -p $(DESTDIR)/usr/share/base\n\tcp hello.txt $(DESTDIR)/usr/share/base/\n' >"$T/src/base-1.0/Makefile"
tar -C "$T/src" -cf "$T/src/base-1.0.tar" base-1.0
printf 'SHA512 (base-1.0.tar) = %s\n' "$(sha512sum "$T/src/base-1.0.tar" | cut -d' ' -f1)" >"$T/repo/devel/base/distinfo"
printf '%s\n' '$NetBSD$' '' '--- hello.txt.orig' '+++ hello.txt' '@@ -1 +1 @@' '-hello 2.1' '+hello patched' >"$T/repo/devel/hello/patches/patch-hello"
check 'pkgsrc info' "devel/hello 2.1
  a pkgsrc test package
  source: file://$T/src/hello-2.1.tar
  deps: devel/base devel/bmake
  recipe: $T/repo/devel/hello/Makefile
  not installed" "$($MAG info devel/hello)"
$MAG install devel/hello >"$T/out" 2>&1; check 'pkgsrc install' 0 $?
check 'pkgsrc patch' "hello patched" "$(cat "$T/root/usr/share/hello/hello.txt")"
check 'pkgsrc dep' "b" "$(cat "$T/root/usr/share/base/hello.txt")"
printf 'SHA512 (hello-2.1.tar) = %s\n' "0000" >"$T/repo/devel/hello/distinfo"
rm -f "$T/root/var/cache/mag/hello-2.1.tar"
$MAG remove hello >/dev/null 2>&1; $MAG install devel/hello >"$T/out" 2>&1; check 'pkgsrc wrong checksum' 1 $?

# options and mag.conf
mkdir -p "$T/repo/devel/opt" "$T/root/etc"
cat >"$T/repo/devel/opt/Makefile" <<'R'
DISTNAME=	opt-1.0
MASTER_SITES=	file:///nonexistent/
COMMENT=	a package with options
.include "options.mk"
.include "../../mk/bsd.pkg.mk"
R
cat >"$T/repo/devel/opt/options.mk" <<'R'
PKG_OPTIONS_VAR=	PKG_OPTIONS.opt
PKG_SUPPORTED_OPTIONS=	alpha beta gamma
PKG_SUGGESTED_OPTIONS=	alpha beta
.include "../../mk/bsd.options.mk"
.if !empty(PKG_OPTIONS:Mbeta)
DEPENDS+=	base>=1:../../devel/base
.endif
R
echo 'SHA512 (opt-1.0.tar.gz) = 00' >"$T/repo/devel/opt/distinfo"
check 'options suggested' "  options: alpha beta" "$($MAG info devel/opt | grep '^  options:')"
check 'options give a dep' "devel/base
devel/bmake" "$($MAG deps devel/opt)"
printf 'PKG_DEFAULT_OPTIONS=-beta gamma\n' >"$T/root/etc/mag.conf"
check 'mag.conf default options' "  options: alpha gamma" "$($MAG info devel/opt | grep '^  options:')"
check 'options off, dep gone' "devel/bmake" "$($MAG deps devel/opt)"
printf 'PKG_DEFAULT_OPTIONS=-beta\nPKG_OPTIONS.opt=gamma -alpha\n' >"$T/root/etc/mag.conf"
check 'package option variable' "  options: gamma" "$($MAG info devel/opt | grep '^  options:')"
rm "$T/root/etc/mag.conf"

echo "$pass passed, $fail failed"
[ $fail = 0 ]
