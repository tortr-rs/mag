#!/bin/sh
# builds mag with clang and lld on c.h, no libc under it
set -e
cd "$(dirname "$0")"
${CC:-cc} -std=gnu11 -O2 -Wall -Wextra -Wno-missing-field-initializers -Wno-deprecated-non-prototype -Wno-unused-parameter -Wno-empty-body \
    -static -nostdlib -ffreestanding -fno-builtin -fno-stack-protector -fno-asynchronous-unwind-tables \
    -fno-pie -ffunction-sections -fdata-sections -fuse-ld=lld -Wl,--gc-sections -Wl,-s -Wl,-z,norelro \
    -o mag mag.c
