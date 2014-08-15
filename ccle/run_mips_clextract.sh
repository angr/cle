#!/bin/sh

qemu-mips -L /usr/mips-linux-gnu/ -E LD_LIBRARY_PATH=$PWD/mips mips/clextract $1
