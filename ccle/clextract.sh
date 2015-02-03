#!/bin/sh
#Usage: cle <architecture> <bin>
# It assumes you have qemu-user installed and the right libc6-cross for the
# architecture.

# This runs cle for the provided architecture against the provided
# binary.

if [ -z $1 ] || [ -z $2 ]  ; then
    echo "Usage: cle <architecture> <bin>"
    exit 1
fi

arch=$1
bin=$2

qemu="qemu-${arch}"
ldpath="${PWD}/${arch}/"

# Try to find stuff automatically
lib=$(ls /usr | grep ${arch}- | sed 's/\n//')

# Exceptions
if [ "${arch}" = "i386" ] ; then
    inc="/lib32"

elif [ "${arch}" = "armhf" ] ; then
    inc="/usr/arm-linux-gnueabihf"
	qemu="qemu-arm"

elif [ "${arch}" = "armel" ] ; then
    inc="/usr/arm-linux-gnueabi"
	qemu="qemu-arm"

elif [ "${arch}" = "ppc" ] ; then
    inc="/usr/powerpc-linux-gnu"

else
    inc="/usr/$lib/"
fi

if ! [ -d "$inc" ] ; then
    echo "-L $inc"
    echo "Check that you have the right libc6-cross for ${arch}"
    exit 2
fi

${qemu} -L ${inc} -E LD_LIBRARY_PATH=${ldpath}:/lib ${arch}/cle ${bin}

