#!/bin/bash
# Copyright (c) 2020 TrussLab@University of California, Irvine.
# Authors: Hsin-Wei Hung <hsinweih@uci.edu>
# All rights reserved.
#
# This document is shared under the GNU Free Documentation License WITHOUT ANY WARRANTY. See https://www.gnu.org/licenses/ for details.
#
MOUSSE_ROOT=/home/$USER/Mousse
SRC=$MOUSSE_ROOT/mousse_source/mousse_server/src
OUT=$MOUSSE_ROOT/mousse_build/mousse_server_build

mkdir -p $OUT

g++ -std=c++14 -o $OUT/exec_trace_parser $SRC/exec_trace_parser.cpp
g++ -pthread -std=c++14 -o $OUT/mousse_server $SRC/server.cpp -lstdc++fs

export NDK=$MOUSSE_ROOT/mousse_dependencies
export SYSROOT="$NDK/sysroot"
export PREFIX="$NDK/bin/arm-linux-androideabi-"
export AR=${PREFIX}ar
export AS=${PREFIX}as
export LD=${PREFIX}ld
export NM=${PREFIX}nm
export CLANG=${PREFIX}clang
export CXXCLANG=${PREFIX}clang++
export CPP=${PREFIX}cpp
export CXXCPP=${PREFIX}cpp
export STRIP=${PREFIX}strip
export RANLIB=${PREFIX}ranlib
export STRINGS=${PREFIX}strings
export CFLAGS="-I${NDK}/include"
export LDFLAGS="-fPIE -pie -Wl,-rpath-link=${SYSROOT}/usr/lib -latomic"

${CLANG} --sysroot=${SYSROOT} ${CFLAGS} ${LDFLAGS} -o $OUT/executor $SRC/executor.c
