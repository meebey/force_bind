#!/bin/sh

export FORCE_NET_MSS=1280

export LD_PRELOAD="${LD_PRELOAD}:./force_bind.so"

strace -s100 -o "${0}.strace" ./test_bind "$@"
