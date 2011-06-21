#!/bin/sh

export FORCE_NET_KA=60

export LD_PRELOAD="${LD_PRELOAD}:./force_bind.so"

strace -o test_ka1.strace -f -s100 ./test_bind "$@"
