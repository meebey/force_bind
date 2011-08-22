#!/bin/sh

export FORCE_NET_VERBOSE=1
export FORCE_NET_PRIO=2

export LD_PRELOAD="${LD_PRELOAD}:./force_bind.so"

strace -o ${0}.strace -f -s100 ./test_client "$@"
