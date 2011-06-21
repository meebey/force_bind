#!/bin/sh

export FORCE_NET_VERBOSE=1
export FORCE_NET_TOS="0x0f"
export FORCE_NET_KA=60
export FORCE_NET_MSS=1400
export FORCE_NET_REUSEADDR=1
export FORCE_NET_NODELAY=1

export LD_PRELOAD="${LD_PRELOAD}:./force_bind.so"

debug ./test_bind

strace -o test_all.strace -f -s100 ./test_bind
strace -o test_all2.strace -f -s100 telnet www.kernel.org 80
