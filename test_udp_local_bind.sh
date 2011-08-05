#!/bin/sh

# Test if we can alter source IP

ulimit -c2000000

export FORCE_BIND_ADDRESS_V4=127.0.0.2
export FORCE_NET_VERBOSE=1

export LD_PRELOAD="${LD_PRELOAD}:./force_bind.so"

make send_udp
strace -f -s200 -o ${0}.strace ./send_udp 123 8000
