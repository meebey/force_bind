#!/bin/sh

# Test bandwidth limiting when both bw options are provided

ulimit -c2000000

export FORCE_NET_BW="1000"
export FORCE_NET_BW_PER_SOCKET="1000" # this should fail

export LD_PRELOAD="${LD_PRELOAD}:./force_bind.so"

time strace -f -s200 -o test_bw2.strace ./send_udp 123 3000
