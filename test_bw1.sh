#!/bin/sh

# Test bandwidth limiting

ulimit -c2000000

export FORCE_NET_BW=1000

export LD_PRELOAD="${LD_PRELOAD}:./force_bind.so"

time strace -f -s200 -o test_bw1.strace ./send_udp 123 3000
