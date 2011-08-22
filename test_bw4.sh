#!/bin/sh

# Test setting priority and clasification in prio qdisc

ulimit -c2000000

export FORCE_NET_VERBOSE=1

export LD_PRELOAD="${LD_PRELOAD}:./force_bind.so"

# 6 = Interactive (band 0)
export FORCE_NET_PRIO=6
strace -o ${0}.band0 ./send_udp 123 3000 &

# 0 = best effors (band 1)
export FORCE_NET_PRIO=0
strace -o ${0}.band1 ./send_udp 123 3000 &

# 2 = bulk (band 2)
export FORCE_NET_PRIO=2
strace -o ${0}.band2 ./send_udp 123 3000 &

wait
