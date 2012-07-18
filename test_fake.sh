#!/bin/sh

# Test if we can fake bind a protocol

ulimit -c2000000

export FORCE_BIND_ADDRESS_V4=fake
export FORCE_NET_LOG="test_fake.sh.log"
export FORCE_NET_VERBOSE=1

export LD_PRELOAD="${LD_PRELOAD}:./force_bind.so"

make test_bind
strace -f -s200 -o ${0}.strace ./test_bind 10000
