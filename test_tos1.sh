#!/bin/sh

export FORCE_NET_TOS="0xff"

export LD_PRELOAD="${LD_PRELOAD}:./force_bind.so"

exec ./test_bind "$@"
