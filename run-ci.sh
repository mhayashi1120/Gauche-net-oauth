#!/bin/sh

set -eu

./configure
make check install validate
