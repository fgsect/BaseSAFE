#!/bin/sh

git submodule init
git submodule update
make distrib -C AFLplusplus || exit 1
