#!/bin/bash

# usage ./dwarfdump.sh fixed-sized-array/lib.so
# The path is relative to examples

docker run -it -v $PWD:/code -it gcc:12.1 bash -c "apt-get update && apt-get install -y dwarfdump && dwarfdump /code/examples/$1"
