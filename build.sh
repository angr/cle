#!/bin/bash

docker run -it -v $PWD:/code -it gcc:12.1 bash -c "cd /code && make"
