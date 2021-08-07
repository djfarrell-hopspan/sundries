#!/bin/bash

HERE=$(dirname ${0})

cd ${HERE}

./utils/timer.sh 1.0 bash ./connie_cmds.sh 2>/dev/null
