#!/bin/bash

HERE=$(dirname ${0})

set -e

source ${HERE}/timerlib.sh

timer_run "${@}"
