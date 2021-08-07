#!/bin/bash

HERE=$(dirname ${0})

source ${HERE}/timerlib.sh

timer_run "${@}"
