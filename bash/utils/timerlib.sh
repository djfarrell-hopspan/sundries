

function timer_get_uptime() {
	head -n 1 /proc/uptime | awk '{ print $1 }'
}

function timer_bc_diff() {
	local x="${1}"
	local y="${2}"

	echo "${x} - ${y}" | bc -l
}

function timer_do_sleep_to_boundary() {
	local NOW=$(timer_get_uptime)
	local BOUNDARY=${1}
	local SLEEP=$(echo "(${BOUNDARY} - (${NOW} % ${BOUNDARY}))" | bc -s)

	sleep "${SLEEP}s"
	echo "slept: ${SLEEP}s" 1>&2
}

function timer_run_one() {
	BOUNDARY=${1}
	shift
	CMD="${@}"

	timer_do_sleep_to_boundary "${BOUNDARY}"
	echo "timer: running: '${CMD}'" 1>&2
	$CMD
	echo "timer: ... finished running: '${CMD}'" 1>&2
}

function timer_run() {
	PREV=$(timer_get_uptime)
	while true
	do
		THIS=$(timer_get_uptime)
		timer_run_one "${@}"
		echo "timer: since prev loop: $(timer_bc_diff ${THIS} ${PREV})s" 1>&2
		PREV=${THIS}
	done
}
