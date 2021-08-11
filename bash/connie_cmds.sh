
HERE=$(dirname ${0})
source ${HERE}/utils/timerlib.sh

echo '*******************conntrack'
echo "time=$(timer_get_uptime)"
conntrack -L -f ipv6 -o extended,timestamp
conntrack -L -f ipv4 -o extended,timestamp
echo '*******************ip'
echo "time=$(timer_get_uptime)"
ip -s addr
echo '*******************arp'
echo "time=$(timer_get_uptime)"
cat /proc/net/arp
echo '*******************neigh'
echo "time=$(timer_get_uptime)"
ip neigh
echo '*******************rejects'
echo "time=$(timer_get_uptime)"
set +e
dmesg -c | grep -i 'reject '
set -e
echo '*******************done'

