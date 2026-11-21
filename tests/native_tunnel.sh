#!/usr/bin/env bash
# Run in a fresh, offline systemd container with the native package installed.
set -eu -o pipefail
systemd-detect-virt --container --quiet
[[ $(id -u) == 0 && $(ls /sys/class/net) == lo ]]
[[ ! -e /etc/vpnctl/policy.json ]]
# Wait until PID 1 can accept jobs even if unrelated units are degraded.
timeout 40 bash -c 'until systemctl show-environment >/dev/null 2>&1; do sleep 1; done'
# The offline fixture supplies its own uplink and does not use DHCP.
systemctl mask --runtime systemd-networkd-wait-online.service
systemctl start network-online.target
systemd-sysusers /usr/lib/sysusers.d/vpnctl.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/vpnctl.conf
useradd -m -G vpnctl tester
install -Dm644 /usr/share/vpnctl/policy.example.json /etc/vpnctl/policy.json
python3 - <<'PY'
from pathlib import Path
import json
p=Path('/etc/vpnctl/policy.json'); cfg=json.loads(p.read_text())
cfg.update(operators=["tester"],policyUser="tester",killSwitch=True,directIPs=[])
p.write_text(json.dumps(cfg))
PY
systemctl start vpnctl-routing.service vpnctl.socket
runuser -u tester -- vpnctl status
ip netns add peer
ip link add uplink type veth peer name end
ip link set end netns peer
ip addr add 192.0.2.10/24 dev uplink
ip link set uplink up
ip route add default via 192.0.2.1 dev uplink
nsenter --net=/run/netns/peer ip addr add 192.0.2.1/24 dev end
nsenter --net=/run/netns/peer ip link set end up
nsenter --net=/run/netns/peer ip link set lo up
umask 077
mkdir /tmp/peer
cd /tmp/peer
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=fixture -keyout ca.key -out ca.crt >/tmp/ca.log 2>&1
for name in server client; do
  openssl req -new -newkey rsa:2048 -nodes -subj /CN=$name -keyout $name.key -out $name.req >/tmp/request.log 2>&1
  printf 'keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=%sAuth\n' "$name" > extensions
  openssl x509 -req -in $name.req -CA ca.crt -CAkey ca.key -CAcreateserial -days 1 -extfile extensions -out $name.crt
done
nsenter --net=/run/netns/peer openvpn --daemon --log /tmp/server.log --local 192.0.2.1 --port 1194 --proto udp --dev tun --server 10.44.0.0 255.255.255.0 --topology subnet --ca ca.crt --cert server.crt --key server.key --dh none --disable-dco
mkdir -p /home/tester/bundle
cp ca.crt client.crt client.key /home/tester/bundle/
cat > /home/tester/bundle/peer.ovpn <<'PROFILE'
client
remote 192.0.2.1 1194
dev tun
ca ca.crt
cert client.crt
key client.key
nobind
PROFILE
chown -R tester: /home/tester/bundle
cd /
runuser -u tester -- vpnctl import /home/tester/bundle
if ! runuser -u tester -- vpnctl connect peer; then
  journalctl -u vpnctl-tunnel --no-pager -n 40
  tail -20 /tmp/server.log
  exit 1
fi
mkdir -p /tmp/vpnctl-http
echo vpnctl-ok >/tmp/vpnctl-http/check
nsenter --net=/run/netns/peer python3 -m http.server 8080 --directory /tmp/vpnctl-http >/tmp/http.log 2>&1 &
for attempt in {1..10}; do
  if reply=$(runuser -u tester -- curl -fsS --noproxy '*' --max-time 3 http://10.44.0.1:8080/check); then
    break
  fi
  sleep 1
done
[[ ${reply:-} == vpnctl-ok ]]
runuser -u tester -- vpnctl disconnect
systemctl stop vpnctl.socket vpnctl-routing.service
