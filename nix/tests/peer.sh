# Invoked only inside the disposable NixOS test VM.
set -euo pipefail
umask 077
mkdir -p /tmp/vpntest
cd /tmp/vpntest
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=test-ca -keyout ca.key -out ca.crt
for name in server client; do
  openssl req -new -newkey rsa:2048 -nodes -subj /CN=$name -keyout $name.key -out $name.req
  printf 'keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=%sAuth\n' "$name" > extensions
  echo "subjectAltName=IP:10.44.0.1,IP:192.0.2.2" >> extensions
  openssl x509 -req -in $name.req -CA ca.crt -CAkey ca.key -CAcreateserial -days 1 -extfile extensions -out $name.crt
done
ip -n peer link set lo up
ip netns exec peer openvpn --daemon --log /tmp/server.log --local 192.0.2.1 --port 1194 --proto udp --dev tun --server 10.44.0.0 255.255.255.0 --topology subnet --ca ca.crt --cert server.crt --key server.key --dh none --disable-dco
ip netns exec peer dnsmasq --bind-dynamic --listen-address=10.44.0.1,192.0.2.1 --address=/vpn-endpoint.test/192.0.2.1 --no-resolv --local-ttl=4 --address=/direct.test/192.0.2.2 --pid-file=/tmp/test-dns.pid
mkdir -p /home/tester/bundle
cp ca.crt client.crt client.key /home/tester/bundle/
cat > /home/tester/bundle/first.ovpn <<'PROFILE'
client
remote vpn-endpoint.test 1194
dev tun
ca ca.crt
cert client.crt
key client.key
nobind
ping 2
ping-restart 10
PROFILE
cp /home/tester/bundle/{first,second}.ovpn
sed 's/1194/1195/' /home/tester/bundle/first.ovpn > /home/tester/bundle/broken.ovpn
chown -R tester:users /home/tester/bundle
ip netns exec peer python3 /etc/http-peer.py </dev/null >/tmp/http-peer.log 2>&1 &
mkdir -p /home/tester/.config/vpnctl
cat >/home/tester/.config/vpnctl/settings.json <<'JSON'
{"diagnostics":{"downloadUrl":"https://10.44.0.1:8443/down","uploadUrl":"https://10.44.0.1:8443/up","publicIPUrl":"https://10.44.0.1:8443/ip"}}
JSON
chown -R tester:users /home/tester/.config
