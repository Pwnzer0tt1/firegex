#!/usr/bin/env bash

cd "$(dirname "$0")"

TMP=$1
if [[ "$TMP" == "--set-pass" ]]; then
    PASSWORD="testpassword"
else
    PASSWORD=${TMP:-testpassword}
fi
ERROR=0

pip3 install -r requirements.txt

until curl --output /dev/null --silent --fail http://127.0.0.1:4444/api/status; do
    printf '.'
    sleep 1
done
if [[ "$TMP" == "--set-pass" ]]; then
    curl -X POST http://127.0.0.1:4444/api/set-password -H "Content-Type: application/json" -d "{\"password\": \"$PASSWORD\"}" -s
    echo ""
fi

echo "Running standard API test"
python3 api_test.py -p $PASSWORD || ERROR=1
echo "Running TLS Decrypt stream CRUD/edit/cascade test"
python3 tls_test.py -p $PASSWORD || ERROR=1
echo "Running TLS Decrypt stream CRUD/edit/cascade test ipv6"
python3 tls_test.py -p $PASSWORD -6 || ERROR=1
echo "Running Netfilter Regex TCP ipv4"
python3 nfregex_test.py -p $PASSWORD -m tcp || ERROR=1
echo "Running Netfilter Regex TCP ipv6"
python3 nfregex_test.py -p $PASSWORD -m tcp -6 || ERROR=1
echo "Running Netfilter Regex UDP ipv4"
python3 nfregex_test.py -p $PASSWORD -m udp || ERROR=1
echo "Running Netfilter Regex UDP ipv6"
python3 nfregex_test.py -p $PASSWORD -m udp -6 || ERROR=1
echo "Running Port Hijack TCP ipv4"
python3 ph_test.py -p $PASSWORD -m tcp || ERROR=1
echo "Running Port Hijack TCP ipv6"
python3 ph_test.py -p $PASSWORD -m tcp -6 || ERROR=1
echo "Running Port Hijack UDP ipv4"
python3 ph_test.py -p $PASSWORD -m udp || ERROR=1
echo "Running Port Hijack UDP ipv6"
python3 ph_test.py -p $PASSWORD -m udp -6 || ERROR=1
echo "Running Netfilter Proxy ipv4"
python3 nfproxy_test.py -p $PASSWORD || ERROR=1
echo "Running Netfilter Proxy ipv6"
python3 nfproxy_test.py -p $PASSWORD -6 || ERROR=1
echo "Running Netfilter Proxy ipv4 TLS"
python3 nfproxy_test.py -p $PASSWORD --tls || ERROR=1
echo "Running Netfilter Proxy ipv6 TLS"
python3 nfproxy_test.py -p $PASSWORD -6 --tls || ERROR=1

echo "Running Netfilter Regex TCP ipv4 TLS"
python3 nfregex_test.py -p $PASSWORD -m tcp --tls || ERROR=1
echo "Running Netfilter Regex TCP ipv6 TLS"
python3 nfregex_test.py -p $PASSWORD -m tcp -6 --tls || ERROR=1

exit $ERROR

