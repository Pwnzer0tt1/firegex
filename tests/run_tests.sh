#!/usr/bin/env bash

cd "$(dirname "$0")"

TMP=$1
PASSWORD=${TMP:=testpassword}
ERROR=0

pip3 install -r requirements.txt

until curl --output /dev/null --silent --fail http://localhost:4444/api/status; do
    printf '.'
    sleep 1
done

echo "Running standard API test"
python3 api_test.py -p $PASSWORD || ERROR=1
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

exit $ERROR

