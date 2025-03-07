#!/usr/bin/env bash

cd "$(dirname "$0")"

TMP=$1
PASSWORD=${TMP:=testpassword}
ERROR=0

pip3 install -r requirements.txt

echo "Running standard API test"
python3 api_test.py -p $PASSWORD || ERROR=1
echo "Running Netfilter Regex TCP ipv4"
python3 nf_test.py -p $PASSWORD -m tcp || ERROR=1
echo "Running Netfilter Regex TCP ipv6"
python3 nf_test.py -p $PASSWORD -m tcp -6 || ERROR=1
echo "Running Netfilter Regex UDP ipv4"
python3 nf_test.py -p $PASSWORD -m udp || ERROR=1
echo "Running Netfilter Regex UDP ipv6"
python3 nf_test.py -p $PASSWORD -m udp -6 || ERROR=1
echo "Running Port Hijack TCP ipv4"
python3 ph_test.py -p $PASSWORD -m tcp || ERROR=1
echo "Running Port Hijack TCP ipv6"
python3 ph_test.py -p $PASSWORD -m tcp -6 || ERROR=1
echo "Running Port Hijack UDP ipv4"
python3 ph_test.py -p $PASSWORD -m udp || ERROR=1
echo "Running Port Hijack UDP ipv6"
python3 ph_test.py -p $PASSWORD -m udp -6 || ERROR=1

if [[ "$ERROR" == "0" ]] then
	python3 benchmark.py -p $PASSWORD -r 5 -d 1 -s 10 || ERROR=1
fi

exit $ERROR

