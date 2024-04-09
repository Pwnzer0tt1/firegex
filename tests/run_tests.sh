#!/bin/sh

cd "$(dirname "$0")"

TMP=$1
PASSWORD=${TMP:=testpassword}

pip3 install -r requirements.txt

echo "Running standard API test"
python3 api_test.py -p $PASSWORD
echo "Running Netfilter Regex TCP ipv4"
python3 nf_test.py -p $PASSWORD -m tcp
echo "Running Netfilter Regex TCP ipv6"
python3 nf_test.py -p $PASSWORD -m tcp -6
echo "Running Netfilter Regex UDP ipv4"
python3 nf_test.py -p $PASSWORD -m udp
echo "Running Netfilter Regex UDP ipv6"
python3 nf_test.py -p $PASSWORD -m udp -6
echo "Running Proxy Regex"
python3 px_test.py -p $PASSWORD
echo "Running Port Hijack TCP ipv4"
python3 ph_test.py -p $PASSWORD -m tcp
echo "Running Port Hijack TCP ipv6"
python3 ph_test.py -p $PASSWORD -m tcp -6
echo "Running Port Hijack UDP ipv4"
python3 ph_test.py -p $PASSWORD -m udp
echo "Running Port Hijack UDP ipv6"
python3 ph_test.py -p $PASSWORD -m udp -6

