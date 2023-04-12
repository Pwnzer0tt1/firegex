#!/bin/sh
pip3 install -r requirements.txt
echo "Running standard API test"
python3 api_test.py -p testpassword
echo "Running Netfilter Regex TCP ipv4"
python3 nf_test.py -p testpassword -m tcp
echo "Running Netfilter Regex TCP ipv6"
python3 nf_test.py -p testpassword -m tcp -6
echo "Running Netfilter Regex UDP ipv4"
python3 nf_test.py -p testpassword -m udp
echo "Running Netfilter Regex UDP ipv6"
python3 nf_test.py -p testpassword -m udp -6
echo "Running Proxy Regex"
python3 px_test.py -p testpassword
echo "Running Port Hijack TCP ipv4"
python3 ph_test.py -p testpassword -m tcp
echo "Running Port Hijack TCP ipv6"
python3 ph_test.py -p testpassword -m tcp -6
echo "Running Port Hijack UDP ipv4"
python3 ph_test.py -p testpassword -m udp
echo "Running Port Hijack UDP ipv6"
python3 ph_test.py -p testpassword -m udp -6