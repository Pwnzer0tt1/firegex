#!/usr/bin/env bash

cd "$(dirname "$0")"

TMP=$1
if [[ "$TMP" == "--set-pass" ]]; then
    PASSWORD="testpassword"
else
    PASSWORD=${TMP:-testpassword}
fi
ERROR=0

# Where the instance under test is. CI starts it on the default port; an env var so a
# local instance on another port can be tested without editing this file, and without
# every script below growing its own way of being told.
ADDRESS=${FIREGEX_ADDRESS:-http://127.0.0.1:4444/}
ADDRESS=${ADDRESS%/}/

pip3 install -r requirements.txt

until curl --output /dev/null --silent --fail "${ADDRESS}api/status"; do
    printf '.'
    sleep 1
done
if [[ "$TMP" == "--set-pass" ]]; then
    curl -X POST "${ADDRESS}api/set-password" -H "Content-Type: application/json" -d "{\"password\": \"$PASSWORD\"}" -s
    echo ""
fi

# Needs no running instance, only libhs — but a broken match library would make every
# service test below fail in a way that is much harder to read, so it goes first.
echo "Running the firegex.regex library test"
python3 regex_lib_test.py || ERROR=1
# The library's own behaviour, with no instance and no libhs: the HTTP models, and the
# knobs a filter file is documented to be able to set.
echo "Running the firegex.pyfilters library tests"
python3 -m pytest -q test_http_history.py || ERROR=1
echo "Running standard API test"
python3 api_test.py -p $PASSWORD -a $ADDRESS || ERROR=1

# The two network layers, exercised with the same filters. Running both is the point:
# a filter that only works on one of them is the failure this whole model exists to
# make impossible.
echo "Running Services on the proxy layer, ipv4"
python3 services_test.py -p $PASSWORD -a $ADDRESS -t proxy || ERROR=1
echo "Running Services on the proxy layer, ipv6"
python3 services_test.py -p $PASSWORD -a $ADDRESS -t proxy -6 || ERROR=1
echo "Running Services on the NFQUEUE layer, ipv4"
python3 services_test.py -p $PASSWORD -a $ADDRESS -t nfqueue || ERROR=1
echo "Running Services on the NFQUEUE layer, ipv6"
python3 services_test.py -p $PASSWORD -a $ADDRESS -t nfqueue -6 || ERROR=1
# Only the proxy layer: decrypting means terminating the connection, which is what that
# layer does. The NFQUEUE run used to exist because nginx terminated in front of it.
echo "Running Services behind TLS, proxy layer"
python3 services_test.py -p $PASSWORD -a $ADDRESS -t proxy --tls || ERROR=1
echo "Running Services behind TLS, proxy layer, ipv6"
python3 services_test.py -p $PASSWORD -a $ADDRESS -t proxy --tls -6 || ERROR=1
echo "Running Services handing off to an external proxy"
python3 services_test.py -p $PASSWORD -a $ADDRESS -t external || ERROR=1
echo "Running Services handing off to an external proxy, ipv6"
python3 services_test.py -p $PASSWORD -a $ADDRESS -t external -6 || ERROR=1


exit $ERROR

