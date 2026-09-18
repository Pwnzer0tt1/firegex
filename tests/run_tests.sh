#!/usr/bin/env bash
#
# One entry point for the whole suite.
#
# It used to be this script that held the shape of the testing: a list of eight
# invocations of one monolithic program with different flags, plus a second script for
# another directory, plus a handful of scripts nothing called at all. The combinations
# are the interesting part of this suite, so they live in the test code as parameters
# now — which is what lets a case this host cannot carry be skipped rather than failed,
# and lets one failure name its own combination instead of ending the run.
#
# What is left here is what a shell script is actually for: install the dependencies,
# wait for the instance to answer, and hand over to pytest. Every argument is passed
# straight through, so anything pytest understands works here:
#
#   ./run_tests.sh                              # everything, against the default instance
#   ./run_tests.sh --set-pass                   # set the password first, as CI does
#   ./run_tests.sh mypassword                   # a different password
#   ./run_tests.sh -k udp                       # just the UDP tests
#   ./run_tests.sh unit                         # the ones needing no instance
#   ./run_tests.sh --layer proxy --no-ipv6 -x   # narrow, and stop at the first failure

set -uo pipefail
cd "$(dirname "$0")"

SET_PASSWORD=0
PASSWORD="${FIREGEX_PASSWORD:-testpassword}"

# The first argument is a password, or `--set-pass`, or neither — anything else is
# pytest's and is passed on untouched.
#
# A bare word is the password **unless it names something to run**. `unit`,
# `integration/test_udp.py` and `integration/test_udp.py::test_one` are all paths this
# directory really has, and every one of them was being taken as a password and shifted
# away — so `./run_tests.sh unit`, which the help above advertises, quietly ran the whole
# suite against an instance whose password it believed was "unit" and answered with
# hundreds of authentication errors. A password that happens to collide with a path goes
# in `FIREGEX_PASSWORD`, which is what that variable is for.
if [[ $# -gt 0 ]]; then
    case "$1" in
        --set-pass) SET_PASSWORD=1; shift ;;
        -*)         ;;
        *)          [[ -e "${1%%::*}" ]] || { PASSWORD="$1"; shift; } ;;
    esac
fi

ADDRESS="${FIREGEX_ADDRESS:-http://127.0.0.1:4444/}"
ADDRESS="${ADDRESS%/}/"

pip3 install -q -r requirements.txt
# The filter library is imported straight out of the source tree, and it carries a C
# extension — the llhttp binding that parses HTTP — which therefore has to be built. An
# editable install builds it in place; without this `unit/` cannot even be collected.
pip3 install -q -e ../fgex-lib

printf 'Waiting for firegex at %s' "$ADDRESS"
until curl --output /dev/null --silent --fail "${ADDRESS}api/status"; do
    printf '.'
    sleep 1
done
echo " up."

if [[ "$SET_PASSWORD" == "1" ]]; then
    curl -X POST "${ADDRESS}api/set-password" -H "Content-Type: application/json" \
         -d "{\"password\": \"$PASSWORD\"}" -s > /dev/null
    echo "Password set."
fi

exec python3 -m pytest --fg-address "$ADDRESS" --fg-password "$PASSWORD" "$@"
