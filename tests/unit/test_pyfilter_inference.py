"""Which protocol a filter file speaks, and the knobs it may set.

Both are read **off the file**, and that is the mechanism the whole model rests on: the
library decides when to call a filter from what its parameters are annotated with, and
`infer_proto` reads the same table back the other way to say what the file is. Nothing
declares a protocol, so nothing can disagree with the code — which is what a `proto`
passed in from outside used to do, refusing an HTTP filter on a TCP service for asking
for an `HttpRequest`, the only thing an HTTP filter does.

None of it had a unit test. It is exercised end to end by the integration suite, which
means a change here surfaces as a filter that silently never runs, on a machine with a
live instance, rather than here.
"""

import pytest

from firegex.pyfilters import collect_pyfilters, pyfilter
from firegex.pyfilters.internals import (compile as fgex_compile, get_code_proto,
                                         get_filter_names, simplest_proto)
from firegex.pyfilters.internals.data import DataStreamCtx
from firegex.pyfilters.internals.models import ExceptionAction, FullStreamAction
from firegex.pyfilters.models import (HttpRequest, RawPacket, TCPClientStream,
                                      TCPInputStream, TCPServerStream, TCPOutputStream,
                                      type_annotations_associations)

HEAD = ("from firegex.pyfilters import pyfilter, ACCEPT\n"
        "from firegex.pyfilters.models import *\n")


def one(annotation: str, name: str = "a") -> str:
    return f"@pyfilter\ndef {name}(x: {annotation}): return ACCEPT\n"


# --- what a file turns out to speak ------------------------------------------


def test_asking_only_for_raw_payloads_makes_a_tcp_filter():
    """"Simplest" is fewest models: a file that only wants bytes is not an HTTP filter
    that happens never to parse."""
    assert get_code_proto(HEAD + one("RawPacket")) == "tcp"
    assert get_code_proto(HEAD + one("TCPInputStream")) == "tcp"


def test_asking_for_a_parsed_message_makes_an_http_filter():
    assert get_code_proto(HEAD + one("HttpRequest")) == "http"
    assert get_code_proto(HEAD + one("GrpcMessage")) == "http", \
        "gRPC is a body format inside HTTP, not a protocol beside it"


def test_one_file_can_hold_both_kinds():
    """`http` provides everything `tcp` does, so a filter that parses HTTP and one that
    reads the raw stream live together — and the file is an HTTP one."""
    code = HEAD + one("RawPacket", "raw") + one("HttpRequest", "parsed")
    assert get_filter_names(code) == ["raw", "parsed"]
    assert get_code_proto(code) == "http"


def test_a_file_with_no_filters_speaks_the_simplest_protocol():
    """It asks for nothing, so nothing is ruled out."""
    assert get_code_proto(HEAD) == simplest_proto() == "tcp"


def test_the_aliases_are_the_same_models():
    """`docs/pyfilter.md` documents both spellings, so both have to be annotatable.

    They are the same class object rather than a second pair, which is why they are in
    the protocol table without being listed in it — and why annotating with one of them
    is not "an annotation no protocol provides".
    """
    assert TCPClientStream is TCPInputStream
    assert TCPServerStream is TCPOutputStream
    assert get_code_proto(HEAD + one("TCPClientStream")) == "tcp"


# --- what a file cannot say --------------------------------------------------


def test_a_parameter_with_no_annotation_is_refused_naming_it():
    """The annotation is what decides when the filter is called, so a bare parameter
    leaves the library with nothing to go on."""
    with pytest.raises(Exception, match="has no type annotation"):
        get_filter_names(HEAD + "@pyfilter\ndef a(x): return ACCEPT\n")


def test_an_annotation_no_model_matches_is_refused_with_the_list():
    """Told what is available, rather than left to guess at a name."""
    with pytest.raises(Exception) as raised:
        get_filter_names(HEAD + one("int"))
    assert "no protocol provides it" in str(raised.value)
    assert "HttpRequest" in str(raised.value), "the message has to name what there is"


def test_two_different_application_protocols_in_one_file_are_refused(monkeypatch):
    """A connection is only ever one of them.

    Unreachable with the table as it stands — `http` provides everything `tcp` does, so
    no pair of real models can conflict — which is exactly why it is pinned here rather
    than left to be discovered broken the day a protocol is added that is not a superset.
    The message has to name **both** functions: told only that a file is inconsistent,
    the operator has to find the pair themselves.
    """
    monkeypatch.setitem(type_annotations_associations, "tcp",
                        {RawPacket: RawPacket._fetch_packet,
                         TCPInputStream: TCPInputStream._fetch_packet})
    monkeypatch.setitem(type_annotations_associations, "http",
                        {RawPacket: RawPacket._fetch_packet,
                         HttpRequest: HttpRequest._fetch_packet})

    with pytest.raises(Exception) as raised:
        get_filter_names(HEAD + one("TCPInputStream", "streamy") + one("HttpRequest", "parsy"))
    said = str(raised.value)
    assert "streamy" in said and "parsy" in said, said
    assert "one application protocol" in said, said


def test_the_shared_model_still_decides_nothing(monkeypatch):
    """With the same split table, a file wanting only `RawPacket` is still ambiguous and
    still resolves to the simplest answer rather than refusing."""
    monkeypatch.setitem(type_annotations_associations, "tcp",
                        {RawPacket: RawPacket._fetch_packet,
                         TCPInputStream: TCPInputStream._fetch_packet})
    monkeypatch.setitem(type_annotations_associations, "http",
                        {RawPacket: RawPacket._fetch_packet,
                         HttpRequest: HttpRequest._fetch_packet})
    assert get_code_proto(HEAD + one("RawPacket")) == "http", \
        "fewest models wins, and with this table that is the two-model one"


# --- the order the file defines them in --------------------------------------


def test_definition_order_is_the_order_they_run_in():
    """The only order a reader of the file can predict.

    What this replaced was a *set* of names, so the order was whatever hashing produced
    — which decided which function got credited with a block.
    """
    code = HEAD + "".join(one("RawPacket", name) for name in ("third", "first", "second"))
    assert get_filter_names(code) == ["third", "first", "second"]


def test_a_function_registered_twice_is_listed_once():
    """`collect_pyfilters` reads module globals, and a decorated function can be bound to
    more than one name."""
    namespace = {}
    exec(HEAD + one("RawPacket", "a") + "b = a\n", namespace, namespace)
    assert collect_pyfilters(namespace) == ["a"]


def test_the_decorator_hands_the_function_back_unwrapped():
    """A wrapper would add a frame to every traceback the operator has to read."""
    def target(x: RawPacket):
        return None

    assert pyfilter(target) is target


# --- the knobs a file may set ------------------------------------------------


def settings_of(extra: str) -> DataStreamCtx:
    code = HEAD + extra + one("RawPacket")
    glob: dict = {}
    exec(code, glob, glob)
    glob["__firegex_pyfilter_enabled"] = ["a"]
    fgex_compile(glob)
    return DataStreamCtx(glob, init_pkt=False)


def test_the_documented_default_stream_cap_is_the_one_in_force():
    """It read `1*8e20` under a comment saying 1MB, so `FGEX_FULL_STREAM_ACTION` never
    fired unless a size was set by hand — and the float it produced would have been
    refused by the setter beside it."""
    assert settings_of("").stream_max_size == 1024 * 1024


def test_a_size_is_taken_from_anything_that_reads_as_one():
    assert settings_of("FGEX_STREAM_MAX_SIZE = 4096\n").stream_max_size == 4096
    assert settings_of("FGEX_STREAM_MAX_SIZE = '8192'\n").stream_max_size == 8192


@pytest.mark.parametrize("value", ["'1MB'", "None", "'big'", "[]"])
def test_a_nonsense_size_is_ignored_rather_than_refused(value):
    """It used to take the whole file down with it.

    `int(value)` raises for a typo, so a file carrying `FGEX_STREAM_MAX_SIZE = "1MB"` did
    not fall back to the default — it failed to load, the operator lost every filter in
    it, and the message named neither the setting nor the file. The other two settings
    ignored a wrong value all along; this one only said it did.
    """
    assert settings_of(f"FGEX_STREAM_MAX_SIZE = {value}\n").stream_max_size == 1024 * 1024


def test_a_size_that_is_not_a_size_is_ignored_too():
    assert settings_of("FGEX_STREAM_MAX_SIZE = -5\n").stream_max_size == 1024 * 1024
    assert settings_of("FGEX_STREAM_MAX_SIZE = 0\n").stream_max_size == 1024 * 1024


def test_the_other_two_knobs_want_their_own_enum():
    assert settings_of("").full_stream_action is FullStreamAction.FLUSH
    assert settings_of("").invalid_encoding_action is ExceptionAction.ACCEPT

    chosen = settings_of("from firegex.pyfilters import FullStreamAction\n"
                         "FGEX_FULL_STREAM_ACTION = FullStreamAction.REJECT\n")
    assert chosen.full_stream_action is FullStreamAction.REJECT


def test_a_knob_set_to_the_wrong_kind_of_thing_is_ignored():
    """`FullStreamAction.FLUSH` is not the string `"flush"`, and a file that says so
    keeps the default rather than failing to load."""
    assert settings_of("FGEX_FULL_STREAM_ACTION = 'flush'\n"
                       ).full_stream_action is FullStreamAction.FLUSH
