# Where the code in this directory comes from

Two separate works live here, under two separate MIT notices, and the difference
matters when either is updated.

## `lib/` — llhttp, upstream and unmodified

* Version: **9.4.3**
* Source: <https://github.com/nodejs/llhttp>, tag `release/v9.4.3` (30 July 2026)
* Tarball: `https://github.com/nodejs/llhttp/archive/refs/tags/release/v9.4.3.tar.gz`
  (`sha256:1eb813c7437b31a87496a1cd3ed79f00746720f5e7e29c79b42c02cb69f36c39`)
* Licence: MIT, © Fedor Indutny and contributors — `lib/LICENSE.llhttp`

Four files, copied verbatim from that tag, and nothing in them has been edited:

| here | upstream | sha256 |
|---|---|---|
| `lib/llhttp.h` | `include/llhttp.h` | `5bc82fa51b19aa8bee7d921038393fbfc74e8cc9bae0844c2d82c102fb8cfd68` |
| `lib/llhttp.c` | `src/llhttp.c`     | `391e7c99912abf3b1c9dd8a9c85fdeaac2663e9fa55b6f3871154d16fef8b892` |
| `lib/api.c`    | `src/api.c`        | `0f8590206fe2f264db2825401b5fb856b979ee1363dc88b06f36dc9577afb941` |
| `lib/http.c`   | `src/http.c`       | `a1f2b23168f8e9b5bfa464c89027d3ca259fc649ae3d7e72bfff997d1aeb5d72` |

`llhttp.c` is *generated* upstream, from the TypeScript that describes the state
machine; the `release/*` tags are the branch where that output is committed, which is
why these can be taken as source without a Node toolchain. There is no `api.h`: the
public header is one file and already carries what that used to declare. It was here
until 9.4.3, included by nothing.

### Updating

Replace those four files from the new tag, update the table above, rebuild, and run
`pytest unit/test_http_parsing.py` from `tests/`. The binding needs no change for a
minor release: `parser_settings` is built with designated initialisers, so a callback
added upstream (`on_protocol_complete` arrived in 9.3.0) stays NULL, and the error list
is generated from `HTTP_ERRNO_MAP`, so new codes bring their own exceptions along.

What does need looking at is the other direction: each release changes what the parser
*accepts*. Going from 9.2.1 to 9.4.3, an empty `Transfer-Encoding` stopped being
accepted and tabs around `Content-Length` started being. Both are pinned in
`tests/unit/test_http_parsing.py` — a change there is a decision about what filters see,
not a test to fix.

## `llhttp_module.c` — the Python binding, ours

Derived from [pyllhttp](https://github.com/domysh/pyllhttp) (itself a fork of Derrick
Lyndon Pallas' `pyllhttp`, now archived), and modified. Licence: MIT —
`LICENSE.pyllhttp`.

What differs from that fork, which is what to re-apply if anything is ever taken from it
again:

* It is built as `firegex._llhttp` and declares `Py_MOD_PER_INTERPRETER_GIL_SUPPORTED`,
  which is what lets it load in the subinterpreters `cpproxy` runs filters in — the
  reason none of the alternatives with prebuilt wheels can be used.
* **Nothing here reaches for `pyllhttp` any more.** The types and the exception classes
  carry this module's name, and the error path looks the class up in this module through
  `sys.modules`, so each interpreter finds the classes it built. It used to
  `PyImport_ImportModule("pyllhttp")` on every parse error: that package is not a
  dependency and is installed on no machine the wheel is, so the import failed, printed
  its traceback to stderr — the service log, on a filter — and returned *without setting
  an exception*, which CPython reports as `SystemError: ... returned NULL without setting
  an exception`. A malformed request said that instead of naming the parse error. Pinned
  by `tests/unit/test_llhttp_binding.py`, which takes `pyllhttp` away before asking, and
  by `wheel_smoke.py`, which `cibuildwheel` runs where it was never there.
* The exception class names are derived into a local buffer instead of being `malloc`ed
  once onto a process-global table and never freed — that table is shared by every
  interpreter, which is not somewhere a module claiming per-interpreter support may
  write.
