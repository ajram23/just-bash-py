# Orbit fork of just-bash

This repository is a fork of [dbreunig/just-bash-py](https://github.com/dbreunig/just-bash-py),
pinned to tag `v0.1.16`, carrying the network/curl wiring that upstream
shipped as inert plumbing.

## What's changed vs. upstream v0.1.16

**`Bash(network=NetworkConfig(...))` now actually enables a working
pure-Python `curl`.** Upstream defined `NetworkConfig` and
`CommandContext.fetch` but never wired them through `Bash`, `Interpreter`,
or the `curl` command, so passing `network=...` was a no-op.

Wired in `src/just_bash/network/__init__.py`,
`src/just_bash/bash.py`, `src/just_bash/commands/curl/curl.py`, and
`src/just_bash/interpreter/interpreter.py`:

- aiohttp-backed default fetch built from `NetworkConfig`
- `curl` is registered only when `network` or `fetch` is configured
- URL allow-list with origin + path-prefix matching (segment-boundary,
  not raw `startsWith`)
- Allowed-methods enforcement; manual redirect handling with per-hop
  allow-list re-check; `max_redirects`, `timeout_ms`, `max_response_size`
- `deny_private_ranges` with lexical IPv4/IPv6 checks + DNS-resolution
  recheck, DNS-pinned `aiohttp.TCPConnector` to defeat rebinding between
  preflight and connection
- Header transforms (`RequestTransform`) applied at the fetch boundary
  so credentials never enter the sandbox
- Byte-preserving response body for `curl -o` writes

**TS-parity allow-list / private-range hardening** (ported from
`vercel-labs/just-bash` `src/network/allow-list.ts`):

- Fail-fast `validateAllowList` from `make_default_fetch` unless
  `dangerously_allow_full_internet_access=True`: rejects malformed
  entries, missing scheme/host, non-http(s) schemes, query strings
  and fragments, and ambiguous path separators (`\`, `%2f`, `%5c`)
- Origin matching normalized like TS `URL.origin`: lowercase
  scheme/host, strip default ports (`:80`, `:443`), exact non-default
  ports
- Explicit IPv4 private-range table including CGNAT `100.64.0.0/10`
  (which `ipaddress.IPv4Address.is_private` misses in 3.11),
  benchmarking `198.18.0.0/15`, IETF/TEST-NET, and reserved `240/4`
- Lexical IPv4 parser accepting `2130706433` and `0x7f.0.0.1` style
  numeric forms (`socket.getaddrinfo` catches them at resolve time
  but the lexical pass needs parity)
- Explicit IPv6 checks: `::`, `::1`, `fe80::/10`, `fc00::/7`,
  `::ffff:` IPv4-mapped, `2001:db8::/32`, NAT64 `64:ff9b::/96`,
  NAT64-local `64:ff9b:1::/48`, 6to4 `2002::/16` with embedded-v4
  recheck
- Defensive `Content-Length` parsing (malformed → ignored, rely on
  streamed body-size enforcement instead of bubbling `ValueError`)

Tests: `tests/test_network.py` (covers allow-list validation,
matching, methods, redirects, timeout, response size, private ranges,
content-length, header transforms, byte-preserving body).

## Orbit tag

`v0.1.16.post1` — first stable release of the network/curl wiring +
TS-parity hardening. Named as a PEP 440 post-release of upstream
`0.1.16` so `pip install` from the Git URL resolves to a version
distinguishable from PyPI's `just-bash==0.1.16` (which is still the
inert-network release).

```
just-bash @ git+https://github.com/ajram23/just-bash-py@v0.1.16.post1
```

## When to retire this fork

Delete the fork and switch back to upstream PyPI `just-bash` once
[dbreunig/just-bash-py](https://github.com/dbreunig/just-bash-py)
releases a version that wires `NetworkConfig` through `Bash` and
ships the TS-parity allow-list / private-range checks.
