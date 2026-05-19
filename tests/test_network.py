import asyncio

import pytest
from aiohttp import web

from just_bash import AllowedUrl, Bash, NetworkConfig, RequestTransform


async def make_server(routes):
    app = web.Application()
    for method, path, handler in routes:
        app.router.add_route(method, path, handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    assert site._server is not None
    port = site._server.sockets[0].getsockname()[1]
    return runner, f"http://127.0.0.1:{port}"


@pytest.mark.asyncio
async def test_curl_disabled_by_default_returns_command_not_found():
    bash = Bash()
    result = await bash.exec("curl -s https://example.com")

    assert result.exit_code == 127
    assert "command not found" in result.stderr


@pytest.mark.asyncio
async def test_curl_loads_when_network_configured():
    async def ok(_request):
        return web.Response(text="ok")

    runner, base_url = await make_server([("GET", "/ok", ok)])
    try:
        bash = Bash(network=NetworkConfig(allowed_url_prefixes=[base_url]))
        result = await bash.exec(f"curl -s {base_url}/ok")
    finally:
        await runner.cleanup()

    assert result.exit_code == 0
    assert result.stdout == "ok"


@pytest.mark.asyncio
async def test_curl_blocked_when_url_not_in_prefixes():
    async def ok(_request):
        return web.Response(text="ok")

    runner, base_url = await make_server([("GET", "/ok", ok)])
    try:
        bash = Bash(network=NetworkConfig(allowed_url_prefixes=[f"{base_url}/allowed"]))
        result = await bash.exec(f"curl -sS {base_url}/ok")
    finally:
        await runner.cleanup()

    assert result.exit_code == 7
    assert "Network access denied" in result.stderr


@pytest.mark.asyncio
async def test_curl_blocked_when_method_not_allowed():
    async def ok(_request):
        return web.Response(text="ok")

    runner, base_url = await make_server([("POST", "/ok", ok)])
    try:
        bash = Bash(network=NetworkConfig(allowed_url_prefixes=[base_url]))
        result = await bash.exec(f"curl -sS -X POST {base_url}/ok")
    finally:
        await runner.cleanup()

    assert result.exit_code == 3
    assert "HTTP method" in result.stderr
    assert "not allowed" in result.stderr


@pytest.mark.asyncio
async def test_curl_head_allowed_by_default():
    async def ok(_request):
        return web.Response(text="ok", headers={"x-test": "1"})

    runner, base_url = await make_server([("HEAD", "/ok", ok)])
    try:
        bash = Bash(network=NetworkConfig(allowed_url_prefixes=[base_url]))
        result = await bash.exec(f"curl -I {base_url}/ok")
    finally:
        await runner.cleanup()

    assert result.exit_code == 0
    assert "HTTP/1.1 200" in result.stdout
    assert "x-test: 1" in result.stdout.lower()


@pytest.mark.asyncio
async def test_dangerously_allow_full_internet_access_bypasses_prefixes_and_methods():
    async def ok(_request):
        return web.Response(text="posted")

    runner, base_url = await make_server([("POST", "/ok", ok)])
    try:
        bash = Bash(
            network=NetworkConfig(
                allowed_url_prefixes=[],
                dangerously_allow_full_internet_access=True,
            )
        )
        result = await bash.exec(f"curl -s -X POST {base_url}/ok")
    finally:
        await runner.cleanup()

    assert result.exit_code == 0
    assert result.stdout == "posted"


@pytest.mark.asyncio
async def test_redirect_target_checked_against_allow_list():
    async def redirect(_request):
        raise web.HTTPFound("/final")

    async def final(_request):
        return web.Response(text="final")

    runner, base_url = await make_server(
        [("GET", "/redirect", redirect), ("GET", "/final", final)]
    )
    try:
        bash = Bash(network=NetworkConfig(allowed_url_prefixes=[f"{base_url}/redirect"]))
        result = await bash.exec(f"curl -sS {base_url}/redirect")
    finally:
        await runner.cleanup()

    assert result.exit_code == 47
    assert "Redirect target not in allow-list" in result.stderr


@pytest.mark.asyncio
async def test_max_redirects_honored():
    async def one(_request):
        raise web.HTTPFound("/two")

    async def two(_request):
        raise web.HTTPFound("/final")

    async def final(_request):
        return web.Response(text="final")

    runner, base_url = await make_server(
        [("GET", "/one", one), ("GET", "/two", two), ("GET", "/final", final)]
    )
    try:
        bash = Bash(
            network=NetworkConfig(
                allowed_url_prefixes=[base_url],
                max_redirects=1,
            )
        )
        result = await bash.exec(f"curl -sS {base_url}/one")
    finally:
        await runner.cleanup()

    assert result.exit_code == 47
    assert "Too many redirects" in result.stderr


@pytest.mark.asyncio
async def test_timeout_ms_honored():
    async def slow(_request):
        await asyncio.sleep(0.2)
        return web.Response(text="slow")

    runner, base_url = await make_server([("GET", "/slow", slow)])
    try:
        bash = Bash(
            network=NetworkConfig(
                allowed_url_prefixes=[base_url],
                timeout_ms=10,
            )
        )
        result = await bash.exec(f"curl -sS {base_url}/slow")
    finally:
        await runner.cleanup()

    assert result.exit_code == 28


@pytest.mark.asyncio
async def test_max_response_size_honored():
    async def large(_request):
        return web.Response(body=b"too large")

    runner, base_url = await make_server([("GET", "/large", large)])
    try:
        bash = Bash(
            network=NetworkConfig(
                allowed_url_prefixes=[base_url],
                max_response_size=3,
            )
        )
        result = await bash.exec(f"curl -sS {base_url}/large")
    finally:
        await runner.cleanup()

    assert result.exit_code == 1
    assert "Response body too large" in result.stderr


@pytest.mark.asyncio
async def test_deny_private_ranges_blocks_loopback_even_with_full_access():
    async def ok(_request):
        return web.Response(text="ok")

    runner, base_url = await make_server([("GET", "/ok", ok)])
    try:
        bash = Bash(
            network=NetworkConfig(
                dangerously_allow_full_internet_access=True,
                deny_private_ranges=True,
            )
        )
        result = await bash.exec(f"curl -sS {base_url}/ok")
    finally:
        await runner.cleanup()

    assert result.exit_code == 7
    assert "private/loopback" in result.stderr


@pytest.mark.asyncio
async def test_header_transform_overrides_user_header():
    async def ok(request):
        return web.Response(text=request.headers.get("Authorization", ""))

    runner, base_url = await make_server([("GET", "/ok", ok)])
    try:
        bash = Bash(
            network=NetworkConfig(
                allowed_url_prefixes=[
                    AllowedUrl(
                        url=base_url,
                        transform=[
                            RequestTransform(headers={"Authorization": "Bearer secret"})
                        ],
                    )
                ],
            )
        )
        result = await bash.exec(
            f"curl -s -H 'Authorization: Bearer user' {base_url}/ok"
        )
    finally:
        await runner.cleanup()

    assert result.exit_code == 0
    assert result.stdout == "Bearer secret"


@pytest.mark.asyncio
async def test_curl_writes_bytes_to_sandbox_fs_with_custom_fetch():
    async def fetch(url, _options):
        return {
            "status": 200,
            "statusText": "OK",
            "headers": {"content-type": "application/octet-stream"},
            "body": b"\x00\xffdata",
            "url": url,
        }

    bash = Bash(fetch=fetch)
    result = await bash.exec("curl -s -o out.bin https://example.com/blob")

    assert result.exit_code == 0
    assert await bash.fs.read_file_bytes("/home/user/out.bin") == b"\x00\xffdata"


@pytest.mark.asyncio
async def test_curl_write_out_format_string():
    async def ok(_request):
        return web.Response(text="data", content_type="text/plain")

    runner, base_url = await make_server([("GET", "/ok", ok)])
    try:
        bash = Bash(network=NetworkConfig(allowed_url_prefixes=[base_url]))
        result = await bash.exec(f"curl -s -w '%{{content_type}}|%{{size_download}}' {base_url}/ok")
    finally:
        await runner.cleanup()

    assert result.exit_code == 0
    assert result.stdout.endswith("text/plain; charset=utf-8|4")
