"""Check real HTTP conversion using synthetic nodes, without real subscriptions."""

import argparse
import base64
import json
import urllib.parse
import urllib.request


def convert(endpoint, target, link):
    query = urllib.parse.urlencode({
        "target": target,
        "url": link,
        "list": "true",
        "new_name": "true",
        "insert": "false",
        "emoji": "false",
    })
    request = urllib.request.Request(
        endpoint.rstrip("/") + "/sub?" + query,
        headers={"User-Agent": "subconverter/v0.9.0"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return response.read().decode("utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("endpoint", help="Example: http://127.0.0.1:12550")
    args = parser.parse_args()
    credentials = base64.b64encode(b"aes-256-gcm:test-password").decode().rstrip("=")
    cases = [
        ("ss", f"ss://{credentials}@example.com:12345#smoke-ss"),
        ("vless", "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&sni=example.com&type=ws&path=%2Ftest#smoke-vless"),
        ("anytls", "anytls://test-password@example.com:443?sni=example.com#smoke-anytls"),
    ]
    for protocol, link in cases:
        clash = convert(args.endpoint, "clash", link)
        assert f"smoke-{protocol}" in clash, (protocol, clash[:300])
        assert protocol in clash, (protocol, clash[:300])
        assert "example.com" in clash, (protocol, clash[:300])
        singbox = json.loads(convert(args.endpoint, "singbox", link))
        expected_type = "shadowsocks" if protocol == "ss" else protocol
        nodes = [node for node in singbox.get("outbounds", []) if node.get("type") == expected_type]
        assert len(nodes) == 1, (protocol, singbox)
        assert nodes[0]["server"] == "example.com", nodes[0]
        assert nodes[0]["server_port"] == (12345 if protocol == "ss" else 443), nodes[0]
        print(f"PASS {protocol}: Clash and sing-box")


if __name__ == "__main__":
    main()
