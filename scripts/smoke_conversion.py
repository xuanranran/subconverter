"""Check real HTTP conversion using synthetic nodes, without real subscriptions."""

import argparse
import base64
import json
import urllib.parse
import urllib.request


def convert(endpoint, target, link, **options):
    parameters = {
        "target": target,
        "url": link,
        "list": "true",
        "new_name": "true",
        "insert": "false",
        "emoji": "false",
    }
    parameters.update(options)
    query = urllib.parse.urlencode(parameters)
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

    # SOCKS accepts both v2rayN userinfo and the legacy whole-address encoding.
    for label, encoded in [
        ("userinfo", base64.b64encode(b"test-user:test:password").decode() + "@example.com:1080"),
        ("legacy", base64.b64encode(b"test-user:test:password@example.com:1080").decode()),
    ]:
        config = json.loads(convert(args.endpoint, "singbox", f"socks://{encoded}#smoke-socks"))
        nodes = [node for node in config["outbounds"] if node.get("type") == "socks"]
        assert len(nodes) == 1, config
        assert nodes[0]["server"] == "example.com" and nodes[0]["server_port"] == 1080, nodes[0]
        assert nodes[0]["username"] == "test-user" and nodes[0]["password"] == "test:password", nodes[0]
        print(f"PASS SOCKS {label}: authentication and address")

    # Shadowrocket VLESS aliases must retain the decoded WS path, Host and TLS SNI.
    link = ("vless://11111111-1111-4111-8111-111111111111@example.com:443"
            "?tls=1&obfs=websocket&obfsParam=ws.example.com&path=%2Ftest%3Fkey%3Dvalue"
            "&sni=tls.example.com#smoke-vless-ws")
    config = json.loads(convert(args.endpoint, "singbox", link))
    node = next(node for node in config["outbounds"] if node.get("type") == "vless")
    assert node["tls"]["enabled"] is True and node["tls"]["server_name"] == "tls.example.com", node
    assert node["transport"]["type"] == "ws" and node["transport"]["path"] == "/test?key=value", node
    assert node["transport"]["headers"]["Host"] == "ws.example.com", node
    fallback = json.loads(convert(args.endpoint, "singbox", link.replace("&sni=tls.example.com", "")))
    fallback_node = next(node for node in fallback["outbounds"] if node.get("type") == "vless")
    assert fallback_node["tls"]["server_name"] == "ws.example.com", fallback_node
    surge = convert(args.endpoint, "surge", link)
    assert "smoke-vless-ws" in surge and "vless," in surge and "ws-path=/test?key=value" in surge, surge
    assert "Host:ws.example.com" in surge and "sni=tls.example.com" in surge, surge
    mixed = cases[0][1] + "|" + link
    surge5 = convert(args.endpoint, "surge", mixed, ver="5")
    assert "smoke-ss" in surge5 and "smoke-vless-ws" not in surge5, surge5
    print("PASS VLESS: Shadowrocket aliases, decoded WS fields, Surge 6 default and explicit Surge 5")

    snell = ("proxies:\n  - name: smoke-snell\n    type: snell\n    server: example.com\n"
             "    port: 443\n    psk: test-password\n    version: 6\n    mode: unshaped\n"
             "    userkey: test-userkey\n    udp: true\n    obfs-opts: {mode: tls, host: obfs.example.com}\n")
    data_url = "data:text/plain;base64," + base64.b64encode(snell.encode()).decode()
    clash = convert(args.endpoint, "clash", data_url)
    for expected in ["smoke-snell", "version: 6", "mode: unshaped", "userkey: test-userkey", "udp: true"]:
        assert expected in clash, clash
    assert "obfs-opts" not in clash, clash
    surge = convert(args.endpoint, "surge", data_url)
    for expected in ["smoke-snell", "version=6", "mode=unshaped"]:
        assert expected in surge, surge
    assert "obfs=tls" not in surge, surge
    print("PASS Snell 6: mode/userkey/UDP preserved and obsolete simple-obfs omitted")


if __name__ == "__main__":
    main()
