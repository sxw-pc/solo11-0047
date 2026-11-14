from __future__ import annotations

import http.client
import json
import re
import threading

import pytest

from slowquery_autopsy.server.app import build_server
from slowquery_autopsy.store.ledger import open_readonly

EXTERNAL = re.compile(r"https?://|//cdn|@import|url\(", re.I)


def _request(port: int, path: str, method: str = "GET", body: bytes | None = None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(method, path, body=body)
        response = conn.getresponse()
        return response.status, response.read().decode("utf-8"), response.headers
    finally:
        conn.close()


def test_loopback_server_routes_and_read_only(ledger_result):
    config, result = ledger_result
    with open_readonly(config.ledger_path) as ledger:
        cluster_id = ledger.list_clusters(result.batch_id)[0]["cluster_id"]
        finding_id = ledger.list_findings(result.batch_id)[0]["finding_id"]
        query_id = ledger.list_queries(result.batch_id)[0]["query_id"]
    server = build_server(config.ledger_path, port=0)
    assert server.server_address[0] == "127.0.0.1"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        status, body, headers = _request(port, "/healthz")
        assert status == 200
        assert json.loads(body)["readonly"] is True
        assert "default-src 'none'" in headers["Content-Security-Policy"]
        paths = [
            "/", f"/batch/{result.batch_id}", f"/batch/{result.batch_id}/clusters",
            f"/batch/{result.batch_id}/findings",
            f"/cluster/{result.batch_id}/{cluster_id}",
            f"/finding/{result.batch_id}/{finding_id}",
            f"/query/{result.batch_id}/{query_id}",
        ]
        for path in paths:
            status, body, _ = _request(port, path)
            assert status == 200 and result.batch_id in body
            assert EXTERNAL.search(body) is None
        status, body, _ = _request(port, "/missing")
        assert status == 404 and "未知路径" in body
        status, _, _ = _request(port, "/", method="POST", body=b"x")
        assert status == 405
        status, body, _ = _request(port, "/healthz", method="HEAD")
        assert status == 200 and body == ""
    finally:
        server.shutdown()
        server.server_close()


def test_server_rejects_non_loopback_bind(ledger_result):
    config, _ = ledger_result
    with pytest.raises(ValueError):
        build_server(config.ledger_path, host="0.0.0.0", port=0)
