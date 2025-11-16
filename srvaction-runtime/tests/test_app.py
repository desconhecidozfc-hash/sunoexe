import shutil
import time

import pytest
from fastapi.testclient import TestClient

from app.main import MANUS_PAGES_DIR, SANDBOX_ROOT, SESSIONS_ROOT, app, sanitize_path

client = TestClient(app)


def clear_fs():
    client.post("/apiclearfs")
    if SESSIONS_ROOT.exists():
        for child in SESSIONS_ROOT.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    if MANUS_PAGES_DIR.exists():
        for child in MANUS_PAGES_DIR.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()


@pytest.fixture(autouse=True)
def sandbox_isolated():
    clear_fs()
    yield
    clear_fs()


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["data"]["status"] == "ok"


def test_sanitize_path_rejects_traversal():
    with pytest.raises(ValueError):
        sanitize_path("../outside.txt")


def test_traversal_attack_blocked():
    response = client.post("/apifileread", json={"file": "../etc/passwd"})
    body = response.json()
    assert body["success"] is False
    assert "path" in body["error"].lower()


def test_file_write_creates_directories_and_applies_newlines():
    response = client.post(
        "/apifilewrite",
        json={
            "file": "nested/dir/file.txt",
            "content": "payload",
            "leading_newline": True,
            "trailing_newline": True,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True

    target = SANDBOX_ROOT / "nested/dir/file.txt"
    assert target.read_text(encoding="utf-8") == "\npayload\n"


def test_multiline_read_slice():
    target = SANDBOX_ROOT / "sample.txt"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("one\ntwo\nthree\nfour\n", encoding="utf-8")

    response = client.post(
        "/apifileread",
        json={"file": "sample.txt", "start_line": 2, "end_line": 3},
    )
    body = response.json()
    assert body["success"] is True
    assert body["data"]["content"] == "two\nthree"


def test_regex_timeout(monkeypatch):
    target = SANDBOX_ROOT / "regex.txt"
    target.write_text("a" * 10, encoding="utf-8")

    from app import main as main_module

    def slow_collect(pattern, content):
        time.sleep(3)
        return []

    monkeypatch.setattr(main_module, "_collect_regex_matches", slow_collect)

    response = client.post(
        "/apifilefind_in_content",
        json={"file": "regex.txt", "pattern": "a+"},
    )
    body = response.json()
    assert body["success"] is False
    assert "timed out" in body["error"]


def test_shell_exec_and_wait_returns_logs():
    session_id = "shellbasic"
    response = client.post(
        "/api/shell/exec",
        json={"id": session_id, "exec_dir": ".", "command": "echo first && echo second"},
    )
    assert response.status_code == 200
    assert response.json()["success"] is True

    wait_response = client.post(
        "/api/shell/wait", json={"id": session_id, "timeout": 5}
    ).json()
    assert wait_response["success"] is True
    assert "first" in wait_response["data"]["output"]
    assert "second" in wait_response["data"]["output"]
    assert wait_response["data"]["running"] is False


def test_shell_write_supports_interactive_commands():
    session_id = "shellwrite"
    command = "python3 -c \"import sys; print(sys.stdin.readline().strip())\""
    exec_resp = client.post(
        "/api/shell/exec",
        json={"id": session_id, "exec_dir": ".", "command": command},
    )
    assert exec_resp.json()["success"] is True

    write_resp = client.post(
        "/api/shell/write",
        json={"id": session_id, "data": "hello world", "press_enter": True},
    ).json()
    assert write_resp["success"] is True

    wait_data = client.post("/api/shell/wait", json={"id": session_id}).json()
    assert wait_data["data"]["running"] is False
    assert "hello world" in wait_data["data"]["output"]


def test_shell_kill_terminates_and_cleans_session():
    session_id = "shellkill"
    exec_resp = client.post(
        "/api/shell/exec", json={"id": session_id, "exec_dir": ".", "command": "sleep 30"}
    ).json()
    assert exec_resp["success"] is True
    session_path = SESSIONS_ROOT / session_id
    assert session_path.exists()

    kill_resp = client.post("/api/shell/kill", json={"id": session_id}).json()
    assert kill_resp["success"] is True

    # Allow cleanup to propagate
    time.sleep(0.5)
    assert not session_path.exists()


def test_shell_rejects_disallowed_commands():
    response = client.post(
        "/api/shell/exec", json={"id": "badcmd", "exec_dir": ".", "command": "sudo ls"}
    ).json()
    assert response["success"] is False
    assert "disallowed" in response["error"]


def test_shell_rejects_outside_exec_dir():
    response = client.post(
        "/api/shell/exec",
        json={"id": "badpath", "exec_dir": "../outside", "command": "echo hi"},
    ).json()
    assert response["success"] is False
    assert "exec_dir" in response["error"].lower()


def test_make_manus_page_generates_html():
    mdx_path = SANDBOX_ROOT / "docs/sample.mdx"
    mdx_path.parent.mkdir(parents=True, exist_ok=True)
    mdx_path.write_text("# Title\nBody text", encoding="utf-8")

    response = client.post(
        "/api/make_manus_page",
        json={"mdx_file": "docs/sample.mdx", "title": "Sample Page"},
    ).json()

    assert response["success"] is True
    output = MANUS_PAGES_DIR / "sample.html"
    assert output.exists()
    content = output.read_text(encoding="utf-8")
    assert "Sample Page" in content


def test_message_notify_endpoint():
    response = client.post("/api/message/notify", json={"message": "Hello"}).json()
    assert response["success"] is True
    assert response["data"]["message"] == "Hello"


def test_info_search_requires_api_key(monkeypatch):
    monkeypatch.delenv("BING_API_KEY", raising=False)
    response = client.post("/api/info/search_web", json={"query": "fastapi"}).json()
    assert response["success"] is False
    assert "BING_API_KEY" in response["error"]


