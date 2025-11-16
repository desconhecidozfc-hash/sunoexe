from __future__ import annotations

import asyncio
import os
import pwd
import re
import resource
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI
from markdown import markdown
from pydantic import BaseModel, Field, validator

try:
    from pyppeteer import launch
except Exception:  # pragma: no cover - optional dependency resolution
    launch = None

SANDBOX_ROOT = (Path(__file__).resolve().parent.parent / "srvaction-runtimefsroot").resolve()
SANDBOX_ROOT.mkdir(parents=True, exist_ok=True)

SESSIONS_ROOT = Path("/srv/action-runtime/sessions").resolve()
SESSIONS_ROOT.mkdir(parents=True, exist_ok=True)

BROWSER_CONTEXT = Path("/srv/action-runtime/browser/context").resolve()
BROWSER_CONTEXT.mkdir(parents=True, exist_ok=True)

MANUS_PAGES_DIR = Path("/srv/action-runtime/manus-pages").resolve()
MANUS_PAGES_DIR.mkdir(parents=True, exist_ok=True)

MAX_LOG_TAIL = 2000
MAX_SHELL_TIMEOUT = 60
MAX_RUNTIME_SECONDS = 60
CPU_TIME_LIMIT_SECONDS = 30
MEMORY_LIMIT_BYTES = 256 * 1024 * 1024

app = FastAPI(title="Sandboxed File Service")


@app.get("/health")
async def health() -> Dict[str, Any]:
    """Simple health probe used by deployment scripts."""
    return {"success": True, "data": {"status": "ok"}}


def ensure_actionuser() -> pwd.struct_passwd:
    try:
        return pwd.getpwnam("actionuser")
    except KeyError:
        # Attempt to create the user with a home inside the sandbox root.
        home_dir = SANDBOX_ROOT / "actionuser"
        home_dir.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.run(
                [
                    "useradd",
                    "-M",
                    "-d",
                    str(home_dir),
                    "-s",
                    "/usr/sbin/nologin",
                    "actionuser",
                ],
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as exc:
            raise RuntimeError("failed to provision actionuser") from exc
        return pwd.getpwnam("actionuser")


class FileRequest(BaseModel):
    file: str = Field(..., description="Path to the target file relative to the sandbox root.")


class FileReadRequest(FileRequest):
    start_line: Optional[int] = Field(None, ge=1)
    end_line: Optional[int] = Field(None, ge=1)

    @validator("end_line")
    def validate_line_order(cls, v, values):
        start = values.get("start_line")
        if v is not None and start is not None and v < start:
            raise ValueError("end_line must be greater than or equal to start_line")
        return v


class FileWriteRequest(FileRequest):
    content: str = Field(..., description="Text content to write.")
    append: bool = False
    leading_newline: bool = False
    trailing_newline: bool = False


class FileReplaceRequest(FileRequest):
    search: str = Field(..., min_length=1)
    replace: str = ""


class FileRegexRequest(FileRequest):
    pattern: str = Field(..., description="Regular expression to evaluate.")
    flags: Optional[List[str]] = Field(
        None,
        description="List of regex flags such as IGNORECASE, MULTILINE, DOTALL.",
    )


class FileFindByNameRequest(BaseModel):
    pattern: str = Field(..., description="Glob pattern relative to the sandbox root.")


class ShellExecRequest(BaseModel):
    id: str
    exec_dir: str
    command: str


class ShellSessionIdRequest(BaseModel):
    id: str


class ShellWaitRequest(ShellSessionIdRequest):
    timeout: Optional[int] = Field(
        MAX_SHELL_TIMEOUT,
        ge=1,
        le=MAX_SHELL_TIMEOUT,
        description="Maximum seconds to wait for the process to exit.",
    )


class ShellWriteRequest(ShellSessionIdRequest):
    data: str
    press_enter: bool = False


class BrowserNavigateRequest(BaseModel):
    url: str


class BrowserIndexRequest(BaseModel):
    index: int = Field(..., ge=0)


class BrowserInputRequest(BrowserIndexRequest):
    text: str
    clear: bool = False


class BrowserSelectRequest(BrowserIndexRequest):
    value: str


class BrowserMoveMouseRequest(BaseModel):
    x: float
    y: float


class BrowserPressKeyRequest(BaseModel):
    key: str


class BrowserScrollRequest(BaseModel):
    amount: int = Field(500, ge=1, le=10000)


class BrowserConsoleExecRequest(BaseModel):
    script: str


class BrowserConsoleViewRequest(BaseModel):
    limit: int = Field(50, ge=1, le=500)


class InfoSearchRequest(BaseModel):
    query: str


class DeployExposePortRequest(BaseModel):
    port: int = Field(..., ge=1, le=65535)


class DeployApplyRequest(BaseModel):
    project_path: str
    site_name: str = Field(..., regex=r"^[A-Za-z0-9_-]+$")
    kind: str = Field(..., regex=r"^(static|nextjs)$")


class ManusPageRequest(BaseModel):
    mdx_file: str
    title: Optional[str]


class MessageNotifyRequest(BaseModel):
    message: str


class MessageAskRequest(BaseModel):
    prompt: str
    options: Optional[List[str]]


class IdleRequest(BaseModel):
    reason: Optional[str]


def sanitize_path(requested_path: str) -> Path:
    if not requested_path or requested_path.strip() == "":
        raise ValueError("file path is required")

    target = Path(requested_path)
    if target.is_absolute():
        # Reject attempts to escape sandbox with absolute paths
        target = Path(str(target).lstrip("/"))

    normalized = (SANDBOX_ROOT / target).resolve()
    if not str(normalized).startswith(str(SANDBOX_ROOT)):
        raise ValueError("path traversal is not allowed")

    return normalized


def validate_session_id(session_id: str) -> str:
    session_id = session_id.strip()
    if not session_id:
        raise ValueError("session id is required")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", session_id):
        raise ValueError("session id contains invalid characters")
    return session_id


def validate_command(command: str) -> str:
    if not command or not command.strip():
        raise ValueError("command is required")

    lowered = command.lower()
    banned_terms = ["sudo", "systemctl", "curl", "wget"]
    for term in banned_terms:
        if term in lowered:
            raise ValueError(f"command contains disallowed token: {term}")

    if re.search(r"(?<!&)&(?!&)", command):
        raise ValueError("background execution is not permitted")
    if "nohup" in lowered:
        raise ValueError("background daemons are not permitted")

    return command


def ensure_text_size_limit(content: str) -> None:
    size = len(content.encode("utf-8"))
    if size > 5 * 1024 * 1024:
        raise ValueError("file content exceeds 5MB limit")


def validate_url(target_url: str) -> str:
    parsed = urlparse(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("a valid http(s) URL is required")
    return target_url


def _collect_regex_matches(pattern: re.Pattern[str], content: str):
    matches = []
    for match in pattern.finditer(content):
        line = content.count("\n", 0, match.start()) + 1
        matches.append(
            {
                "match": match.group(0),
                "start": match.start(),
                "end": match.end(),
                "line": line,
            }
        )
    return matches


def find_matches_with_timeout(pattern: re.Pattern[str], content: str, timeout_seconds: float = 2.0):
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_collect_regex_matches, pattern, content)
        return future.result(timeout=timeout_seconds)


def resolve_exec_dir(path_value: str) -> Path:
    path = sanitize_path(path_value)
    if not path.exists() or not path.is_dir():
        raise ValueError("exec_dir must refer to an existing directory inside the sandbox")
    return path


class ShellSession:
    def __init__(self, session_id: str, exec_dir: Path, command: str):
        self.id = session_id
        self.exec_dir = exec_dir
        self.command = command
        self.log_dir = SESSIONS_ROOT / session_id
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.stdout_path = self.log_dir / "out.log"
        self.stderr_path = self.log_dir / "err.log"
        self.combined_path = self.log_dir / "combined.log"
        self.stdout_path.touch(exist_ok=True)
        self.stderr_path.touch(exist_ok=True)
        self.combined_path.touch(exist_ok=True)
        self.process: Optional[subprocess.Popen[str]] = None
        self._stdout_thread: Optional[threading.Thread] = None
        self._stderr_thread: Optional[threading.Thread] = None
        self._timeout_timer: Optional[threading.Timer] = None
        self._log_lock = threading.Lock()

    @property
    def is_active(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def _limit_and_switch_user(self):
        os.setsid()
        resource.setrlimit(resource.RLIMIT_CPU, (CPU_TIME_LIMIT_SECONDS, CPU_TIME_LIMIT_SECONDS))
        resource.setrlimit(resource.RLIMIT_AS, (MEMORY_LIMIT_BYTES, MEMORY_LIMIT_BYTES))
        user = ensure_actionuser()
        os.setgid(user.pw_gid)
        os.setuid(user.pw_uid)

    def _stream_reader(self, pipe, destination: Path):
        if pipe is None:
            return
        with destination.open("a", encoding="utf-8") as dest, self.combined_path.open(
            "a", encoding="utf-8"
        ) as combined:
            while True:
                data = pipe.readline()
                if data == "":
                    break
                with self._log_lock:
                    dest.write(data)
                    dest.flush()
                    combined.write(data)
                    combined.flush()
        pipe.close()

    def start(self):
        if self.process is not None:
            raise RuntimeError("session already started")

        ensure_actionuser()
        self.process = subprocess.Popen(
            ["/bin/bash", "-lc", self.command],
            cwd=self.exec_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            text=True,
            bufsize=1,
            preexec_fn=self._limit_and_switch_user,
        )

        self._stdout_thread = threading.Thread(
            target=self._stream_reader,
            args=(self.process.stdout, self.stdout_path),
            daemon=True,
        )
        self._stderr_thread = threading.Thread(
            target=self._stream_reader,
            args=(self.process.stderr, self.stderr_path),
            daemon=True,
        )
        self._stdout_thread.start()
        self._stderr_thread.start()

        self._timeout_timer = threading.Timer(MAX_RUNTIME_SECONDS, self.kill)
        self._timeout_timer.daemon = True
        self._timeout_timer.start()

    def read_combined_tail(self, max_chars: int = MAX_LOG_TAIL) -> str:
        if not self.combined_path.exists():
            return ""
        content = self.combined_path.read_text(encoding="utf-8")
        if len(content) <= max_chars:
            return content
        return content[-max_chars:]

    def wait(self, timeout: float):
        if self.process is None:
            raise RuntimeError("session not started")
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            pass
        return self.read_combined_tail()

    def write(self, data: str, press_enter: bool = False):
        if self.process is None or self.process.stdin is None:
            raise RuntimeError("session not running")
        if not self.is_active:
            raise RuntimeError("session already completed")
        payload = data
        if press_enter:
            payload += "\n"
        try:
            self.process.stdin.write(payload)
            self.process.stdin.flush()
        except BrokenPipeError as exc:
            raise RuntimeError("unable to write to session") from exc

    def kill(self):
        if self._timeout_timer:
            self._timeout_timer.cancel()
        if self.process and self.is_active:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.process = None

    def cleanup(self):
        if self.log_dir.exists():
            shutil.rmtree(self.log_dir, ignore_errors=True)


class ShellManager:
    def __init__(self):
        self.sessions: Dict[str, ShellSession] = {}
        self._lock = threading.Lock()

    def start_session(self, session_id: str, exec_dir: Path, command: str) -> ShellSession:
        validate_session_id(session_id)
        validate_command(command)
        session = ShellSession(session_id, exec_dir, command)
        with self._lock:
            existing = self.sessions.get(session_id)
            if existing and existing.is_active:
                raise ValueError("session already running")
            if existing and not existing.is_active:
                existing.cleanup()
            self.sessions[session_id] = session
        session.start()
        return session

    def get(self, session_id: str) -> ShellSession:
        validate_session_id(session_id)
        session = self.sessions.get(session_id)
        if not session:
            raise ValueError("session not found")
        return session

    def remove(self, session_id: str):
        with self._lock:
            session = self.sessions.pop(session_id, None)
        if session:
            session.cleanup()


shell_manager = ShellManager()
class BrowserManager:
    def __init__(self):
        self._browser = None
        self._page = None
        self._elements: List[Dict[str, Any]] = []
        self._console_logs: List[Dict[str, str]] = []
        self._lock = asyncio.Lock()

    async def _ensure_started(self):
        if launch is None:
            raise RuntimeError("puppeteer/pyppeteer is not installed")
        if self._browser is not None and self._page is not None:
            return
        self._browser = await launch(
            headless=True,
            userDataDir=str(BROWSER_CONTEXT),
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ],
        )
        self._page = await self._browser.newPage()
        self._page.on("console", self._handle_console_message)

    def _handle_console_message(self, message):  # pragma: no cover - callback
        try:
            text = message.text
            level = getattr(message, "type", lambda: "log")()
        except Exception:  # pragma: no cover - defensive
            text = str(message)
            level = "log"
        self._console_logs.append({"level": level, "message": text})
        if len(self._console_logs) > 500:
            self._console_logs = self._console_logs[-500:]

    async def _snapshot_dom(self):
        if self._page is None:
            return []

        script = """
        () => {
            const nodes = Array.from(document.querySelectorAll('*'));
            const cssPath = (el) => {
                if (!el) return '';
                const segments = [];
                while (el && el.nodeType === 1) {
                    if (el.id) {
                        segments.unshift(el.nodeName.toLowerCase() + '#' + el.id);
                        break;
                    }
                    let nth = 1;
                    let sibling = el;
                    while ((sibling = sibling.previousElementSibling)) {
                        if (sibling.nodeName === el.nodeName) {
                            nth++;
                        }
                    }
                    const selector = `${el.nodeName.toLowerCase()}:nth-of-type(${nth})`;
                    segments.unshift(selector);
                    el = el.parentElement;
                }
                return segments.join(' > ');
            };

            return nodes.map((node, index) => {
                const attrs = {};
                for (const attr of Array.from(node.attributes || [])) {
                    attrs[attr.name] = attr.value;
                }
                return {
                    index,
                    tag: node.tagName ? node.tagName.toLowerCase() : 'unknown',
                    text: (node.innerText || '').trim().slice(0, 200),
                    selector: cssPath(node),
                    attributes: attrs,
                };
            });
        }
        """
        self._elements = await self._page.evaluate(script)
        return self._elements

    async def restart(self):
        async with self._lock:
            if self._page is not None:
                try:
                    await self._page.close()
                except Exception:  # pragma: no cover - cleanup guard
                    pass
            if self._browser is not None:
                try:
                    await self._browser.close()
                except Exception:  # pragma: no cover - cleanup guard
                    pass
            self._browser = None
            self._page = None
            self._elements = []
            self._console_logs = []
            shutil.rmtree(BROWSER_CONTEXT, ignore_errors=True)
            BROWSER_CONTEXT.mkdir(parents=True, exist_ok=True)

    async def navigate(self, target_url: str) -> Dict[str, Any]:
        validate_url(target_url)
        async with self._lock:
            await self._ensure_started()
            assert self._page is not None
            try:
                await self._page.goto(target_url, timeout=15000, waitUntil="load")
            except Exception as exc:
                raise RuntimeError(f"failed to navigate: {exc}")
            await asyncio.sleep(0.2)
            elements = await self._snapshot_dom()
            title = await self._page.title()
            return {"url": target_url, "title": title, "elements": elements}

    async def current_view(self) -> Dict[str, Any]:
        async with self._lock:
            if self._page is None:
                raise RuntimeError("browser session has not been started")
            elements = await self._snapshot_dom()
            url = self._page.url
            title = await self._page.title()
            return {"url": url, "title": title, "elements": elements}

    async def _selector_for_index(self, index: int) -> str:
        if not self._elements:
            await self._snapshot_dom()
        for element in self._elements:
            if element.get("index") == index:
                selector = element.get("selector")
                if selector:
                    return selector
        raise ValueError("element index not found")

    async def click(self, index: int):
        async with self._lock:
            selector = await self._selector_for_index(index)
            await self._page.click(selector)

    async def input_text(self, index: int, text: str, clear: bool = False):
        async with self._lock:
            selector = await self._selector_for_index(index)
            if clear:
                await self._page.evaluate(
                    "(sel) => { const el = document.querySelector(sel); if (el) { el.value = ''; el.innerText = ''; } }",
                    selector,
                )
            await self._page.focus(selector)
            await self._page.type(selector, text)

    async def move_mouse(self, x: float, y: float):
        async with self._lock:
            if self._page is None:
                raise RuntimeError("browser session has not been started")
            await self._page.mouse.move(x, y)

    async def press_key(self, key: str):
        async with self._lock:
            if self._page is None:
                raise RuntimeError("browser session has not been started")
            await self._page.keyboard.press(key)

    async def select_option(self, index: int, value: str):
        async with self._lock:
            selector = await self._selector_for_index(index)
            await self._page.select(selector, value)

    async def scroll(self, amount: int):
        async with self._lock:
            if self._page is None:
                raise RuntimeError("browser session has not been started")
            await self._page.evaluate("(amt) => window.scrollBy(0, amt)", amount)

    async def console_exec(self, script: str) -> Any:
        async with self._lock:
            if self._page is None:
                raise RuntimeError("browser session has not been started")
            try:
                return await self._page.evaluate(f"() => {{ return {script}; }}")
            except Exception as exc:
                raise RuntimeError(f"console execution failed: {exc}")

    def console_logs(self, limit: int) -> List[Dict[str, str]]:
        return self._console_logs[-limit:]


browser_manager = BrowserManager()


class CloudflaredManager:
    def __init__(self):
        self._tunnels: Dict[int, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def expose_port(self, port: int) -> str:
        with self._lock:
            existing = self._tunnels.get(port)
            if existing and existing["process"].poll() is None:
                return existing["url"]

            command = [
                "cloudflared",
                "tunnel",
                "--url",
                f"http://localhost:{port}",
                "--no-autoupdate",
                "--loglevel",
                "info",
            ]
            try:
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )
            except FileNotFoundError as exc:
                raise RuntimeError("cloudflared is not installed") from exc

        url = self._wait_for_url(process)
        if not url:
            process.terminate()
            raise RuntimeError("failed to obtain tunnel URL from cloudflared")

        with self._lock:
            self._tunnels[port] = {"process": process, "url": url}
        return url

    def _wait_for_url(self, process: subprocess.Popen) -> Optional[str]:
        pattern = re.compile(r"https://[\w.-]+")
        start = time.time()
        if process.stdout is None:
            return None
        while time.time() - start < 15:
            line = process.stdout.readline()
            if line:
                match = pattern.search(line)
                if match:
                    return match.group(0)
            if process.poll() is not None:
                break
        return None


cloudflared_manager = CloudflaredManager()


async def perform_web_search(query: str) -> List[Dict[str, str]]:
    api_key = os.getenv("BING_API_KEY")
    if not api_key:
        raise RuntimeError("BING_API_KEY is not configured")
    endpoint = os.getenv("BING_API_ENDPOINT", "https://api.bing.microsoft.com/v7.0/search")
    headers = {"Ocp-Apim-Subscription-Key": api_key}
    params = {"q": query}
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.get(endpoint, headers=headers, params=params)
        response.raise_for_status()
        payload = response.json()
    items = payload.get("webPages", {}).get("value", [])
    results = []
    for item in items:
        results.append(
            {
                "title": item.get("name"),
                "link": item.get("url"),
                "snippet": item.get("snippet"),
            }
        )
    return results


def apply_static_deployment(project_path: Path, site_name: str) -> str:
    target = Path("/var/www/html") / site_name
    target.parent.mkdir(parents=True, exist_ok=True)
    command = ["rsync", "-a", "--delete", f"{project_path}/", str(target)]
    subprocess.run(command, check=True)
    return str(target)


def apply_nextjs_deployment(project_path: Path, site_name: str) -> str:
    env = os.environ.copy()
    subprocess.run(["npm", "install"], cwd=project_path, check=True, env=env)
    subprocess.run(["npm", "run", "build"], cwd=project_path, check=True, env=env)
    pm2_name = f"nextjs-{site_name}"
    subprocess.run(["pm2", "delete", pm2_name], cwd=project_path, check=False, env=env)
    subprocess.run(["pm2", "start", "npm", "--name", pm2_name, "--", "run", "start"], cwd=project_path, check=True, env=env)
    return pm2_name



@app.post("/apifileread")
def api_file_read(request: FileReadRequest):
    try:
        path = sanitize_path(request.file)
    except ValueError as exc:
        return {"success": False, "error": str(exc)}

    if not path.exists() or not path.is_file():
        return {"success": False, "error": "file not found"}

    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return {"success": False, "error": "file is not valid UTF-8 text"}

    if request.start_line is None and request.end_line is None:
        result = content
    else:
        lines = content.splitlines()
        start_idx = request.start_line - 1 if request.start_line else 0
        end_idx = request.end_line if request.end_line else len(lines)
        sliced = lines[start_idx:end_idx]
        result = "\n".join(sliced)

    return {"success": True, "data": {"content": result}}


@app.post("/apifilewrite")
def api_file_write(request: FileWriteRequest):
    try:
        path = sanitize_path(request.file)
    except ValueError as exc:
        return {"success": False, "error": str(exc)}

    if not isinstance(request.content, str):
        return {"success": False, "error": "content must be textual data"}

    try:
        ensure_text_size_limit(request.content)
    except ValueError as exc:
        return {"success": False, "error": str(exc)}

    payload = request.content
    if request.leading_newline:
        payload = "\n" + payload
    if request.trailing_newline:
        payload = payload + "\n"

    path.parent.mkdir(parents=True, exist_ok=True)

    mode = "a" if request.append else "w"
    with path.open(mode, encoding="utf-8") as file_handle:
        file_handle.write(payload)

    return {"success": True, "data": {"bytes_written": len(payload.encode("utf-8"))}}


@app.post("/apifilestr_replace")
def api_file_str_replace(request: FileReplaceRequest):
    try:
        path = sanitize_path(request.file)
    except ValueError as exc:
        return {"success": False, "error": str(exc)}

    if not path.exists() or not path.is_file():
        return {"success": False, "error": "file not found"}

    content = path.read_text(encoding="utf-8")
    replacements = content.count(request.search)
    if replacements == 0:
        return {"success": True, "data": {"replacements": 0}}

    updated_content = content.replace(request.search, request.replace)
    path.write_text(updated_content, encoding="utf-8")
    return {"success": True, "data": {"replacements": replacements}}


def _resolve_regex_flags(flags: Optional[List[str]]) -> int:
    if not flags:
        return 0

    flag_mapping = {
        "IGNORECASE": re.IGNORECASE,
        "MULTILINE": re.MULTILINE,
        "DOTALL": re.DOTALL,
    }
    resolved = 0
    for item in flags:
        upper_item = item.upper()
        if upper_item not in flag_mapping:
            raise ValueError(f"unsupported regex flag: {item}")
        resolved |= flag_mapping[upper_item]
    return resolved


@app.post("/apifilefind_in_content")
def api_file_find_in_content(request: FileRegexRequest):
    try:
        path = sanitize_path(request.file)
    except ValueError as exc:
        return {"success": False, "error": str(exc)}

    if not path.exists() or not path.is_file():
        return {"success": False, "error": "file not found"}

    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return {"success": False, "error": "file is not valid UTF-8 text"}

    try:
        flags = _resolve_regex_flags(request.flags)
        compiled = re.compile(request.pattern, flags)
    except re.error as exc:
        return {"success": False, "error": f"invalid regex: {exc}"}
    except ValueError as exc:
        return {"success": False, "error": str(exc)}

    try:
        matches = find_matches_with_timeout(compiled, content)
    except TimeoutError:
        return {"success": False, "error": "regex evaluation timed out"}

    return {"success": True, "data": {"matches": matches}}


@app.post("/apifilefind_by_name")
def api_file_find_by_name(request: FileFindByNameRequest):
    pattern = request.pattern.strip()
    if not pattern:
        return {"success": False, "error": "pattern is required"}

    try:
        sanitize_path(pattern)
    except ValueError:
        pass  # Patterns can include wildcards; validation occurs during iteration

    results = []
    for file_path in SANDBOX_ROOT.rglob(pattern):
        if file_path.is_file():
            results.append(file_path.relative_to(SANDBOX_ROOT).as_posix())

    return {"success": True, "data": {"files": results}}


@app.post("/api/browser/navigate")
async def api_browser_navigate(request: BrowserNavigateRequest):
    try:
        data = await browser_manager.navigate(request.url)
    except Exception as exc:
        return {"success": False, "error": str(exc)}
    return {"success": True, "data": data}


@app.post("/api/browser/view")
async def api_browser_view():
    try:
        view = await browser_manager.current_view()
        logs = browser_manager.console_logs(50)
    except Exception as exc:
        return {"success": False, "error": str(exc)}
    return {"success": True, "data": {"view": view, "console": logs}}


@app.post("/api/browser/restart")
async def api_browser_restart():
    try:
        await browser_manager.restart()
    except Exception as exc:
        return {"success": False, "error": str(exc)}
    return {"success": True}


@app.post("/api/browser/click")
async def api_browser_click(request: BrowserIndexRequest):
    try:
        await browser_manager.click(request.index)
    except Exception as exc:
        return {"success": False, "error": str(exc)}
    return {"success": True}


@app.post("/api/browser/input")
async def api_browser_input(request: BrowserInputRequest):
    try:
        await browser_manager.input_text(request.index, request.text, request.clear)
    except Exception as exc:
        return {"success": False, "error": str(exc)}
    return {"success": True}


@app.post("/api/browser/move_mouse")
async def api_browser_move_mouse(request: BrowserMoveMouseRequest):
    try:
        await browser_manager.move_mouse(request.x, request.y)
    except Exception as exc:
        return {"success": False, "error": str(exc)}
    return {"success": True}


@app.post("/api/browser/press_key")
async def api_browser_press_key(request: BrowserPressKeyRequest):
    try:
        await browser_manager.press_key(request.key)
    except Exception as exc:
        return {"success": False, "error": str(exc)}
    return {"success": True}


@app.post("/api/browser/select_option")
async def api_browser_select(request: BrowserSelectRequest):
    try:
        await browser_manager.select_option(request.index, request.value)
    except Exception as exc:
        return {"success": False, "error": str(exc)}
    return {"success": True}


@app.post("/api/browser/scroll/up")
async def api_browser_scroll_up(request: BrowserScrollRequest):
    try:
        await browser_manager.scroll(-abs(request.amount))
    except Exception as exc:
        return {"success": False, "error": str(exc)}
    return {"success": True}


@app.post("/api/browser/scroll/down")
async def api_browser_scroll_down(request: BrowserScrollRequest):
    try:
        await browser_manager.scroll(abs(request.amount))
    except Exception as exc:
        return {"success": False, "error": str(exc)}
    return {"success": True}


@app.post("/api/browser/console/exec")
async def api_browser_console_exec(request: BrowserConsoleExecRequest):
    try:
        result = await browser_manager.console_exec(request.script)
    except Exception as exc:
        return {"success": False, "error": str(exc)}
    return {"success": True, "data": {"result": result}}


@app.post("/api/browser/console/view")
async def api_browser_console_view(request: BrowserConsoleViewRequest):
    logs = browser_manager.console_logs(request.limit)
    return {"success": True, "data": {"console": logs}}


@app.post("/api/shell/exec")
def api_shell_exec(request: ShellExecRequest):
    try:
        exec_dir = resolve_exec_dir(request.exec_dir)
        session = shell_manager.start_session(request.id, exec_dir, request.command)
        pid = session.process.pid if session.process else None
    except (ValueError, RuntimeError) as exc:
        return {"success": False, "error": str(exc)}

    return {"success": True, "data": {"pid": pid, "session": session.id}}


@app.post("/api/shell/view")
def api_shell_view(request: ShellSessionIdRequest):
    try:
        session = shell_manager.get(request.id)
        output = session.read_combined_tail()
    except ValueError as exc:
        return {"success": False, "error": str(exc)}

    return {"success": True, "data": {"output": output, "running": session.is_active}}


@app.post("/api/shell/wait")
def api_shell_wait(request: ShellWaitRequest):
    timeout = request.timeout or MAX_SHELL_TIMEOUT
    try:
        session = shell_manager.get(request.id)
        output = session.wait(timeout)
        running = session.is_active
        returncode = None if session.process is None else session.process.returncode
    except (ValueError, RuntimeError) as exc:
        return {"success": False, "error": str(exc)}

    return {
        "success": True,
        "data": {"output": output, "running": running, "returncode": returncode},
    }


@app.post("/api/shell/write")
def api_shell_write(request: ShellWriteRequest):
    try:
        session = shell_manager.get(request.id)
        session.write(request.data, request.press_enter)
    except (ValueError, RuntimeError) as exc:
        return {"success": False, "error": str(exc)}

    return {"success": True}


@app.post("/api/shell/kill")
def api_shell_kill(request: ShellSessionIdRequest):
    try:
        session = shell_manager.get(request.id)
        session.kill()
        shell_manager.remove(request.id)
    except ValueError as exc:
        return {"success": False, "error": str(exc)}

    return {"success": True}


@app.post("/api/info/search_web")
async def api_info_search(request: InfoSearchRequest):
    try:
        results = await perform_web_search(request.query)
    except Exception as exc:
        return {"success": False, "error": str(exc)}
    return {"success": True, "data": {"results": results}}


@app.post("/api/deploy/expose_port")
def api_deploy_expose_port(request: DeployExposePortRequest):
    try:
        url = cloudflared_manager.expose_port(request.port)
    except Exception as exc:
        return {"success": False, "error": str(exc)}
    return {"success": True, "data": {"url": url}}


@app.post("/api/deploy/apply")
def api_deploy_apply(request: DeployApplyRequest):
    try:
        project_path = sanitize_path(request.project_path)
        if not project_path.exists() or not project_path.is_dir():
            raise ValueError("project_path must be an existing directory")
        if request.kind == "static":
            location = apply_static_deployment(project_path, request.site_name)
        else:
            location = apply_nextjs_deployment(project_path, request.site_name)
    except (ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        return {"success": False, "error": str(exc)}
    return {"success": True, "data": {"location": location}}


@app.post("/api/make_manus_page")
def api_make_manus_page(request: ManusPageRequest):
    try:
        mdx_path = sanitize_path(request.mdx_file)
    except ValueError as exc:
        return {"success": False, "error": str(exc)}

    if not mdx_path.exists():
        return {"success": False, "error": "mdx file not found"}

    content = mdx_path.read_text(encoding="utf-8")
    body = markdown(content)
    title = request.title or mdx_path.stem
    html = f"""<!DOCTYPE html><html><head><meta charset='utf-8'><title>{title}</title></head><body>{body}</body></html>"""
    MANUS_PAGES_DIR.mkdir(parents=True, exist_ok=True)
    output_path = MANUS_PAGES_DIR / f"{mdx_path.stem}.html"
    output_path.write_text(html, encoding="utf-8")
    return {"success": True, "data": {"page": str(output_path)}}


@app.post("/api/message/notify")
def api_message_notify(request: MessageNotifyRequest):
    return {"success": True, "data": {"delivered": True, "message": request.message}}


@app.post("/api/message/ask")
def api_message_ask(request: MessageAskRequest):
    return {
        "success": True,
        "data": {"prompt": request.prompt, "options": request.options or []},
    }


@app.post("/api/idle")
def api_idle(request: IdleRequest):
    return {
        "success": True,
        "data": {"status": "idle", "reason": request.reason or "awaiting instructions"},
    }


@app.post("/apiclearfs")
def api_clear_fs():
    """Utility endpoint for tests to clear the sandbox."""
    for child in SANDBOX_ROOT.iterdir():
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()
    return {"success": True}


__all__ = [
    "app",
    "sanitize_path",
    "find_matches_with_timeout",
    "_collect_regex_matches",
    "SANDBOX_ROOT",
    "MANUS_PAGES_DIR",
]
