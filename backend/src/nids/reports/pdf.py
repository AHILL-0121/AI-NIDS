"""Print an HTML file to PDF with a headless Chromium-based browser (Edge, Chrome, Chromium).

Why a browser: it renders the same HTML the user can open, handles any Unicode text with system
fonts, and needs no extra Python dependency or native libraries (WeasyPrint needs GTK/Pango, which
is painful on Windows). Edge ships with Windows; Linux images install Chromium.

The browser gets a throwaway profile, no network (every hostname resolves to nothing) and a
timeout. The report itself contains no scripts and its CSP blocks every external fetch.
"""

import contextlib
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path


class PdfError(RuntimeError):
    pass


_POSIX_NAMES = (
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "microsoft-edge",
    "microsoft-edge-stable",
)
_MAC_APPS = (
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
)


def _windows_candidates() -> list[Path]:
    roots = [
        os.environ.get("PROGRAMFILES(X86)"),  # Windows environment names ignore case
        os.environ.get("PROGRAMFILES"),
        os.environ.get("LOCALAPPDATA"),
    ]
    tails = ("Microsoft/Edge/Application/msedge.exe", "Google/Chrome/Application/chrome.exe")
    return [Path(root) / tail for root in roots if root for tail in tails]


def find_browser(configured: str | None = None) -> Path | None:
    """The configured browser if it exists, else the first one found on this machine."""
    if configured:
        path = Path(configured)
        return path if path.is_file() else None
    if sys.platform == "win32":
        candidates = _windows_candidates()
    elif sys.platform == "darwin":
        candidates = [Path(p) for p in _MAC_APPS]
    else:
        candidates = [Path(found) for name in _POSIX_NAMES if (found := shutil.which(name))]
    return next((c for c in candidates if c.is_file()), None)


def html_to_pdf(
    html: Path, pdf: Path, browser: Path, timeout_s: float = 90, no_sandbox: bool = False
) -> None:
    """Print `html` to `pdf`. Raises PdfError with a readable reason on failure."""
    pdf.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix="nids-pdf-") as profile:
        args = [
            str(browser),
            "--headless",
            "--disable-gpu",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-extensions",
            "--disable-background-networking",
            "--disable-sync",
            "--disable-breakpad",
            "--disable-dev-shm-usage",  # containers often have a tiny /dev/shm
            "--password-store=basic",  # never wait on a desktop keyring
            "--use-mock-keychain",
            "--host-resolver-rules=MAP * ~NOTFOUND",  # nothing in the report may go online
            "--no-pdf-header-footer",
            f"--user-data-dir={profile}",
            f"--print-to-pdf={pdf.resolve()}",
            html.resolve().as_uri(),
        ]
        if no_sandbox or (sys.platform == "linux" and os.geteuid() == 0):
            # Chromium refuses to run as root with its sandbox, and containers usually lack the
            # user namespaces it needs. The page is our own script-free HTML with no network, so
            # running it unsandboxed is an acceptable trade.
            args.insert(1, "--no-sandbox")
        # stderr goes to a file, not a pipe: Chrome's helpers (crashpad) inherit its handles and
        # can outlive it, and reading a pipe would wait for them too.
        with tempfile.TemporaryFile() as err:
            try:
                proc = subprocess.Popen(  # noqa: S603 - fixed executable found above, no shell
                    args,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=err,
                    start_new_session=os.name == "posix",  # so the whole tree can be stopped
                )
            except OSError as exc:
                raise PdfError(f"Couldn't start {browser.name}: {exc}") from exc
            try:
                finished = _wait_for_pdf(proc, pdf, timeout_s)
            finally:
                _stop(proc)
            err.seek(0)
            detail = _last_lines(err.read().decode(errors="replace"))
    if not finished:
        raise PdfError(f"The browser took longer than {timeout_s:.0f} s. {detail}".strip())
    if not _is_complete_pdf(pdf):
        raise PdfError(f"{browser.name} exited with {proc.returncode}: {detail or 'no output'}")


def _wait_for_pdf(proc: subprocess.Popen[bytes], pdf: Path, timeout_s: float) -> bool:
    """True once the browser has exited or written a whole PDF, False on timeout.

    Headless Chrome on some Linux hosts (GitHub's Ubuntu runners among them) doesn't exit after
    printing, so a finished file counts as done even while the process is still up.
    """
    deadline = time.monotonic() + timeout_s
    last_size = -1
    while proc.poll() is None:
        if _is_complete_pdf(pdf):
            size = pdf.stat().st_size
            if size == last_size:  # unchanged across two polls: the write is over
                return True
            last_size = size
        if time.monotonic() > deadline:
            return False
        time.sleep(0.25)
    return True


def _is_complete_pdf(pdf: Path) -> bool:
    try:
        with pdf.open("rb") as f:
            if f.read(5) != b"%PDF-":
                return False
            f.seek(max(0, pdf.stat().st_size - 1024))
            return b"%%EOF" in f.read()
    except OSError:
        return False


def _stop(proc: subprocess.Popen[bytes]) -> None:
    """Kill the browser and everything it started (renderers, crashpad)."""
    if sys.platform != "win32":
        with contextlib.suppress(ProcessLookupError, PermissionError):  # already gone
            os.killpg(proc.pid, signal.SIGKILL)
    elif proc.poll() is None:
        proc.kill()
    proc.wait()


def _last_lines(stderr: str, count: int = 3) -> str:
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    return " | ".join(lines[-count:])
