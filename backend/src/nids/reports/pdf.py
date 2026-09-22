"""Print an HTML file to PDF with a headless Chromium-based browser (Edge, Chrome, Chromium).

Why a browser: it renders the same HTML the user can open, handles any Unicode text with system
fonts, and needs no extra Python dependency or native libraries (WeasyPrint needs GTK/Pango, which
is painful on Windows). Edge ships with Windows; Linux images install Chromium.

The browser gets a throwaway profile, no network (every hostname resolves to nothing) and a
timeout. The report itself contains no scripts and its CSP blocks every external fetch.
"""

import os
import shutil
import subprocess
import sys
import tempfile
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
        try:
            done = subprocess.run(  # noqa: S603 - fixed executable found above, no shell
                args, capture_output=True, timeout=timeout_s, check=False
            )
        except subprocess.TimeoutExpired as exc:
            raise PdfError(f"The browser took longer than {timeout_s:.0f} s.") from exc
        except OSError as exc:
            raise PdfError(f"Couldn't start {browser.name}: {exc}") from exc
    if not pdf.is_file() or pdf.stat().st_size == 0:
        detail = done.stderr.decode(errors="replace").strip().splitlines()[-1:] or ["no output"]
        raise PdfError(f"{browser.name} exited with {done.returncode}: {detail[0]}")
