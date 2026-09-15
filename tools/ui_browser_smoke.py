"""Fixture-only Signal Desk browser smoke; never binds or calls production port 8787."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_PORT = 8787
# (There was a PLAYWRIGHT_FALLBACK here: an absolute path to one machine's borrowed
#  node_modules. It duplicated PLAYWRIGHT_NODE_PATH below, which already does exactly
#  this job, so it is gone rather than re-homed into a second env var.)


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False).encode("utf-8")


class FixtureServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, fixture):
        super().__init__(("127.0.0.1", 0), FixtureHandler)
        self.fixture = fixture
        self.requests = []
        self.status_index = {}


class FixtureHandler(SimpleHTTPRequestHandler):
    server_version = "SignalDeskFixture/1.0"

    def log_message(self, _format, *_args):
        pass

    def _record(self):
        parsed = urlparse(self.path)
        self.server.requests.append({"method": self.command, "path": parsed.path})
        return parsed

    def _send_bytes(self, body, content_type, status=HTTPStatus.OK):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = self._record()
        if parsed.path == "/api/status":
            run = self.headers.get("X-Smoke-Run", "normal")
            snapshots = self.server.fixture["status_snapshots"]
            index = self.server.status_index.get(run, 0)
            self.server.status_index[run] = index + 1
            self._send_bytes(json_bytes(snapshots[min(index, len(snapshots) - 1)]), "application/json; charset=utf-8")
            return
        route_map = {
            "/api/ports": self.server.fixture["ports"],
            "/api/cli-bridge": self.server.fixture["cli_bridge"],
            "/api/deletions": self.server.fixture["deletions"],
        }
        if parsed.path in route_map:
            self._send_bytes(json_bytes(route_map[parsed.path]), "application/json; charset=utf-8")
            return
        if parsed.path == "/favicon.ico":
            self._send_bytes(b"", "image/x-icon", HTTPStatus.NO_CONTENT)
            return
        if parsed.path in ("/", "/index.html"):
            self._send_bytes((ROOT / "ui" / "dashboard.html").read_bytes(), "text/html; charset=utf-8")
            return
        if parsed.path.startswith("/assets/"):
            asset = (ROOT / "ui" / parsed.path.lstrip("/")).resolve()
            asset_root = (ROOT / "ui" / "assets").resolve()
            if asset.is_file() and os.path.commonpath((str(asset_root), str(asset))) == str(asset_root):
                self._send_bytes(asset.read_bytes(), "image/png")
                return
        self._send_bytes(b"not found", "text/plain", HTTPStatus.NOT_FOUND)

    def do_POST(self):
        self._record()
        self._send_bytes(b"fixture server rejects POST", "text/plain", HTTPStatus.METHOD_NOT_ALLOWED)


RUNNER = r'''
const { chromium } = require('playwright');
const baseUrl = process.argv[2];
const width = Number(process.argv[3]);
const height = Number(process.argv[4]);
const chromePath = process.env.SMOKE_CHROME_PATH || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const result = { requests: [], console: [], page_errors: [], checks: [] };
function check(condition, message) { if (!condition) throw new Error(message); result.checks.push(message); }
async function documentFits(page, label) {
  const geometry = await page.evaluate(() => ({ scrollWidth: document.documentElement.scrollWidth, clientWidth: document.documentElement.clientWidth }));
  check(geometry.scrollWidth <= geometry.clientWidth, label + ': document horizontal overflow ' + JSON.stringify(geometry));
  return geometry;
}
async function makePage(browser, run, reducedMotion) {
  const context = await browser.newContext({ viewport: { width, height }, reducedMotion });
  const page = await context.newPage();
  page.setExtraHTTPHeaders({ 'X-Smoke-Run': run });
  page.on('console', msg => { if (msg.type() === 'error') result.console.push(msg.text()); });
  page.on('pageerror', err => result.page_errors.push(String(err)));
  page.on('request', req => result.requests.push({ method: req.method(), path: new URL(req.url()).pathname }));
  return { context, page };
}
(async () => {
  const browser = await chromium.launch({ headless: true, executablePath: chromePath });
  try {
    for (const viewport of [{ label: 'wide', width: 1440 }, { label: 'narrow', width }]) {
      const pair = await makePage(browser, viewport.label, 'no-preference');
      await pair.page.setViewportSize({ width: viewport.width, height });
      await pair.page.goto(baseUrl, { waitUntil: 'networkidle' });
      await pair.page.locator('button[data-v="office"]').click();
      await pair.page.locator('[data-session-id="signal-parent"]').waitFor();
      await documentFits(pair.page, viewport.label);
      const parent = pair.page.locator('[data-session-id="signal-parent"]');
      check(await parent.getAttribute('data-zone') === 'working', viewport.label + ': initial parent is working');
      check((await parent.locator('.signal-parent-id').textContent()).trim() === 'A1', viewport.label + ': parent A/a label exists');
      check((await parent.locator('.child-token').first().textContent()).trim() === 'a1.1', viewport.label + ': child token exists');
      check((await parent.getAttribute('aria-label')).includes('Claude Code'), viewport.label + ': source is readable');
      if (viewport.label === 'wide') {
        const floor = pair.page.locator('.signal-floor'), rail = pair.page.locator('.signal-rail');
        const inspector = pair.page.locator('.signal-inspector'), queue = pair.page.locator('.signal-queue'), pool = pair.page.locator('.office-pool');
        const desktopGeometry = await pair.page.evaluate(() => {
          const rect = selector => { const r = document.querySelector(selector).getBoundingClientRect(); return { left: r.left, top: r.top, width: r.width, height: r.height }; };
          return { floor: rect('.signal-floor'), rail: rect('.signal-rail'), inspector: rect('.signal-inspector'), queue: rect('.signal-queue'), pool: rect('.office-pool') };
        });
        check(desktopGeometry.rail.left >= desktopGeometry.floor.left + desktopGeometry.floor.width, 'wide: operations rail is right of primary floor');
        check(desktopGeometry.inspector.top <= desktopGeometry.queue.top && desktopGeometry.queue.top <= desktopGeometry.pool.top, 'wide: Inspector precedes Queue and Pool in rail');
        const accents = await pair.page.evaluate(() => ['working', 'standby', 'stopped'].map(zone => getComputedStyle(document.querySelector('[data-zone="' + zone + '"]')).getPropertyValue('--zone-accent').trim()));
        check(accents.every(Boolean) && new Set(accents).size === 3, 'wide: three zones expose distinguishable accents');
        await parent.evaluate(el => { el.dataset.smokeIdentity = 'preserve'; });
        await pair.page.evaluate(() => tick());
        await pair.page.waitForFunction(() => document.querySelector('[data-session-id="signal-parent"]')?.dataset.zone === 'standby');
        check(await parent.getAttribute('data-smoke-identity') === 'preserve', 'same parent node survives working to standby');
        const emptyWorking = await pair.page.evaluate(() => {
          const desks = document.querySelector('[data-zone="working"] .signal-desks');
          const empty = desks.querySelector('.office-empty');
          return { hasEmpty: !!empty, desksHeight: desks.getBoundingClientRect().height, emptyHeight: empty && empty.getBoundingClientRect().height };
        });
        check(emptyWorking.hasEmpty && emptyWorking.desksHeight <= 72 && emptyWorking.emptyHeight <= 60, 'working empty state uses compact treatment');
        await pair.page.evaluate(() => tick());
        await pair.page.waitForFunction(() => document.querySelector('[data-session-id="signal-parent"]')?.dataset.zone === 'stopped');
        check(await parent.getAttribute('data-smoke-identity') === 'preserve', 'same parent node survives standby to stopped');
        const stopped = await parent.evaluate(el => ({ filter: getComputedStyle(el).filter, opacity: Number(getComputedStyle(el).opacity), zone: el.dataset.zone }));
        check(stopped.zone === 'stopped' && stopped.filter !== 'none' && stopped.opacity < 1, 'stopped desk has muted treatment');
        await parent.focus(); await pair.page.keyboard.press('Enter');
        check(await parent.getAttribute('aria-pressed') === 'true', 'keyboard selects Signal Desk parent');
        await pair.page.locator('button[data-v="deletions"]').click();
        await pair.page.locator('#deletions').waitFor({ state: 'visible' });
        await pair.page.waitForFunction(() => document.querySelector('#deletions').textContent.includes('fixture-repo'));
      }
      await pair.context.close();
    }
    const reduced = await makePage(browser, 'reduced', 'reduce');
    await reduced.page.goto(baseUrl, { waitUntil: 'networkidle' });
    await reduced.page.locator('button[data-v="office"]').click();
    const reducedParent = reduced.page.locator('[data-session-id="signal-parent"]');
    await reducedParent.waitFor();
    await reduced.page.evaluate(() => tick());
    await reduced.page.waitForFunction(() => document.querySelector('[data-session-id="signal-parent"]')?.dataset.zone === 'standby');
    const motion = await reducedParent.evaluate(el => ({ transform: el.style.transform, moving: el.classList.contains('signal-flip-moving'), reduce: matchMedia('(prefers-reduced-motion: reduce)').matches }));
    check(motion.reduce && !motion.transform && !motion.moving, 'reduced motion preserves final placement without FLIP animation');
    await documentFits(reduced.page, 'reduced');
    await reduced.context.close();
    check(result.console.length === 0, 'zero console errors: ' + result.console.join(' | '));
    check(result.page_errors.length === 0, 'zero page errors: ' + result.page_errors.join(' | '));
    check(result.requests.every(r => r.method === 'GET'), 'zero POST requests: ' + JSON.stringify(result.requests));
    const apiPaths = new Set(result.requests.filter(r => r.path.startsWith('/api/')).map(r => r.path));
    for (const expected of ['/api/status', '/api/ports', '/api/cli-bridge', '/api/deletions']) check(apiPaths.has(expected), 'observed fixture GET ' + expected);
    process.stdout.write(JSON.stringify({ ok: true, ...result }) + '\n');
  } finally { await browser.close(); }
})().catch(error => { process.stderr.write(String(error && error.stack || error) + '\n'); process.exit(1); });
'''


def playwright_node_path():
    configured = os.environ.get("PLAYWRIGHT_NODE_PATH")
    candidates = [Path(configured)] if configured else []
    candidates.append(ROOT / "node_modules")
    for candidate in candidates:
        if candidate and (candidate / "playwright" / "package.json").is_file():
            return candidate
    return None


def run_smoke(base_url, width, height):
    node = shutil.which("node")
    node_path = playwright_node_path()
    if not node:
        raise RuntimeError("node executable not found")
    if not node_path:
        raise RuntimeError("Playwright package not found; set PLAYWRIGHT_NODE_PATH to a node_modules directory containing playwright")
    with tempfile.NamedTemporaryFile("w", suffix=".cjs", encoding="utf-8", delete=False) as runner:
        runner.write(RUNNER)
        runner_path = runner.name
    try:
        env = os.environ.copy()
        env["NODE_PATH"] = str(node_path)
        completed = subprocess.run([node, runner_path, base_url, str(width), str(height)], text=True,
                                   capture_output=True, env=env, timeout=90)
    finally:
        Path(runner_path).unlink(missing_ok=True)
    if completed.returncode:
        raise RuntimeError((completed.stderr or completed.stdout).strip())
    return json.loads(completed.stdout)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--width", type=int, required=True)
    parser.add_argument("--height", type=int, required=True)
    args = parser.parse_args()
    if args.width < 1 or args.height < 1:
        raise SystemExit("width and height must be positive")
    fixture = json.loads(Path(args.fixture).read_text(encoding="utf-8"))
    server = FixtureServer(fixture)
    port = server.server_address[1]
    if port == PRODUCTION_PORT:
        raise SystemExit("refusing production port 8787")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = run_smoke("http://127.0.0.1:%d/" % port, args.width, args.height)
        result["fixture_port"] = port
        result["server_requests"] = server.requests
        result["production_port_touched"] = False
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
