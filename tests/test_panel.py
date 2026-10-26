import asyncio
import base64
import html
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

# Ensure the repository root is importable regardless of pytest's import mode.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ["DATA_DIR"] = "/tmp/abyss-panel-test-import"
os.environ["COOKIE_SECURE"] = "0"
os.environ["ABYSS_TEST_MODE"] = "1"

from fastapi.testclient import TestClient
from starlette.requests import Request
import pytest

import app.main as panel
import app.extended as extended


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(panel, "DATA_DIR", tmp_path)
    monkeypatch.setattr(panel, "DB_PATH", tmp_path / "panel.sqlite3")
    monkeypatch.setattr(panel, "XRAY_CONFIG", tmp_path / "xray.json")
    monkeypatch.setattr(panel, "xray_proc", None)

    async def fake_start_xray():
        panel.XRAY_CONFIG.write_text('{"test": true}', encoding="utf-8")

    monkeypatch.setattr(panel, "start_xray", fake_start_xray)
    with TestClient(panel.app) as test_client:
        yield test_client


def admin_client(client):
    page = client.get("/login")
    assert page.status_code == 200
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    response = client.post(
        "/login",
        data={"username": "admin", "password": "admin", "csrf_token": html.unescape(token)},
        follow_redirects=False,
    )
    assert response.status_code == 303
    overview = client.get("/api/overview")
    assert overview.status_code == 200
    return overview.json()["csrf"]


def test_support_url_is_rendered_safely_on_login_and_dashboard(client, monkeypatch):
    support_url = "https://support.example/donate?source=void"
    monkeypatch.setenv("SUPPORT_URL", support_url)

    login = client.get("/login")
    assert login.status_code == 200
    expected_link = f'href="{support_url}" target="_blank" rel="noopener noreferrer"'
    assert expected_link in login.text
    assert 'href="#support-link-not-configured"' not in login.text

    admin_client(client)
    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert expected_link in dashboard.text
    assert 'href="#support-link-not-configured"' not in dashboard.text


def test_support_url_rejects_unsafe_or_malformed_values(monkeypatch):
    marker = '<a href="#support-link-not-configured">support</a>'
    for value in ("javascript:alert(1)", "https://user:pass@support.example/donate", "https://support.example:invalid/donate", "file:///etc/passwd"):
        monkeypatch.setenv("SUPPORT_URL", value)
        assert panel.inject_support_links(marker) == marker

    monkeypatch.delenv("SUPPORT_URL", raising=False)
    assert panel.inject_support_links(marker) == marker


def test_fresh_install_uses_requested_admin_default(client, tmp_path):
    credential_file = tmp_path / "INITIAL_ADMIN_PASSWORD.txt"
    assert credential_file.exists()
    assert "Username: admin" in credential_file.read_text(encoding="utf-8")
    assert "Password: admin" in credential_file.read_text(encoding="utf-8")


def test_dashboard_is_not_cached_and_has_section_navigation(client):
    login_page = client.get("/login")
    assert 'id="abyss-theme-system"' in login_page.text
    assert 'id="abyss-theme-polish"' in login_page.text
    assert 'id="abyss-layout-repair"' in login_page.text
    assert 'class="login-layout"' in login_page.text
    assert "@keyframes abyssStreakDrift" in login_page.text
    assert ".login-layout>.card{position:relative!important;z-index:2!important" in login_page.text
    assert 'id="abyss-theme-controller"' in login_page.text
    assert 'data-abyss-theme="angel"' in login_page.text
    admin_client(client)
    profiles = client.get("/api/settings").json()["profiles"]
    websocket = next(p for p in profiles if p["key"] == "ws")
    assert websocket["network"] == "ws"
    assert websocket["path"] == "/ws"
    assert websocket["port"] == 10001
    assert websocket["protocol"] == "vless"
    assert any(p["experimental"] for p in profiles)
    response = client.get("/")
    assert response.status_code == 200
    assert "no-store" in response.headers.get("cache-control", "")
    assert '/dashboard.js?v=20261018-chart-stallfix1' in response.text
    assert 'id="abyss-theme-system"' in response.text
    assert 'id="abyss-theme-polish"' in response.text
    assert 'id="abyss-theme-controller"' in response.text
    assert 'Abyss · مشکی و خاکستری' in response.text
    assert 'Angel · سفید و طلایی کمرنگ' in response.text
    assert 'Graphite · خاکستری ساده' in response.text
    assert 'abyssParticleCanvas' in response.text
    assert 'ستاره دادن' in response.text
    assert 'سازنده · Abyss Tunnel' in response.text
    assert 'id="sidebar"' in response.text
    assert 'id="menuToggle"' in response.text
    assert 'id="abyss-layout-repair"' in response.text
    assert 'id="abyss-layout-repair-js"' in response.text
    assert 'id="overviewStats"' in response.text
    assert 'id="dashboardUsageCard"' in response.text
    assert 'id="panelHealthCard"' in response.text
    assert "grid-template-columns:repeat(4,minmax(0,1fr))!important" in response.text
    assert '<img class="abyss-logo-image" src="/brand-logo" alt="" aria-hidden="true">' not in response.text
    assert '<div class="abyss-utility-links" aria-label="پیوندهای پروژه">' in response.text
    assert response.text.index('</nav>') < response.text.index('aria-label="پیوندهای پروژه"') < response.text.index('aria-label="حساب فعلی"')
    assert '.client-details-panel{grid-row:2!important}' in response.text
    login_page = client.get("/login")
    assert '<img class="abyss-logo-image" src="/brand-logo" alt="" aria-hidden="true">' in login_page.text
    logo = client.get("/brand-logo")
    assert logo.status_code == 200
    assert logo.headers.get("content-type", "").startswith("image/jpeg")
    assert "background-image:url('/brand/abyss-tunnel-logo.jpg')" in response.text
    assert "Desktop proportions from the reference dashboard" in response.text
    assert "grid-column:1 / span 3!important;grid-row:3!important" in response.text
    assert "grid-column:4 / span 3!important;grid-row:3!important" in response.text
    assert "grid-column:7 / span 6!important;grid-row:3!important" in response.text
    assert "#dashboardQuickCard #recentActivityList[hidden]{display:none!important}" in response.text
    visual_workflow = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "visual-preview.yml").read_text(encoding="utf-8")
    assert "chartXBeforeHealth:chart.x<health.x" in visual_workflow
    assert "healthXBeforeQuick:health.x<quick.x" in visual_workflow
    assert 'dashboard_layout["chartXBeforeHealth"]' in visual_workflow
    assert 'dashboard_layout["healthXBeforeQuick"]' in visual_workflow
    assert "Administrator created a database backup" in visual_workflow
    assert "Updated enabled connection profiles" in visual_workflow
    assert 'expected_quick_values = ("user123"' in visual_workflow
    assert 'out / "13-users-mobile.png"' in visual_workflow
    assert 'out / "14-create-mobile.png"' in visual_workflow
    assert "MOBILE_CLIENTS_LAYOUT=" in visual_workflow
    assert "MOBILE_CREATE_LAYOUT=" in visual_workflow
    assert 'out / "15-users-tablet.png"' in visual_workflow
    assert 'out / "16-create-tablet.png"' in visual_workflow
    assert "TABLET_CLIENTS_LAYOUT=" in visual_workflow
    assert "TABLET_CREATE_LAYOUT=" in visual_workflow
    assert "quickDetailCount:quickDetailRows.length,quickDetailLabels,quickDetailValues," in visual_workflow
    assert "logoReady" in visual_workflow
    assert "CREATE_MULTISELECT_CHECKED=" in visual_workflow
    assert "protocol choices behave as single-select" in visual_workflow
    assert "ABYSS TUNNEL" in login_page.text
    assert 'class="visual-orbit" src="/brand/abyss-tunnel-logo.jpg" alt="AbyssTunnel · I.T.A."' in login_page.text
    logo_response = client.get("/brand/abyss-tunnel-logo.jpg")
    assert logo_response.status_code == 200
    assert logo_response.headers.get("content-type", "").startswith("image/jpeg")
    assert logo_response.content.startswith(b"\xff\xd8\xff")
    assert logo_response.content.endswith(b"\xff\xd9")
    assert 'class="login-password-toggle"' in login_page.text
    assert 'aria-pressed="false"' in login_page.text
    assert 'data-nav="create"' in response.text
    assert 'data-nav="servers"' in response.text
    assert 'data-nav="protocols"' in response.text
    assert 'data-nav="reports"' in response.text
    assert 'data-section-page="create"' in response.text
    assert 'id="serversPage"' in response.text
    assert 'id="protocolsPage"' in response.text
    assert 'id="reportsPage"' in response.text
    assert 'data-settings-tab="backup"' in response.text
    assert 'html body main.app-shell .workspace #reportsPage .report-event-table{display:table!important;width:100%!important;' in response.text
    assert 'overflow-wrap:normal!important;word-break:normal!important' in response.text
    assert 'unicode-bidi:isolate!important' in response.text
    assert 'id="protocolCatalog"' in response.text
    assert 'id="reportProfiles"' in response.text
    assert 'id="serverTableBody"' in response.text
    assert 'id="dashboardComponentStatus"' in response.text
    assert 'id="dashboardQuickCard"' in response.text
    assert 'id="dashboardQuickDetails"' in response.text
    assert 'data-i18n="quickDetails"' in response.text
    assert 'id="dashboardStatusAccessible"' in response.text
    assert 'id="globalSearch"' in response.text
    assert 'id="panelHelpDialog"' in response.text
    assert 'class="account-badge"' in response.text
    assert 'افزودن کاربر +' in response.text
    dashboard_script = client.get("/dashboard.js")
    assert dashboard_script.status_code == 200
    assert "function runGlobalSearch()" in dashboard_script.text
    assert 'oninput="scheduleClientRender()"' in response.text
    assert "function scheduleClientRender()" in dashboard_script.text
    assert "activeSection==='dashboard'||activeSection==='metrics'" in dashboard_script.text
    assert "function renderDashboardQuickDetails(data=latestOverview)" in dashboard_script.text
    assert "latestService:'آخرین سرویس ساخته‌شده'" in dashboard_script.text
    assert "latestPanelChange:'آخرین تغییر پنل'" in dashboard_script.text
    assert "latestBackup:'آخرین پشتیبان'" in dashboard_script.text
    assert "function showPanelHelp()" in dashboard_script.text
    assert "function loadServerStatus()" in dashboard_script.text
    assert "setTimeout(()=>controller.abort(),20000)" in dashboard_script.text
    assert "درخواست API پس از ۲۰ ثانیه پاسخ نداد." in dashboard_script.text
    assert "function loadReports()" in dashboard_script.text
    assert "report-event-table" in dashboard_script.text
    assert '<bdi dir="ltr">' in dashboard_script.text
    assert "function renderProtocolCatalog(profiles)" in dashboard_script.text
    assert 'id="void-touch-responsive-polish"' in response.text
    assert 'id="void-touch-interaction"' in response.text
    assert "document.addEventListener('pointerdown',e=>respond" in response.text
    assert "void-touch-compact" in response.text
    assert 'content="width=device-width,initial-scale=1,viewport-fit=cover"' in response.text
    assert response.text.count('id="name"') == 1
    assert response.text.count('id="clientProfileChoices"') == 1
    assert 'data-section-page="clients"' in response.text
    assert 'id="metricsCard"' in response.text
    assert 'id="adminUsersCard"' in response.text
    assert 'id="apiKeysCard"' in response.text
    assert '<span class="abyss-logo-mark" aria-hidden="true"></span>' not in response.text
    # Menu branding stays text-only at every breakpoint; the login page keeps its full logo.
    assert 'html body main.app-shell .abyss-brand-row .abyss-logo-mark,' in response.text
    assert 'html body main.app-shell .abyss-brand-row .abyss-logo-image,' in response.text
    assert 'justify-content:flex-start!important;gap:0!important;' in response.text
    assert 'background:transparent!important;border:0!important;border-radius:0!important;' in response.text
    assert 'menu.textContent=\'☰\';' in response.text
    assert '(brand||sidebar).prepend(closeButton);' in response.text
    assert 'body.abyss-menu-open main.app-shell>#menuToggle{' in response.text
    assert 'overflow-y:auto!important;overflow-x:hidden!important' in response.text
    # Obsolete eclipse pseudo-element and mobile-only inset/header treatment must stay removed.
    assert "Small eclipse insignia" not in response.text
    assert "side-brand:before{" not in response.text
    assert 'html body main.app-shell>aside.sidebar>.side-brand .brand-name{\n  display:grid!important;flex:1 1 auto!important;width:100%!important;' in response.text
    assert 'html body main.app-shell>aside.sidebar>.side-brand{\n  justify-content:flex-start!important;gap:0!important;' in response.text
    assert 'background:transparent!important;border:0!important;border-radius:0!important;' in response.text
    assert 'width:24px!important;height:28px!important;' in response.text
    assert 'font-size:16px!important;' in response.text
    assert "closeButton.setAttribute('aria-label','بستن منو');" in response.text
    assert 'MOBILE_DRAWER_BOTTOM=' in visual_workflow
    assert 'The floating menu trigger must be icon-only and hidden while the drawer is open' in visual_workflow
    assert '.sidebar{position:fixed!important;top:0!important;left:0!important;right:auto!important;' in response.text
    assert "پیش‌فرض خاموش‌اند" in response.text


def test_embedded_dashboard_scripts_have_valid_javascript_syntax():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is not installed; JavaScript syntax validation is run when available.")

    scripts = []
    for document in (panel.LOGIN, panel.DASH):
        scripts.extend(re.findall(r"<script\b[^>]*>(.*?)</script>", document, flags=re.S))
    scripts.append(panel.DASH_JS)

    for index, script in enumerate(scripts):
        if not script.strip():
            continue
        result = subprocess.run(
            [node, "--check"],
            input=script,
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )
        assert result.returncode == 0, f"JavaScript chunk {index} has a syntax error:\n{result.stderr}"


def test_dashboard_requires_login(client):
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert client.get("/api/overview").status_code == 401


def test_system_metrics_exposes_traffic_history_for_dashboard_chart(client):
    admin_client(client)
    response = client.get("/api/system/metrics?period=24h")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["period"] == "24h"
    assert isinstance(payload.get("history"), list)
    history = payload.get("traffic_history")
    assert isinstance(history, list)
    assert history
    assert payload["traffic_history_count"] >= len(history)
    assert {"at", "recorded_traffic_bytes"} <= set(history[-1])


def test_dashboard_usage_chart_note_is_not_hidden(client):
    admin_client(client)
    response = client.get("/")
    assert response.status_code == 200
    assert 'id="chartNote"' in response.text
    assert "#dashboardUsageCard #chartNote{display:none!important}" not in response.text


def test_create_pause_subscription_and_revoke(client):
    csrf = admin_client(client)
    headers = {"X-CSRF-Token": csrf}

    created = client.post("/api/clients", json={"name": "Test client", "duration_days": 30, "quota_gb": 10}, headers=headers)
    assert created.status_code == 200, created.text
    client_id = created.json()["id"]

    overview = client.get("/api/overview").json()
    assert overview["total"] == 1
    assert overview["active"] == 1
    row = overview["clients"][0]
    assert row["quota_bytes"] == 10 * 1024**3
    assert row["expires_at"]

    link = client.get(f"/api/clients/{client_id}/subscription")
    assert link.status_code == 200
    assert link.json()["url"].startswith("https://")

    subscription = client.get(link.json()["url"].replace("https://testserver", "http://testserver"))
    assert subscription.status_code == 200
    configs = base64.b64decode(subscription.text).decode().splitlines()
    assert len(configs) == 9
    assert sum(line.startswith("vless://") for line in configs) == 6
    assert sum(line.startswith("trojan://") for line in configs) == 1
    assert sum(line.startswith("vmess://") for line in configs) == 1
    assert sum(line.startswith("ss://") for line in configs) == 1
    ss_uri = next(line for line in configs if line.startswith("ss://"))
    assert "plugin=v2ray-plugin%3Btls%3Bhost%3Dtestserver%3Bpath%3D%2Fss-ws" in ss_uri
    assert any("type=ws" in line for line in configs)
    assert any("type=httpupgrade" in line for line in configs)
    httpupgrade_configs = [line for line in configs if "type=httpupgrade" in line]
    assert len(httpupgrade_configs) == 2
    assert any("path=%2Fhttpupgrade" in line and "ed%3D2560" not in line for line in httpupgrade_configs)
    assert any("path=%2Fupgrade" in line and "ed%3D2560" not in line for line in httpupgrade_configs)
    websocket_configs = [line for line in configs if "type=ws" in line]
    assert len(websocket_configs) == 3
    assert any("path=%2Fws%3Fed%3D2560" in line for line in websocket_configs)
    assert any("path=%2Fconnect%3Fed%3D2560" in line for line in websocket_configs)
    assert any("path=%2Ftrojan-ws%3Fed%3D2560" in line for line in websocket_configs)
    assert all("ed%3D2560" in line for line in websocket_configs)
    assert not any("ed%3D2560" in line for line in configs if "type=xhttp" in line)
    assert sum("type=xhttp" in line for line in configs) == 2
    assert any("mode=auto" in line for line in configs)
    assert any("mode=packet-up" in line for line in configs)
    assert sum("mode=packet-up" in line for line in configs) == 1
    assert not any("mode=stream-up" in line or "mode=stream-one" in line for line in configs)
    assert sum("mode=auto" in line for line in configs) == 1
    paused = client.patch(f"/api/clients/{client_id}", json={"enabled": False}, headers=headers)
    assert paused.status_code == 200
    assert client.get(f"/sub/{_token_from_url(link.json()['url'])}").status_code == 404

    enabled = client.patch(f"/api/clients/{client_id}", json={"enabled": True}, headers=headers)
    assert enabled.status_code == 200

    revoked = client.delete(f"/api/clients/{client_id}", headers=headers)
    assert revoked.status_code == 200
    assert client.get("/api/overview").json()["total"] == 0


def test_same_subscription_url_serves_branded_page_to_browsers(client):
    csrf = admin_client(client)
    created = client.post("/api/clients", json={"name": "Unified URL", "duration_days": 30, "quota_gb": 4},
                          headers={"X-CSRF-Token": csrf})
    assert created.status_code == 200
    url = client.get(f"/api/clients/{created.json()['id']}/subscription").json()["url"]
    path = url.replace("https://testserver", "")
    browser = client.get(path, headers={"Accept": "text/html,application/xhtml+xml", "User-Agent": "Mozilla/5.0 Chrome/130"})
    assert browser.status_code == 200
    assert "text/html" in browser.headers["content-type"]
    assert "Unified URL" in browser.text
    assert 'id="abyss-theme-system"' in browser.text
    assert 'id="abyss-theme-polish"' in browser.text
    assert 'id="abyss-theme-controller"' in browser.text
    assert "no-store" in browser.headers["cache-control"]
    subscription_client = client.get(path, headers={"Accept": "*/*", "User-Agent": "v2rayNG"})
    assert subscription_client.status_code == 200
    assert "text/plain" in subscription_client.headers["content-type"]
    configs = base64.b64decode(subscription_client.text).decode().splitlines()
    assert len(configs) == 9
    assert "Accept, User-Agent" in subscription_client.headers["vary"]
    assert "Subscription-Userinfo" in subscription_client.headers
    assert "total=4294967296" in subscription_client.headers["Subscription-Userinfo"]
    assert client.get(f"/api/clients/{created.json()['id']}/subscription").json()["page_url"] == url


def test_usage_history_has_index_for_retention_cleanup(client):
    admin_client(client)
    with panel.db() as conn:
        indexes = {row["name"] for row in conn.execute("PRAGMA index_list(client_usage_history)")}
    assert "idx_client_usage_history_sampled_at" in indexes
    assert "idx_client_usage_history_retention" in indexes


def test_subscription_usage_chart_uses_scoped_real_client_history(client):
    csrf = admin_client(client)
    headers = {"X-CSRF-Token": csrf}
    first = client.post("/api/clients", json={"name": "History A", "quota_gb": 20}, headers=headers)
    second = client.post("/api/clients", json={"name": "History B", "quota_gb": 20}, headers=headers)
    assert first.status_code == 200 and second.status_code == 200
    first_id, second_id = first.json()["id"], second.json()["id"]

    with panel.db() as conn:
        conn.execute("UPDATE clients SET used_bytes=? WHERE id=?", (5 * 1024**3, first_id))
        conn.execute("UPDATE clients SET used_bytes=? WHERE id=?", (3 * 1024**3, second_id))

    now = int(panel.time.time()) - 7200
    panel.record_client_usage_history(now=now)
    with panel.db() as conn:
        conn.execute("UPDATE clients SET used_bytes=? WHERE id=?", (6 * 1024**3, first_id))
    panel.record_client_usage_history(now=now + panel.CLIENT_USAGE_HISTORY_SAMPLE_SECONDS + 1)

    sample_time = now + panel.CLIENT_USAGE_HISTORY_SAMPLE_SECONDS + 1
    first_history = panel.get_client_usage_history(first_id, now=sample_time)
    second_history = panel.get_client_usage_history(second_id, now=sample_time)
    assert [row["used_bytes"] for row in first_history] == [5 * 1024**3, 6 * 1024**3]
    assert [row["used_bytes"] for row in second_history] == [3 * 1024**3, 3 * 1024**3]

    token = client.get(f"/api/clients/{first_id}/subscription").json()["url"].rsplit("/sub/", 1)[1]
    browser = client.get(
        f"/sub/{token}",
        headers={"Accept": "text/html,application/xhtml+xml", "User-Agent": "Mozilla/5.0 Chrome/130"},
    )
    assert browser.status_code == 200
    assert 'id="clientUsageChart"' in browser.text
    assert 'data-usage-days="7"' in browser.text
    assert 'data-usage-days="30"' in browser.text
    assert 'data-usage-days="90"' in browser.text
    assert "__USAGE_HISTORY__" not in browser.text
    assert f'"used_bytes":{6 * 1024**3}' in browser.text


def _token_from_url(url):
    return url.rsplit("/sub/", 1)[1]


def test_mutations_reject_missing_csrf(client):
    admin_client(client)
    response = client.post("/api/clients", json={"name": "Should fail"})
    assert response.status_code == 403


def test_failed_xray_update_rolls_back_new_client(client, monkeypatch):
    csrf = admin_client(client)
    calls = {"count": 0}

    async def fail_once_then_recover():
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("simulated Xray failure")
        panel.XRAY_CONFIG.write_text('{"recovered": true}', encoding="utf-8")

    monkeypatch.setattr(panel, "start_xray", fail_once_then_recover)
    response = client.post(
        "/api/clients",
        json={"name": "Rollback test"},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 503
    assert client.get("/api/overview").json()["total"] == 0
    assert calls["count"] == 2


def test_xray_config_has_unique_inbounds_and_stats_api(client):
    admin_client(client)
    csrf = client.get("/api/overview").json()["csrf"]
    created = client.post("/api/clients", json={"name": "Config test"}, headers={"X-CSRF-Token": csrf})
    assert created.status_code == 200
    config = panel.make_xray_config()
    inbounds = config["inbounds"]
    assert len(inbounds) == 10  # Stats API plus nine stable profiles; four experimental profiles stay off by default
    assert len({item["tag"] for item in inbounds}) == len(inbounds)
    assert len({item["port"] for item in inbounds}) == len(inbounds)
    assert config["api"]["services"] == ["StatsService"]
    assert config["policy"]["levels"]["0"]["statsUserUplink"] is True
    assert config["policy"]["levels"]["0"]["statsUserDownlink"] is True
    by_tag = {item["tag"]: item for item in inbounds}
    ws_settings = by_tag["in-ws"]["streamSettings"]["wsSettings"]
    assert ws_settings["maxEarlyData"] == 2560
    assert ws_settings["earlyDataHeaderName"] == "Sec-WebSocket-Protocol"
    assert "maxEarlyData" not in by_tag["in-ss_ws"]["streamSettings"]["wsSettings"]
    xhttp = [item for item in inbounds if item.get("streamSettings", {}).get("network") == "xhttp"]
    assert {item["streamSettings"]["xhttpSettings"]["mode"] for item in xhttp} == {"auto", "packet-up"}
    assert len({item["streamSettings"]["xhttpSettings"]["path"] for item in xhttp}) == 2


def test_tcp_reality_profile_is_only_detected_for_matching_railway_proxy(monkeypatch):
    for key in ("RAILWAY_TCP_PROXY_DOMAIN", "RAILWAY_TCP_PROXY_PORT", "RAILWAY_TCP_APPLICATION_PORT"):
        monkeypatch.delenv(key, raising=False)
    assert panel.railway_tcp_reality_profile() is None

    monkeypatch.setenv("RAILWAY_TCP_PROXY_DOMAIN", "quiet.proxy.rlwy.net")
    monkeypatch.setenv("RAILWAY_TCP_PROXY_PORT", "15140")
    monkeypatch.setenv("RAILWAY_TCP_APPLICATION_PORT", str(panel.TCP_REALITY_INTERNAL_PORT))
    profile = panel.railway_tcp_reality_profile()
    assert profile["key"] == "vless_reality_tcp"
    assert profile["network"] == "raw"
    assert profile["port"] == 10014
    assert profile["listen"] == "0.0.0.0"
    assert profile["tcp_proxy_domain"] == "quiet.proxy.rlwy.net"
    assert profile["tcp_proxy_port"] == 15140

    monkeypatch.setenv("RAILWAY_TCP_APPLICATION_PORT", "8080")
    assert panel.railway_tcp_reality_profile() is None
    monkeypatch.setenv("RAILWAY_TCP_APPLICATION_PORT", str(panel.TCP_REALITY_INTERNAL_PORT))
    monkeypatch.setenv("RAILWAY_TCP_PROXY_PORT", "not-a-port")
    assert panel.railway_tcp_reality_profile() is None


def test_reality_keypair_generation_is_persistent_and_parses_current_xray_output(client, monkeypatch, tmp_path):
    fake_xray = tmp_path / "xray-keygen"
    fake_xray.write_text(
        "#!/bin/sh\n"
        "echo 'PrivateKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'\n"
        "echo 'Password (PublicKey): BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'\n"
        "echo 'Hash32: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'\n",
        encoding="utf-8",
    )
    fake_xray.chmod(0o755)
    monkeypatch.setattr(panel, "XRAY_BIN", str(fake_xray))
    monkeypatch.setenv("VOID_REALITY_SERVER_NAME", "www.microsoft.com")
    monkeypatch.delenv("VOID_REALITY_TARGET", raising=False)

    first = panel.get_reality_tcp_settings()
    second = panel.get_reality_tcp_settings()
    assert first == second
    assert first["private_key"].startswith("A")
    assert first["public_key"].startswith("B")
    assert first["server_name"] == "www.microsoft.com"
    assert first["target"] == "www.microsoft.com:443"
    assert len(first["short_id"]) == 16
    with panel.db() as conn:
        saved = conn.execute("SELECT value FROM settings WHERE key='reality_tcp_config'").fetchone()
    assert saved is not None


def test_tcp_reality_profile_builds_xray_inbound_and_direct_subscription(client, monkeypatch):
    csrf = admin_client(client)
    created = client.post(
        "/api/clients",
        json={"name": "Direct TCP test"},
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 200
    with panel.db() as conn:
        row = conn.execute("SELECT * FROM clients WHERE id=?", (created.json()["id"],)).fetchone()
    assert row is not None
    profile = {
        "key": "vless_reality_tcp",
        "label": "VLESS · REALITY · TCP مستقیم",
        "protocol": "vless",
        "network": "raw",
        "path": "",
        "port": 10014,
        "mode": None,
        "security": "reality",
        "listen": "0.0.0.0",
        "flow": "xtls-rprx-vision",
        "tcp_proxy_domain": "quiet.proxy.rlwy.net",
        "tcp_proxy_port": 15140,
    }
    monkeypatch.setattr(panel, "PROFILES", panel.PROFILES + [profile])
    monkeypatch.setattr(panel, "get_reality_tcp_settings", lambda: {
        "private_key": "PRIVATE_TEST_KEY",
        "public_key": "PUBLIC_TEST_KEY",
        "short_id": "a1b2c3d4e5f60718",
        "server_name": "www.microsoft.com",
        "target": "www.microsoft.com:443",
    })

    config = panel.make_xray_config()
    inbound = next(item for item in config["inbounds"] if item["tag"] == "in-vless_reality_tcp")
    assert inbound["listen"] == "0.0.0.0"
    assert inbound["port"] == 10014
    assert inbound["streamSettings"]["network"] == "raw"
    assert inbound["streamSettings"]["security"] == "reality"
    assert inbound["streamSettings"]["realitySettings"]["privateKey"] == "PRIVATE_TEST_KEY"
    assert inbound["settings"]["clients"][0]["flow"] == "xtls-rprx-vision"

    request = Request({
        "type": "http", "method": "GET", "scheme": "https", "path": "/sub/test",
        "raw_path": b"/sub/test", "query_string": b"",
        "headers": [(b"host", b"void.example")],
    })
    links = panel.make_subscription_links(dict(row), request)
    direct = next(item for item in links if item["key"] == "vless_reality_tcp")
    assert "vless://" + row["client_uuid"] + "@quiet.proxy.rlwy.net:15140?" in direct["url"]
    assert "security=reality" in direct["url"]
    assert "pbk=PUBLIC_TEST_KEY" in direct["url"]
    assert "sni=www.microsoft.com" in direct["url"]
    assert "sid=a1b2c3d4e5f60718" in direct["url"]
    assert "flow=xtls-rprx-vision" in direct["url"]
    assert "type=tcp" in direct["url"]


def test_subscription_feedback_validates_operator_and_result(client):
    csrf = admin_client(client)
    made = client.post("/api/clients", json={"name": "Feedback test"}, headers={"X-CSRF-Token": csrf})
    assert made.status_code == 200
    info = client.get("/api/clients/" + made.json()["id"] + "/subscription").json()
    token = info["url"].rsplit("/", 1)[1]
    invalid = client.post("/sub/" + token + "/feedback", json={"carrier": "invalid", "profile_key": "ws", "result": "ok"})
    assert invalid.status_code == 422
    accepted = client.post("/sub/" + token + "/feedback", json={"carrier": "irancell", "profile_key": "ws", "result": "ok"})
    assert accepted.status_code == 200


def test_operator_diagnostics_calculates_profile_success_rate(client):
    admin_client(client)
    with panel.db() as conn:
        for index, result in enumerate(("ok", "ok", "fail")):
            conn.execute(
                "INSERT INTO profile_feedback(client_id,carrier,profile_key,result,created_at,user_agent) VALUES(?,?,?,?,?,?)",
                ("sample-client-" + str(index), "irancell", "ws", result, panel.utc_now(), "test-agent"),
            )
    response = client.get("/api/system/diagnostics?carrier=irancell")
    assert response.status_code == 200, response.text
    profile = next(item for item in response.json()["profiles"] if item["key"] == "ws")
    assert profile["feedback_reports"] == 3
    assert profile["feedback_success_rate"] == 67


def test_xhttp_modes_are_real_and_alternate_paths_are_unique(client):
    profiles = {p["key"]: p for p in panel.PROFILES}
    assert profiles["xhttp_stream_up"]["mode"] == "stream-up"
    assert profiles["xhttp_stream_one"]["mode"] == "stream-one"
    assert profiles["xhttp_stream_up_alt"]["mode"] == "stream-up"
    assert profiles["xhttp_stream_one_alt"]["mode"] == "stream-one"
    assert profiles["xhttp_stream_up"]["path"] != profiles["xhttp_stream_up_alt"]["path"]
    assert profiles["xhttp_stream_one"]["path"] != profiles["xhttp_stream_one_alt"]["path"]
    assert len({p["port"] for p in panel.PROFILES}) == len(panel.PROFILES)


def test_experimental_xhttp_profiles_are_opt_in(client):
    csrf = admin_client(client)
    headers = {"X-CSRF-Token": csrf}
    settings = client.get("/api/settings").json()["profiles"]
    experimental = {p["key"] for p in panel.PROFILES if p.get("experimental")}
    assert experimental == {
        "xhttp_stream_up", "xhttp_stream_one",
        "xhttp_stream_up_alt", "xhttp_stream_one_alt",
    }
    settings_by_key = {p["key"]: p for p in settings}
    assert all(not settings_by_key[key]["enabled"] for key in experimental)

    response = client.patch(
        "/api/settings/profiles",
        json={"profiles": {"xhttp_stream_up": True}},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    updated = {p["key"]: p["enabled"] for p in response.json()["profiles"]}
    assert updated["xhttp_stream_up"] is True
    assert updated["xhttp_stream_one"] is False
    ports = {item["port"] for item in panel.make_xray_config()["inbounds"]}
    assert 10005 in ports
    assert 10006 not in ports


def test_diagnostics_distinguish_local_route_from_real_tunnel(client):
    admin_client(client)
    response = client.get("/api/system/diagnostics")
    assert response.status_code == 200, response.text
    data = response.json()
    assert len(data["profiles"]) == 13
    assert data["actual_tunnel_tested"] is False
    assert "پینگ یا تونل واقعی" in data["note"]
    for profile in data["profiles"]:
        assert "listener_ok" in profile
        assert "route_ok" in profile
        assert profile["tunnel_tested"] is False
        assert profile["status"] in {
            "disabled", "listener_missing", "gateway_error", "upgrade_handshake_failed", "route_reachable_tunnel_unverified"
        }


def test_subscription_diagnostics_only_probe_profiles_in_that_subscription(client, monkeypatch):
    csrf = admin_client(client)
    headers = {"X-CSRF-Token": csrf}
    created = client.post(
        "/api/clients",
        json={"name": "Single profile", "profiles": ["ws"]},
        headers=headers,
    )
    assert created.status_code == 200, created.text
    subscription = client.get(f"/api/clients/{created.json()['id']}/subscription")
    token = subscription.json()["url"].rsplit("/sub/", 1)[1]
    probed = []

    def fake_probe(profile):
        probed.append(profile["key"])
        return {"key": profile["key"], "route_ok": True, "latency_ms": 1}

    monkeypatch.setattr(extended, "_probe_profile", fake_probe)
    response = client.get(f"/s/{token}/diagnostics")
    assert response.status_code == 200, response.text
    assert probed == ["ws"]
    assert [item["key"] for item in response.json()["route_checks"]] == ["ws"]
    assert response.json()["checked_profiles"] == ["ws"]
    assert "ws" in response.json()["enabled_profiles"]


def _stub_profile_probe(monkeypatch, http_status):
    observed = {}

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    class FakeResponse:
        status = http_status

    class FakeHTTPConnection:
        def __init__(self, host, port, timeout):
            observed["target"] = (host, port, timeout)

        def request(self, method, path, headers):
            observed["request"] = (method, path, dict(headers))

        def getresponse(self):
            return FakeResponse()

        def close(self):
            pass

    monkeypatch.setattr(extended.socket, "create_connection", lambda address, timeout: FakeSocket())
    monkeypatch.setattr(extended.http.client, "HTTPConnection", FakeHTTPConnection)
    return observed


@pytest.mark.parametrize("network", ["ws", "httpupgrade"])
def test_profile_probe_sends_complete_upgrade_handshake(monkeypatch, network):
    observed = _stub_profile_probe(monkeypatch, 101)
    profile = {
        "key": "test-profile", "label": network, "path": "/probe",
        "port": 10001, "network": network, "mode": None,
        "protocol": "vless", "enabled": True,
    }

    result = extended._probe_profile(profile)

    method, path, headers = observed["request"]
    assert method == "GET"
    assert path == "/probe"
    assert headers["Connection"] == "Upgrade"
    assert headers["Upgrade"] == "websocket"
    assert headers["Sec-WebSocket-Key"] == "dGhlIHNhbXBsZSBub25jZQ=="
    assert headers["Sec-WebSocket-Version"] == "13"
    assert result["listener_ok"] is True
    assert result["route_ok"] is True
    assert result["handshake_ok"] is True
    assert result["status"] == "route_reachable_tunnel_unverified"
    assert result["route_latency_ms"] is not None
    assert result["probe_duration_ms"] is not None
    assert result["latency_ms"] == result["route_latency_ms"]
    assert result["tunnel_tested"] is False


@pytest.mark.parametrize(
    ("http_status", "expected_route_ok", "expected_probe_status"),
    [
        (400, False, "upgrade_handshake_failed"),
        (502, False, "gateway_error"),
        (101, True, "route_reachable_tunnel_unverified"),
    ],
)
def test_profile_probe_does_not_mark_failed_upgrade_as_healthy(
    monkeypatch, http_status, expected_route_ok, expected_probe_status
):
    _stub_profile_probe(monkeypatch, http_status)
    profile = {
        "key": "ws", "label": "WebSocket", "path": "/ws",
        "port": 10001, "network": "ws", "mode": None,
        "protocol": "vless", "enabled": True,
    }

    result = extended._probe_profile(profile)

    assert result["route_ok"] is expected_route_ok
    assert result["status"] == expected_probe_status
    assert result["handshake_ok"] is (http_status == 101)


def test_subscription_landing_page_and_qr_are_responsive_and_private(client):
    csrf = admin_client(client)
    created = client.post(
        "/api/clients",
        json={"name": "Portal user", "duration_days": 14, "quota_gb": 8},
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 200
    cid = created.json()["id"]
    info = client.get(f"/api/clients/{cid}/subscription").json()
    assert info["url"].startswith("https://testserver/sub/")
    assert info["page_url"] == info["url"] and info["page_url"].startswith("https://testserver/sub/")
    assert info["qr_url"].endswith("/qr")

    page = client.get(info["page_url"].replace("https://testserver", "http://testserver"), headers={"Accept": "text/html,application/xhtml+xml", "User-Agent": "Mozilla/5.0 Chrome/130"})
    assert page.status_code == 200
    assert "viewport-fit=cover" in page.text
    assert "Abyss Tunnel" in page.text
    assert '.usage-detail b{direction:ltr!important;unicode-bidi:isolate!important;display:block!important;text-align:left!important}' in page.text
    assert 'id="abyss-theme-polish"' in page.text
    assert "Portal user" in page.text
    assert "XHTTP" in page.text and "auto" in page.text and "packet-up" in page.text
    assert "stream-up" not in page.text and "stream-one" not in page.text
    assert page.headers["cache-control"] == "no-store"
    assert "noindex, nofollow" in page.headers["x-robots-tag"]

    qr = client.get(info["qr_url"].replace("https://testserver", "http://testserver"))
    assert qr.status_code == 200
    assert "image/svg+xml" in qr.headers["content-type"]
    assert b"<svg" in qr.content
    assert qr.headers["cache-control"] == "no-store"

    paused = client.patch(f"/api/clients/{cid}", json={"enabled": False}, headers={"X-CSRF-Token": csrf})
    assert paused.status_code == 200
    assert client.get(f"/s/{info['url'].rsplit('/', 1)[1]}").status_code == 404
    assert client.get(f"/sub/{info['url'].rsplit('/', 1)[1]}/qr").status_code == 404


def test_edit_client_and_reset_usage(client):
    csrf = admin_client(client)
    headers = {"X-CSRF-Token": csrf}
    created = client.post(
        "/api/clients",
        json={"name": "Before", "duration_days": 7, "quota_gb": 5, "note": "old"},
        headers=headers,
    )
    assert created.status_code == 200
    cid = created.json()["id"]
    with panel.db() as conn:
        conn.execute("UPDATE clients SET used_bytes=? WHERE id=?", (12345, cid))

    edited = client.patch(
        f"/api/clients/{cid}",
        json={"name": "After", "note": "new", "duration_days": 21, "quota_gb": 12},
        headers=headers,
    )
    assert edited.status_code == 200
    row = client.get("/api/overview").json()["clients"][0]
    assert row["name"] == "After"
    assert row["note"] == "new"
    assert row["quota_bytes"] == 12 * 1024**3
    assert row["used_bytes"] == 12345
    assert row["expires_at"]

    reset = client.post(f"/api/clients/{cid}/reset-usage", headers=headers)
    assert reset.status_code == 200
    assert client.get("/api/overview").json()["clients"][0]["used_bytes"] == 0

    unlimited = client.patch(
        f"/api/clients/{cid}",
        json={"duration_days": None, "quota_gb": None},
        headers=headers,
    )
    assert unlimited.status_code == 200
    row = client.get("/api/overview").json()["clients"][0]
    assert row["expires_at"] is None
    assert row["quota_bytes"] is None


def test_failed_revoke_restores_usage_and_limits(client, monkeypatch):
    csrf = admin_client(client)
    headers = {"X-CSRF-Token": csrf}
    created = client.post(
        "/api/clients",
        json={"name": "Rollback metadata", "duration_days": 20, "quota_gb": 7},
        headers=headers,
    )
    cid = created.json()["id"]
    with panel.db() as conn:
        conn.execute("UPDATE clients SET used_bytes=34567 WHERE id=?", (cid,))
    before = client.get("/api/overview").json()["clients"][0]

    calls = {"count": 0}
    async def fail_once_then_recover():
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("simulated Xray failure")
        panel.XRAY_CONFIG.write_text('{"recovered": true}', encoding="utf-8")
    monkeypatch.setattr(panel, "start_xray", fail_once_then_recover)

    response = client.delete(f"/api/clients/{cid}", headers=headers)
    assert response.status_code == 503
    after = client.get("/api/overview").json()["clients"][0]
    assert after["id"] == before["id"]
    assert after["expires_at"] == before["expires_at"]
    assert after["quota_bytes"] == before["quota_bytes"]
    assert after["used_bytes"] == 34567


def test_expiry_monitor_disables_expired_client(client, monkeypatch, tmp_path):
    csrf = admin_client(client)
    created = client.post(
        "/api/clients",
        json={"name": "Expired test"},
        headers={"X-CSRF-Token": csrf},
    )
    cid = created.json()["id"]
    with panel.db() as conn:
        conn.execute("UPDATE clients SET expires_at='2000-01-01T00:00:00+00:00' WHERE id=?", (cid,))

    fake_xray = tmp_path / "xray-expiry"
    fake_xray.write_text("test", encoding="utf-8")
    monkeypatch.setattr(panel, "XRAY_BIN", str(fake_xray))
    class RunningProcess:
        def poll(self): return None
        def terminate(self): return None
    monkeypatch.setattr(panel, "xray_proc", RunningProcess())
    monkeypatch.setattr(panel, "read_xray_stats", lambda: {})
    async def fake_restart(): return None
    monkeypatch.setattr(panel, "start_xray", fake_restart)

    asyncio.run(panel.enforce_client_limits())
    row = client.get("/api/overview").json()["clients"][0]
    assert not row["enabled"]


def test_profile_settings_update_xray_and_subscription(client):
    csrf = admin_client(client)
    headers = {"X-CSRF-Token": csrf}
    created = client.post("/api/clients", json={"name": "Profile test"}, headers=headers)
    assert created.status_code == 200
    cid = created.json()["id"]

    settings = client.get("/api/settings")
    assert settings.status_code == 200
    assert len(settings.json()["profiles"]) == 13
    experimental = {p["key"] for p in panel.PROFILES if p.get("experimental")}
    assert {p["key"] for p in settings.json()["profiles"] if p["enabled"]} == {p["key"] for p in panel.PROFILES} - experimental

    changed = client.patch(
        "/api/settings/profiles",
        json={"profiles": {"ws": False, "xhttp_packet_up": False}},
        headers=headers,
    )
    assert changed.status_code == 200
    assert {p["key"] for p in changed.json()["profiles"] if p["enabled"]} == {"httpupgrade", "xhttp_auto", "trojan_ws", "vmess_ws", "ss_ws", "ws_alt", "httpupgrade_alt"}
    config = panel.make_xray_config()
    assert 10001 not in {i["port"] for i in config["inbounds"]}
    assert 10004 not in {i["port"] for i in config["inbounds"]}

    info = client.get(f"/api/clients/{cid}/subscription").json()
    raw = client.get(info["url"].replace("https://testserver", "http://testserver"))
    links = base64.b64decode(raw.text).decode().splitlines()
    assert len(links) == 7
    # Config names must be stable across protocols: only the AbyssTunnel ID and location flag.
    names = []
    for line in links:
        if line.startswith("vmess://"):
            names.append(json.loads(base64.b64decode(line[len("vmess://"):]))["ps"])
        else:
            names.append(unquote(urlsplit(line).fragment))
    assert names == ["abysstunnel 🇳🇱"] * len(links)
    assert not any("Profile%20test" in line or "Profile test" in line for line in links)
    assert any("mode=auto" in line for line in links)
    query_by_scheme = [urlsplit(line) for line in links if not line.startswith("vmess://")]
    httpupgrade_paths = [u for u in query_by_scheme if "type=httpupgrade" in u.query]
    assert httpupgrade_paths and all("ed=2560" not in u.query and "ed%3D2560" not in u.query for u in httpupgrade_paths)
    inbounds = {item["tag"]: item for item in panel.make_xray_config()["inbounds"]}
    # The Shadowsocks v2ray-plugin URI does not send Xray's WebSocket Early Data header.
    assert "maxEarlyData" not in inbounds["in-ss_ws"]["streamSettings"]["wsSettings"]
    assert "ed=2560" not in next(line for line in links if "ss://" in line)

    rejected = client.patch(
        "/api/settings/profiles",
        json={"profiles": {"httpupgrade": False, "xhttp_auto": False, "xhttp_stream_up": False, "xhttp_stream_one": False, "trojan_ws": False, "vmess_ws": False, "ws_alt": False, "httpupgrade_alt": False, "xhttp_stream_up_alt": False, "xhttp_stream_one_alt": False, "ss_ws": False}},
        headers=headers,
    )
    assert rejected.status_code == 422


def test_profile_settings_roll_back_if_xray_fails(client, monkeypatch):
    csrf = admin_client(client)
    calls = {"count": 0}
    async def fail_once_then_recover():
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("simulated Xray failure")
        panel.XRAY_CONFIG.write_text('{"recovered": true}', encoding="utf-8")
    monkeypatch.setattr(panel, "start_xray", fail_once_then_recover)

    response = client.patch(
        "/api/settings/profiles",
        json={"profiles": {"ws": False}},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 503
    assert panel.get_profile_flags()["ws"] is True
    assert 10001 in {i["port"] for i in panel.make_xray_config()["inbounds"]}
    assert calls["count"] == 2


def test_usage_monitor_enforces_quota(client, monkeypatch, tmp_path):
    csrf = admin_client(client)
    created = client.post(
        "/api/clients",
        json={"name": "Quota test", "quota_gb": 1},
        headers={"X-CSRF-Token": csrf},
    )
    cid = created.json()["id"]
    with panel.db() as conn:
        conn.execute("UPDATE clients SET used_bytes=? WHERE id=?", (1024**3 - 10, cid))

    fake_xray = tmp_path / "xray"
    fake_xray.write_text("test", encoding="utf-8")
    monkeypatch.setattr(panel, "XRAY_BIN", str(fake_xray))
    class RunningProcess:
        def poll(self): return None
        def terminate(self): return None
    monkeypatch.setattr(panel, "xray_proc", RunningProcess())
    monkeypatch.setattr(panel, "read_xray_stats", lambda: {cid: 20})
    async def fake_restart(): return None
    monkeypatch.setattr(panel, "start_xray", fake_restart)

    asyncio.run(panel.enforce_client_limits())
    row = client.get("/api/overview").json()["clients"][0]
    assert row["used_bytes"] == 1024**3 + 10
    assert not row["enabled"]


def test_password_change_removes_initial_credential_file(client, tmp_path):
    csrf = admin_client(client)
    initial_file = tmp_path / "INITIAL_ADMIN_PASSWORD.txt"
    assert initial_file.exists()
    changed = client.post(
        "/api/password",
        json={"current_password": "admin", "new_password": "SecureAbyssPass2026"},
        headers={"X-CSRF-Token": csrf},
    )
    assert changed.status_code == 200
    assert not initial_file.exists()

    client.get("/logout")
    page = client.get("/login")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    response = client.post(
        "/login",
        data={"username": "admin", "password": "SecureAbyssPass2026", "csrf_token": html.unescape(token)},
        follow_redirects=False,
    )
    assert response.status_code == 303


def test_dashboard_has_persian_english_toggle(client):
    csrf = admin_client(client)
    page = client.get("/")
    assert page.status_code == 200
    assert 'lang="fa" dir="rtl"' in page.text
    script = client.get("/dashboard.js")
    assert script.status_code == 200
    assert "toggleLanguage" in script.text
    assert "localStorage.setItem('abyss-lang',lang)" in script.text
    assert "fa:" in script.text and "en:" in script.text


def test_nginx_xhttp_uses_prefix_locations():
    config = (Path(__file__).resolve().parents[1] / "nginx" / "default.conf").read_text(encoding="utf-8")
    assert "location ^~ /xhttp {" in config
    assert "location ^~ /xhttp-packet {" in config
    assert "location = /xhttp {" not in config
    assert "location = /xhttp-packet {" not in config

def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"ok": True, "xray": "running"}


def test_reseller_login_is_scoped_and_cannot_overallocate(client):
    csrf = admin_client(client)
    headers = {"X-CSRF-Token": csrf}
    created = client.post(
        "/api/resellers",
        json={"username": "reseller_one", "password": "StrongPassword123", "quota_gb": 2},
        headers=headers,
    )
    assert created.status_code == 200, created.text
    assert created.json()["quota_bytes"] == 2 * 1024**3

    client.get("/logout")
    page = client.get("/login")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    login = client.post(
        "/login",
        data={"username": "reseller_one", "password": "StrongPassword123", "csrf_token": html.unescape(token)},
        follow_redirects=False,
    )
    assert login.status_code == 303
    csrf = client.get("/api/overview").json()["csrf"]
    headers = {"X-CSRF-Token": csrf}

    own = client.post("/api/clients", json={"name": "Owned", "quota_gb": 1}, headers=headers)
    assert own.status_code == 200, own.text
    assert client.get("/api/overview").json()["total"] == 1
    too_large = client.post("/api/clients", json={"name": "Too large", "quota_gb": 2}, headers=headers)
    assert too_large.status_code == 422

    # A reseller cannot operate on another account's client by guessing its ID.
    assert client.patch("/api/clients/not-owned", json={"enabled": False}, headers=headers).status_code == 404
    # Resellers cannot alter global Xray profiles or download/restore the whole database.
    assert client.patch("/api/settings/profiles", json={"profiles": {"ws": False}}, headers=headers).status_code == 403
    assert client.get("/api/backup").status_code == 403


def test_backup_and_restore_round_trip(client):
    csrf = admin_client(client)
    headers = {"X-CSRF-Token": csrf}
    created = client.post("/api/clients", json={"name": "Backup me", "quota_gb": 2}, headers=headers)
    assert created.status_code == 200
    backup = client.get("/api/backup")
    assert backup.status_code == 200
    assert "application/zip" in backup.headers["content-type"]

    deleted = client.delete(f"/api/clients/{created.json()['id']}", headers=headers)
    assert deleted.status_code == 200
    assert client.get("/api/overview").json()["total"] == 0

    restored = client.post("/api/backup/restore", files={"backup": ("backup.zip", backup.content, "application/zip")}, headers=headers)
    assert restored.status_code == 200, restored.text
    assert client.get("/api/overview").json()["total"] == 1

def test_legacy_sqlite_backup_is_removed_after_download(client):
    admin_client(client)
    before = set(Path(panel.DATA_DIR).glob("abyss-backup-*.sqlite3"))
    backup = client.get("/api/backup/sqlite")
    assert backup.status_code == 200
    assert backup.headers["content-type"].startswith("application/vnd.sqlite3")
    assert backup.content.startswith(b"SQLite format 3")
    after = set(Path(panel.DATA_DIR).glob("abyss-backup-*.sqlite3"))
    assert after == before


def test_nested_reseller_allocation_is_atomic_and_scoped(client):
    csrf = admin_client(client)
    headers = {"X-CSRF-Token": csrf}
    parent = client.post(
        "/api/resellers",
        json={"username": "parent_reseller", "password": "ParentPassword123", "quota_gb": 2},
        headers=headers,
    )
    assert parent.status_code == 200, parent.text

    client.get("/logout")
    page = client.get("/login")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    login = client.post(
        "/login",
        data={"username": "parent_reseller", "password": "ParentPassword123", "csrf_token": html.unescape(token)},
        follow_redirects=False,
    )
    assert login.status_code == 303
    csrf = client.get("/api/overview").json()["csrf"]
    headers = {"X-CSRF-Token": csrf}

    child = client.post(
        "/api/resellers",
        json={"username": "child_reseller", "password": "ChildPassword123", "quota_gb": 1},
        headers=headers,
    )
    assert child.status_code == 200, child.text
    edited = client.patch(
        f"/api/resellers/{child.json()['id']}",
        json={"username": "child_renamed", "password": "ChangedPassword123", "quota_gb": 1},
        headers=headers,
    )
    assert edited.status_code == 200, edited.text
    too_much = client.post(
        "/api/resellers",
        json={"username": "oversized_child", "password": "OtherPassword123", "quota_gb": 1.1},
        headers=headers,
    )
    assert too_much.status_code == 422
    listed = client.get("/api/resellers").json()["resellers"]
    assert listed[0]["id"] == child.json()["id"]
    assert listed[0]["username"] == "child_renamed"

    # Simulate two simultaneous allocation attempts competing for the same
    # final GB. SQLite BEGIN IMMEDIATE must serialize the quota check + insert.
    from concurrent.futures import ThreadPoolExecutor
    def create_one(index):
        return client.post(
            "/api/clients",
            json={"name": f"Concurrent {index}", "quota_gb": 1},
            headers=headers,
        ).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(create_one, range(2)))
    assert sorted(statuses) == [200, 422], statuses
    assert client.get("/api/overview").json()["total"] == 1

    # Parent account suspension must invalidate the child's session too.
    client.get("/logout")
    page = client.get("/login")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    login = client.post(
        "/login",
        data={"username": "child_renamed", "password": "ChangedPassword123", "csrf_token": html.unescape(token)},
        follow_redirects=False,
    )
    assert login.status_code == 303
    child_csrf = client.get("/api/overview").json()["csrf"]
    own_client = client.post(
        "/api/clients",
        json={"name": "Child-owned client", "quota_gb": 1},
        headers={"X-CSRF-Token": child_csrf},
    )
    assert own_client.status_code == 200, own_client.text
    assert client.get("/api/overview").json()["total"] == 1
    over_child_quota = client.post(
        "/api/clients",
        json={"name": "Over child quota", "quota_gb": 1},
        headers={"X-CSRF-Token": child_csrf},
    )
    assert over_child_quota.status_code == 422

    with panel.db() as conn:
        conn.execute("UPDATE resellers SET enabled=0 WHERE id=?", (parent.json()["id"],))
    assert client.get("/api/overview").status_code == 401


def test_restore_rejects_corrupt_database_without_replacing_current(client):
    csrf = admin_client(client)
    headers = {"X-CSRF-Token": csrf}
    created = client.post("/api/clients", json={"name": "Keep me", "quota_gb": 2}, headers=headers)
    assert created.status_code == 200
    before = client.get("/api/overview").json()["total"]
    response = client.post(
        "/api/restore",
        content=b"not a sqlite database",
        headers={**headers, "Content-Type": "application/octet-stream"},
    )
    assert response.status_code == 422
    assert client.get("/api/overview").json()["total"] == before


def test_expiry_is_enforced_while_xray_is_stopped(client, monkeypatch, tmp_path):
    csrf = admin_client(client)
    created = client.post(
        "/api/clients",
        json={"name": "Expired during outage"},
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 200
    cid = created.json()["id"]
    with panel.db() as conn:
        conn.execute("UPDATE clients SET expires_at='2000-01-01T00:00:00+00:00' WHERE id=?", (cid,))
    fake_xray = tmp_path / "xray-not-running"
    fake_xray.write_text("test", encoding="utf-8")
    monkeypatch.setattr(panel, "XRAY_BIN", str(fake_xray))
    monkeypatch.setattr(panel, "xray_proc", None)
    monkeypatch.setattr(panel, "read_xray_stats", lambda: pytest.fail("must not query a stopped Xray process"))
    async def fake_restart():
        return None
    monkeypatch.setattr(panel, "start_xray", fake_restart)

    asyncio.run(panel.enforce_client_limits())
    with panel.db() as conn:
        row = conn.execute("SELECT enabled FROM clients WHERE id=?", (cid,)).fetchone()
    assert row["enabled"] == 0


def test_expired_client_is_not_served_a_subscription(client):
    csrf = admin_client(client)
    created = client.post(
        "/api/clients",
        json={"name": "Expired subscription"},
        headers={"X-CSRF-Token": csrf},
    )
    cid = created.json()["id"]
    with panel.db() as conn:
        conn.execute("UPDATE clients SET expires_at='2000-01-01T00:00:00+00:00' WHERE id=?", (cid,))
        token = conn.execute("SELECT sub_token FROM clients WHERE id=?", (cid,)).fetchone()["sub_token"]
    response = client.get(f"/sub/{token}")
    assert response.status_code == 404


def test_restore_rejects_valid_sqlite_with_incompatible_schema(client, tmp_path):
    csrf = admin_client(client)
    headers = {"X-CSRF-Token": csrf}
    created = client.post("/api/clients", json={"name": "Preserve current DB", "quota_gb": 1}, headers=headers)
    assert created.status_code == 200
    bad_path = tmp_path / "incompatible.sqlite3"
    conn = sqlite3.connect(bad_path)
    try:
        conn.execute("CREATE TABLE admins (id INTEGER PRIMARY KEY, password TEXT)")
        conn.execute("CREATE TABLE clients (id TEXT)")
        conn.execute("CREATE TABLE settings (key TEXT, value TEXT)")
        conn.commit()
    finally:
        conn.close()
    response = client.post(
        "/api/restore",
        content=bad_path.read_bytes(),
        headers={**headers, "Content-Type": "application/octet-stream"},
    )
    assert response.status_code == 422
    assert client.get("/api/overview").json()["total"] == 1


def test_health_reports_stopped_xray_as_unhealthy(client, monkeypatch):
    monkeypatch.setattr(panel, "XRAY_BIN", "/bin/sh")
    monkeypatch.setattr(panel, "xray_proc", None)
    response = client.get("/health")
    assert response.status_code == 503
    assert response.json() == {"ok": False, "xray": "stopped"}


def test_invalid_expiry_metadata_fails_closed():
    assert panel.client_is_expired("not-a-timestamp")
    assert not panel.client_is_expired(None)



def test_client_can_select_multiple_profiles_and_xray_respects_selection(client):
    csrf = admin_client(client)
    response = client.post(
        "/api/clients",
        json={"name": "Profile selection", "profiles": ["ws", "httpupgrade"]},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 200, response.text
    client_id = response.json()["id"]
    rows = {item["tag"]: item for item in panel.make_xray_config()["inbounds"]}
    ws_clients = rows["in-ws"]["settings"]["clients"]
    upgrade_clients = rows["in-httpupgrade"]["settings"]["clients"]
    xhttp_clients = rows["in-xhttp_auto"]["settings"]["clients"]
    assert any(item["email"] == f"client-{client_id}" for item in ws_clients)
    assert any(item["email"] == f"client-{client_id}" for item in upgrade_clients)
    assert not any(item["email"] == f"client-{client_id}" for item in xhttp_clients)


def test_client_profile_selection_rejects_empty_or_unknown_profiles(client):
    csrf = admin_client(client)
    headers = {"X-CSRF-Token": csrf}
    empty = client.post("/api/clients", json={"name": "No profiles", "profiles": []}, headers=headers)
    unknown = client.post("/api/clients", json={"name": "Bad profile", "profiles": ["not-a-profile"]}, headers=headers)
    assert empty.status_code == 422
    assert unknown.status_code == 422



def test_bootstrap_file_never_resets_a_changed_admin_password(client, tmp_path):
    # A bootstrap file may remain on the persistent volume after the owner changes
    # the password. A process restart must not restore the original credential.
    with panel.db() as conn:
        changed_at = panel.utc_now()
        changed_hash = panel.password_hash("changed-password")
        conn.execute(
            "UPDATE panel_admins SET password_hash=?,password_changed_at=? WHERE username='admin'",
            (changed_hash, changed_at),
        )
        conn.execute(
            "UPDATE admins SET password_hash=?,password_changed_at=? WHERE id=1",
            (changed_hash, changed_at),
        )
    panel.init_db()
    with panel.db() as conn:
        owner = conn.execute(
            "SELECT password_hash FROM panel_admins WHERE username='admin'"
        ).fetchone()
    assert panel.verify_password("changed-password", owner["password_hash"])
    assert not panel.verify_password("admin", owner["password_hash"])


def test_global_search_targets_panel_actions_and_keeps_client_filter_separate(client):
    admin_client(client)
    page = client.get("/").text
    assert 'id="globalSearch"' in page
    assert 'placeholder="جست‌وجوی بخش‌ها و ابزارها…"' in page
    assert 'aria-label="جست‌وجوی بخش‌ها و ابزارهای پنل"' in page
    dashboard_js = client.get("/dashboard.js").text
    assert "function renderGlobalSearchResults()" in dashboard_js
    assert "function chooseGlobalSearchResult(index)" in dashboard_js
    assert 'id="search" placeholder="جست‌وجوی نام یا شناسه…"' in page
    assert 'https://github.com/bodisbos-cmd/Void/stargazers' in page
    assert '◇ حمایت از پروژه' in page
    assert "aside.sidebar>.side-brand{display:flex!important;visibility:visible!important;opacity:1!important}" in page
    assert "aside.sidebar>.side-caption.side-caption-top{display:none!important}" in page
    assert "side-brand{gap:7px!important;justify-content:center!important}" not in page
    assert "Small eclipse insignia" not in page
    assert "background:transparent!important;border:0!important;border-radius:0!important;" in page
    assert "aside.sidebar>.abyss-utility-links" in page
