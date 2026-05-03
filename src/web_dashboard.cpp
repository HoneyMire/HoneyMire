#include "web_dashboard.h"
#include "config.h"
#include "wifi_manager.h"
#include "attack_log.h"
#include "storage.h"
#include "ssh_honeypot.h"
#include "intel.h"
#include "attack_classifier.h"

#include <WiFi.h>
#include <ESPAsyncWebServer.h>
#include <ArduinoJson.h>
#include <LittleFS.h>

namespace honeyopus {

static AsyncWebServer s_server(HONEYOPUS_HTTP_PORT);

// ------------------- Page assets (embedded) -------------------

static const char PAGE_HEAD[] PROGMEM = R"HTML(
<!doctype html><html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>HoneyOpus</title>
<style>
:root{--bg:#0e0f13;--fg:#e7e9ee;--mut:#9098a8;--card:#171a21;--acc:#f0b429;--bad:#e94560;--good:#41d693;--bord:#262a35}
*{box-sizing:border-box}body{margin:0;font:14px/1.45 -apple-system,Segoe UI,Roboto,Helvetica,sans-serif;background:var(--bg);color:var(--fg)}
header{padding:14px 18px;border-bottom:1px solid var(--bord);display:flex;justify-content:space-between;align-items:center}
header h1{margin:0;font-size:18px;color:var(--acc)}
nav a{color:var(--fg);text-decoration:none;margin-left:14px;padding:6px 10px;border-radius:6px}
nav a.active{background:#222633}
main{padding:18px;max-width:1100px;margin:0 auto}
.card{background:var(--card);border:1px solid var(--bord);border-radius:10px;padding:14px;margin-bottom:14px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.kpi{background:#1c2029;border:1px solid var(--bord);border-radius:8px;padding:10px}
.kpi b{display:block;font-size:22px;color:var(--acc)}
.kpi span{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:8px 10px;border-bottom:1px solid var(--bord);text-align:left;vertical-align:top}
td.when{white-space:nowrap}
th.c,td.c{text-align:center}
th{color:var(--mut);font-weight:600;text-transform:uppercase;letter-spacing:.05em;font-size:11px}
tr:hover td{background:#1b1f29}
.badge{display:inline-block;padding:1px 7px;border-radius:10px;font-size:11px;color:#0e0f13}
.badge.tn{background:#7ad9ff}.badge.ssh{background:var(--acc)}
.badge.ok{background:var(--good)}.badge.no{background:var(--bad);color:#fff}
form .row{display:grid;grid-template-columns:200px 1fr;gap:10px;align-items:center;margin-bottom:8px}
input,select,textarea{width:100%;background:#0c0d12;color:var(--fg);border:1px solid var(--bord);border-radius:6px;padding:8px 10px;font:13px ui-monospace,Menlo,monospace}
button{background:var(--acc);border:none;color:#0e0f13;font-weight:600;padding:9px 14px;border-radius:6px;cursor:pointer}
button.alt{background:#2a3142;color:var(--fg)}
.meta{color:var(--mut);font-size:12px}
a{color:#7ad9ff}
.flag{font-size:16px;margin-right:6px}
.iconlink{font-size:18px;text-decoration:none;margin-right:8px;line-height:1}
.iconlink:hover{filter:brightness(1.4)}
.repicon{font-size:16px;margin-right:6px;cursor:help}
.repicon.off{filter:grayscale(1) opacity(0.35)}
button.danger{background:var(--bad);color:#fff}
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,0.6);display:none;align-items:center;justify-content:center;z-index:50;backdrop-filter:blur(2px)}
.modal-bg.show{display:flex}
.modal{background:var(--card);border:1px solid var(--bord);border-radius:10px;padding:20px 22px;max-width:460px;width:90%;box-shadow:0 8px 30px rgba(0,0,0,.5)}
.modal h3{margin:0 0 10px;color:var(--bad)}
.modal p{margin:6px 0 16px;color:var(--fg)}
.modal .actions{display:flex;justify-content:flex-end;gap:8px}
.toast{position:fixed;top:14px;left:50%;transform:translateX(-50%);background:var(--good);color:#0e0f13;font-weight:600;padding:10px 18px;border-radius:8px;z-index:60;box-shadow:0 4px 16px rgba(0,0,0,.4)}
details.section{background:#1c2029;border:1px solid var(--bord);border-radius:8px;margin-bottom:10px;overflow:hidden}
details.section>summary{cursor:pointer;padding:12px 14px;font-weight:600;color:var(--acc);list-style:none;display:flex;align-items:center;justify-content:space-between;user-select:none}
details.section>summary::-webkit-details-marker{display:none}
details.section>summary::after{content:'\\25BE';color:var(--mut);transition:transform .2s}
details.section[open]>summary::after{transform:rotate(180deg)}
details.section>.body{padding:12px 14px;border-top:1px solid var(--bord)}
.switch{position:relative;display:inline-block;width:46px;height:24px;cursor:pointer;flex:none}
.switch input{opacity:0;width:0;height:0;position:absolute;margin:0}
.switch .slider{position:absolute;inset:0;background:#3a4055;border-radius:24px;transition:background .15s}
.switch .slider:before{content:'';position:absolute;height:18px;width:18px;left:3px;top:3px;background:#fff;border-radius:50%;transition:transform .15s;box-shadow:0 1px 3px rgba(0,0,0,.4)}
.switch input[type=checkbox]:checked + .slider{background:var(--good)}
.switch input[type=checkbox]:checked + .slider:before{transform:translateX(22px)}
code{font-family:ui-monospace,Menlo,monospace;background:#0c0d12;padding:2px 5px;border-radius:4px}
</style></head><body>
)HTML";

static const char PAGE_NAV[] PROGMEM = R"HTML(
<header>
  <h1><a href="/" style="color:inherit;text-decoration:none">&#127855; HoneyOpus</a></h1>
  <nav>
    <a href="/" id="navHome">Dashboard</a>
    <a href="/config" id="navCfg">Config</a>
    <a href="/sessions" id="navSes">Sessions</a>
  </nav>
</header><main>
)HTML";

static const char PAGE_FOOT[] PROGMEM = R"HTML(
</main></body></html>
)HTML";

// ----------- helpers ------------

static bool authed(AsyncWebServerRequest* req) {
    auto& c = g_config.get();
    if (c.dashboard_user.length() == 0) return true;
    // Skip basic-auth for clients on the local network — owners poking at
    // HoneyOpus from their LAN shouldn't have to enter credentials, and the
    // browser's auth dialog also breaks <a download> + asciinema fetch().
    if (intel_ip_is_private(req->client()->remoteIP().toString())) return true;
    return req->authenticate(c.dashboard_user.c_str(), c.dashboard_pass.c_str());
}

static String flag_emoji(const String& cc) {
    if (cc.length() != 2) return "";
    String out;
    char a = toupper(cc[0]);
    char b = toupper(cc[1]);
    if (a < 'A' || a > 'Z' || b < 'A' || b > 'Z') return "";
    // Regional indicator A=0x1F1E6
    auto append = [&](uint32_t cp) {
        out += (char)(0xF0);
        out += (char)(0x80 | ((cp >> 12) & 0x3F));
        out += (char)(0x80 | ((cp >> 6) & 0x3F));
        out += (char)(0x80 | (cp & 0x3F));
    };
    append(0x1F1E6 + (a - 'A'));
    append(0x1F1E6 + (b - 'A'));
    return out;
}

static String html_escape(const String& s) {
    String out; out.reserve(s.length());
    for (size_t i = 0; i < s.length(); ++i) {
        char c = s[i];
        switch (c) {
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '&': out += "&amp;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default: out += c;
        }
    }
    return out;
}

static String fmt_ts(time_t t) {
    if (t < 1700000000) return "—";
    struct tm tm; localtime_r(&t, &tm);   // honours configTzTime() / cfg.tz
    char buf[48];
    // %z gives the numeric offset (e.g. +0200) so the rendered time is
    // unambiguous even if the user changes TZ later.
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S %z", &tm);
    return String(buf);
}

// ----------- pages ------------

// Renders an "initialization in progress" banner if any subsystem isn't ready
// yet. Returns true if it added anything to the stream.
static bool render_init_banner(AsyncResponseStream* s) {
    bool ssh_enabled = g_config.get().ssh_enabled;
    bool ssh_ready   = ssh_listener_running();
    bool wifi_ok     = wifi_mode() == NetMode::OnlineSTA;
    if (ssh_enabled && !ssh_ready) {
        s->print("<div class='card' style='border-left:4px solid #f0b429'>");
        s->print("<b>HoneyOpus is still initializing.</b> ");
        if (!ssh_hostkey_ready()) {
            s->print("Generating the SSH host key on first boot &mdash; this normally takes ~30 s on ESP32-C3. ");
        } else {
            s->print("SSH host key ready, the listener is binding. ");
        }
        s->print("Telnet captures and the dashboard work right now; SSH will accept connections in a few seconds. ");
        s->print("<span class='meta'>(this page auto-refreshes)</span>");
        s->print("</div>");
        return true;
    }
    if (!wifi_ok) {
        s->print("<div class='card' style='border-left:4px solid #e94560'>");
        s->print("<b>Wi-Fi not in STA mode.</b> Honeypot listeners only run while connected to a real network.");
        s->print("</div>");
        return true;
    }
    return false;
}

static void send_dashboard(AsyncWebServerRequest* req) {
    if (!authed(req)) return req->requestAuthentication();

    auto v = g_attack_log.recent(50);
    size_t total = g_attack_log.count();
    size_t ssh_n = 0, tn_n = 0, authed_n = 0;
    for (auto& e : v) {
        if (e.protocol == "ssh") ssh_n++; else tn_n++;
        if (e.authenticated) authed_n++;
    }

    AsyncResponseStream* s = req->beginResponseStream("text/html; charset=utf-8");
    s->addHeader("Cache-Control", "no-store");
    // Auto-refresh while still initializing so the user sees status flip live.
    bool initializing = (g_config.get().ssh_enabled && !ssh_listener_running()) ||
                        wifi_mode() != NetMode::OnlineSTA;
    if (initializing) s->addHeader("Refresh", "5");

    s->print(FPSTR(PAGE_HEAD));
    s->print(FPSTR(PAGE_NAV));

    render_init_banner(s);

    s->print("<div class='card'><div class='kpis'>");
    s->printf("<div class='kpi'><span>Attacks</span><b>%u</b></div>", (unsigned)total);
    s->printf("<div class='kpi'><span>Telnet</span><b>%u</b></div>", (unsigned)tn_n);
    s->printf("<div class='kpi'><span>SSH</span><b>%u</b></div>", (unsigned)ssh_n);
    s->printf("<div class='kpi'><span>Logged-in</span><b>%u</b></div>", (unsigned)authed_n);
    size_t total_b = storage_total_bytes();
    size_t used_b  = storage_used_bytes();
    size_t free_kb = (total_b > used_b) ? (total_b - used_b) / 1024 : 0;
    s->printf("<div class='kpi'><span>Free flash</span><b>%u KB</b></div>", (unsigned)free_kb);
    s->printf("<div class='kpi'><span>Free heap</span><b>%u KB</b></div>", (unsigned)(ESP.getFreeHeap() / 1024));
    s->print("</div></div>");

    s->print("<div class='card'><h3 style='margin:4px 0 12px'>Recent attacks</h3>");
    if (v.empty()) {
        s->print("<p class='meta'>No attacks captured yet. Telnet listener is on port 23, SSH on port 22. "
                 "Forward those ports from your edge router to this device's IP to start collecting.</p>");
    } else {
        s->print("<table><thead><tr><th class='c'>#</th><th>When</th><th class='c'>Proto</th>"
                 "<th>Source</th><th>Geo</th>"
                 "<th class='c'>Profile</th>"
                 "<th>Creds</th><th class='c'>Auth</th><th class='c'>Cmds</th>"
                 "<th class='c'>Recording</th><th class='c'>Reported</th></tr></thead><tbody>");
        for (auto& e : v) {
            s->printf("<tr><td class='c'>#%u</td><td class='when'>%s</td>", (unsigned)e.id, fmt_ts(e.ts).c_str());
            s->printf("<td class='c'><span class='badge %s'>%s</span></td>",
                      (e.protocol == "ssh" ? "ssh" : "tn"), e.protocol.c_str());
            s->printf("<td><code>%s</code></td>", e.ip.c_str());
            s->print("<td>");
            if (intel_ip_is_private(e.ip)) {
                // 🏠 = U+1F3E0; title attribute provides the text alt for
                // screen readers and hover tooltip.
                s->print("<span class='flag' title='LAN / private network' "
                         "aria-label='LAN'>&#x1F3E0;</span>");
            } else if (e.country_code.length()) {
                String cc = e.country_code; cc.toUpperCase();
                String alt = e.country.length() ? e.country : cc;
                s->printf("<span class='flag' title='%s' aria-label='%s'>%s</span>",
                          html_escape(alt).c_str(), html_escape(cc).c_str(),
                          flag_emoji(e.country_code).c_str());
                s->print(html_escape(e.country));
            } else {
                s->print(html_escape(e.country));
            }
            if (!intel_ip_is_private(e.ip)) {
                if (e.city.length())  { s->print(" · "); s->print(html_escape(e.city)); }
                if (e.isp.length())   { s->printf("<div class='meta'>%s</div>", html_escape(e.isp).c_str()); }
            }
            s->print("</td>");
            // Profile / behavioural fingerprint — icon only; alt/title carry the label.
            {
                auto pv = profile_visual(e.profile);
                s->printf("<td class='c'><span class='flag' title='%s' aria-label='%s'>%s</span></td>",
                          pv.alt, pv.alt, pv.icon);
            }
            s->printf("<td><code>%s</code> / <code>%s</code></td>",
                      html_escape(e.user).c_str(), html_escape(e.pass).c_str());
            s->print(e.authenticated ? "<td class='c'><span class='badge ok'>yes</span></td>"
                                     : "<td class='c'><span class='badge no'>no</span></td>");
            s->printf("<td class='c'>%u</td>", (unsigned)e.commands);
            s->print("<td class='c'>");
            if (e.cast_path.length()) {
                s->printf("<a class='iconlink' href='/play?id=%u' "
                          "title='Play recording in browser' aria-label='Play recording'>&#x25B6;&#xFE0F;</a> "
                          "<a class='iconlink' href='/cast?id=%u' download "
                          "title='Download asciinema .cast file' aria-label='Download .cast'>&#x2B07;&#xFE0F;</a>",
                          (unsigned)e.id, (unsigned)e.id);
            } else s->print("—");
            s->print("</td><td class='c'>");
            // Greyed out via .repicon.off when no report was sent.
            s->printf("<span class='repicon%s' title='AbuseIPDB %s' "
                      "aria-label='AbuseIPDB %s'>&#x1F6E1;&#xFE0F;</span>",
                      e.reported_abuseipdb ? "" : " off",
                      e.reported_abuseipdb ? "reported" : "not reported",
                      e.reported_abuseipdb ? "reported" : "not reported");
            s->printf("<span class='repicon%s' title='AlienVault OTX %s' "
                      "aria-label='OTX %s'>&#x1F989;</span>",
                      e.reported_otx ? "" : " off",
                      e.reported_otx ? "reported" : "not reported",
                      e.reported_otx ? "reported" : "not reported");
            s->print("</td></tr>");
        }
        s->print("</tbody></table>");
    }
    s->print("</div>");

    s->printf("<p class='meta'>HoneyOpus on ESP32-C3 · IP %s · uptime %us · "
              "Telnet %s · SSH %s</p>",
              wifi_ip_string().c_str(),
              (unsigned)(millis() / 1000),
              g_config.get().telnet_enabled ? "on" : "off",
              !g_config.get().ssh_enabled ? "off"
                  : (ssh_listener_running() ? "on" : "starting"));
    s->print(FPSTR(PAGE_FOOT));

    req->send(s);
}

static void send_config_page(AsyncWebServerRequest* req) {
    if (!authed(req)) return req->requestAuthentication();
    auto& c = g_config.get();
    AsyncResponseStream* s = req->beginResponseStream("text/html; charset=utf-8");
    s->print(FPSTR(PAGE_HEAD));
    s->print(FPSTR(PAGE_NAV));
    s->print("<div class='card'><h3>Configuration</h3>"
             "<form method='POST' action='/config'>");
    auto field = [&](const char* label, const char* name, const String& val, const char* type = "text") {
        s->printf("<div class='row'><label>%s</label>"
                  "<input type='%s' name='%s' value='%s'/></div>",
                  label, type, name, html_escape(val).c_str());
    };
    auto checkbox = [&](const char* label, const char* name, bool val) {
        s->printf("<div class='row'><label>%s</label>"
                  "<label class='switch'>"
                  "<input type='hidden' name='%s' value='0'/>"
                  "<input type='checkbox' name='%s' value='1'%s/>"
                  "<span class='slider'></span></label></div>",
                  label, name, name, val ? " checked" : "");
    };
    auto sec_open  = [&](const char* title, bool open = true) {
        s->printf("<details class='section'%s><summary>%s</summary><div class='body'>",
                  open ? " open" : "", title);
    };
    auto sec_close = [&]() { s->print("</div></details>"); };

    sec_open("\xF0\x9F\x93\xB6 Wi-Fi");
    field("WiFi SSID", "wifi_ssid", c.wifi_ssid);
    field("WiFi password", "wifi_pass", c.wifi_pass, "password");
    field("Hostname", "hostname", c.hostname);
    sec_close();

    sec_open("\xF0\x9F\x95\xB7\xEF\xB8\x8F Honeypot");
    checkbox("Telnet enabled", "telnet_enabled", c.telnet_enabled);
    checkbox("SSH enabled", "ssh_enabled", c.ssh_enabled);
    field("Telnet banner", "telnet_banner", c.telnet_banner);
    field("SSH banner", "ssh_banner", c.ssh_banner);
    field("Fake hostname", "fake_hostname", c.fake_hostname);
    field("Fake user", "fake_user", c.fake_user);
    field("Login attempts before accept", "login_attempts_before_accept",
          String((unsigned)c.login_attempts_before_accept), "number");
    sec_close();

    sec_open("\xF0\x9F\x94\x90 Dashboard auth", false);
    field("User", "dashboard_user", c.dashboard_user);
    field("Password", "dashboard_pass", c.dashboard_pass, "password");
    s->print("<p class='meta' style='grid-column:1/3;margin:-4px 0 0'>"
             "Authentication is automatically bypassed for clients on the local network.</p>");
    sec_close();

    sec_open("\xF0\x9F\x8C\x8D Geolocation", false);
    checkbox("GeoIP enabled", "geoip_enabled", c.geoip_enabled);
    field("GeoIP URL ({ip} placeholder)", "geoip_url", c.geoip_url);
    sec_close();

    sec_open("\xF0\x9F\x9B\xA1\xEF\xB8\x8F Threat intelligence reporting", false);
    checkbox("AbuseIPDB", "abuseipdb_enabled", c.abuseipdb_enabled);
    field("AbuseIPDB API key", "abuseipdb_key", c.abuseipdb_key, "password");
    field("AbuseIPDB comment", "abuseipdb_comment", c.abuseipdb_comment);
    checkbox("AlienVault OTX", "otx_enabled", c.otx_enabled);
    field("OTX API key", "otx_key", c.otx_key, "password");
    field("OTX pulse name", "otx_pulse_name", c.otx_pulse_name);
    s->print("<p class='meta' style='grid-column:1/3;margin:-4px 0 0'>"
             "Attacks coming from LAN/private IPs are never reported.</p>");
    sec_close();

    sec_open("\xE2\x8F\xB0 Time &amp; NTP", false);
    field("POSIX TZ string", "tz", c.tz);
    field("NTP server #1", "ntp_server1", c.ntp_server1);
    field("NTP server #2", "ntp_server2", c.ntp_server2);
    field("NTP server #3", "ntp_server3", c.ntp_server3);
    s->print("<p class='meta' style='grid-column:1/3;margin:-4px 0 0'>"
             "Examples: <code>CET-1CEST,M3.5.0,M10.5.0/3</code> (Europe), "
             "<code>EST5EDT,M3.2.0,M11.1.0</code> (US East), "
             "<code>UTC0</code>. Re-applied immediately on save.</p>");
    sec_close();

    sec_open("\xF0\x9F\x96\xA5\xEF\xB8\x8F Display", false);
    field("Display on (s)", "display_on_seconds",
          String((unsigned)c.display_on_seconds), "number");
    field("Attack icon (s)", "attack_icon_seconds",
          String((unsigned)c.attack_icon_seconds), "number");
    sec_close();

    sec_open("\xF0\x9F\x92\xBE Storage", false);
    field("Max sessions kept", "max_sessions",
          String((unsigned)c.max_sessions), "number");
    field("Max attack log entries", "max_attack_entries",
          String((unsigned)c.max_attack_entries), "number");
    field("Max /sessions size (KB, 0=unlimited)", "max_session_dir_kb",
          String((unsigned)c.max_session_dir_kb), "number");
    sec_close();

    s->print("<div class='row'><label></label><div>"
             "<button type='submit'>Save</button> "
             "<button type='button' class='alt' onclick=\"location.href='/'\">Cancel</button>"
             "</div></div></form>");

    // ---- Danger zone ----
    s->print("<h4 style='color:#e94560;margin-top:24px'>Danger zone</h4>"
             "<p class='meta' style='margin:-6px 0 10px'>"
             "Permanently deletes all recorded sessions and attack-log entries. "
             "Configuration (WiFi, API keys, …) is preserved.</p>"
             "<button type='button' class='danger' onclick=\"showClear()\">"
             "&#x1F5D1;&#xFE0F; Clear all attack history</button>");

    s->print("</div>");  // close .card

    // ---- Confirmation modal ----
    s->print(R"HTML(
<div class="modal-bg" id="clearModal">
  <div class="modal" role="dialog" aria-labelledby="clrTitle" aria-modal="true">
    <h3 id="clrTitle">&#x26A0;&#xFE0F; Clear all attack history?</h3>
    <p>This will permanently remove every recorded asciinema session and every
       row in the attack log. Your WiFi, API keys and other settings are kept.</p>
    <p class="meta">This action cannot be undone.</p>
    <div class="actions">
      <button type="button" class="alt" onclick="hideClear()">Cancel</button>
      <button type="button" class="danger" id="clrConfirm" onclick="doClear()">
        Yes, delete everything
      </button>
    </div>
  </div>
</div>
<script>
function showClear(){document.getElementById('clearModal').classList.add('show');}
function hideClear(){document.getElementById('clearModal').classList.remove('show');}
document.addEventListener('keydown',e=>{if(e.key==='Escape')hideClear();});
function doClear(){
  var b=document.getElementById('clrConfirm');b.disabled=true;b.textContent='Clearing…';
  fetch('/admin/clear_history',{method:'POST',credentials:'same-origin'})
    .then(r=>r.ok?r.text():Promise.reject(r.status))
    .then(t=>{
      hideClear();
      var t2=document.createElement('div');t2.className='toast';t2.textContent='History cleared ('+t+' files removed)';
      document.body.appendChild(t2);
      setTimeout(()=>{t2.remove();location.href='/';},1400);
    })
    .catch(err=>{b.disabled=false;b.textContent='Yes, delete everything';
      alert('Clear failed: '+err);});
}
</script>
)HTML");
    s->print(FPSTR(PAGE_FOOT));
    req->send(s);
}

static void handle_config_post(AsyncWebServerRequest* req) {
    if (!authed(req)) return req->requestAuthentication();
    auto& c = g_config.get();
    auto get = [&](const char* n, const String& def = String("")) -> String {
        if (req->hasParam(n, true)) return req->getParam(n, true)->value();
        return def;
    };
    auto getBool = [&](const char* n, bool def) -> bool {
        bool found = false, on = false;
        for (size_t i = 0; i < req->params(); ++i) {
            const AsyncWebParameter* p = req->getParam(i);
            if (!p) continue;
            if (p->isPost() && p->name() == n) {
                found = true;
                if (p->value() == "1") on = true;
            }
        }
        return found ? on : def;
    };
    auto getU16 = [&](const char* n, uint16_t def) -> uint16_t {
        if (req->hasParam(n, true)) return (uint16_t)req->getParam(n, true)->value().toInt();
        return def;
    };
    auto getU8 = [&](const char* n, uint8_t def) -> uint8_t {
        if (req->hasParam(n, true)) return (uint8_t)req->getParam(n, true)->value().toInt();
        return def;
    };
    c.wifi_ssid = get("wifi_ssid", c.wifi_ssid);
    c.wifi_pass = get("wifi_pass", c.wifi_pass);
    c.hostname  = get("hostname",  c.hostname);
    c.telnet_enabled = getBool("telnet_enabled", c.telnet_enabled);
    c.ssh_enabled    = getBool("ssh_enabled", c.ssh_enabled);
    c.telnet_banner  = get("telnet_banner", c.telnet_banner);
    c.ssh_banner     = get("ssh_banner", c.ssh_banner);
    c.fake_hostname  = get("fake_hostname", c.fake_hostname);
    c.fake_user      = get("fake_user", c.fake_user);
    c.login_attempts_before_accept = getU8("login_attempts_before_accept", c.login_attempts_before_accept);
    c.dashboard_user = get("dashboard_user", c.dashboard_user);
    c.dashboard_pass = get("dashboard_pass", c.dashboard_pass);
    c.geoip_enabled  = getBool("geoip_enabled", c.geoip_enabled);
    c.geoip_url      = get("geoip_url", c.geoip_url);
    c.abuseipdb_enabled = getBool("abuseipdb_enabled", c.abuseipdb_enabled);
    c.abuseipdb_key  = get("abuseipdb_key", c.abuseipdb_key);
    c.abuseipdb_comment = get("abuseipdb_comment", c.abuseipdb_comment);
    c.otx_enabled    = getBool("otx_enabled", c.otx_enabled);
    c.otx_key        = get("otx_key", c.otx_key);
    c.otx_pulse_name = get("otx_pulse_name", c.otx_pulse_name);
    String old_tz   = c.tz;
    String old_ntp1 = c.ntp_server1;
    String old_ntp2 = c.ntp_server2;
    String old_ntp3 = c.ntp_server3;
    c.tz                  = get("tz", c.tz);
    c.ntp_server1         = get("ntp_server1", c.ntp_server1);
    c.ntp_server2         = get("ntp_server2", c.ntp_server2);
    c.ntp_server3         = get("ntp_server3", c.ntp_server3);
    c.display_on_seconds  = getU16("display_on_seconds",  c.display_on_seconds);
    c.attack_icon_seconds = getU16("attack_icon_seconds", c.attack_icon_seconds);
    c.max_sessions       = getU16("max_sessions", c.max_sessions);
    c.max_attack_entries = getU16("max_attack_entries", c.max_attack_entries);
    c.max_session_dir_kb = getU16("max_session_dir_kb", c.max_session_dir_kb);
    g_config.save();

    // If TZ or NTP servers changed, re-arm SNTP and re-set the kernel TZ env.
    if (c.tz != old_tz || c.ntp_server1 != old_ntp1 ||
        c.ntp_server2 != old_ntp2 || c.ntp_server3 != old_ntp3) {
        configTzTime(c.tz.c_str(),
                     c.ntp_server1.c_str(),
                     c.ntp_server2.c_str(),
                     c.ntp_server3.c_str());
        Serial.printf("[time] reconfigured tz=%s ntp=%s,%s,%s\n",
                      c.tz.c_str(), c.ntp_server1.c_str(),
                      c.ntp_server2.c_str(), c.ntp_server3.c_str());
    }

    // If wifi creds changed and we're in AP mode, attempt to reconnect.
    if (wifi_mode() == NetMode::FallbackAP && c.wifi_ssid.length()) {
        // Don't tear down AP yet — schedule a reconnect after responding.
        req->onDisconnect([](){ wifi_try_sta(); });
    }

    auto* r = req->beginResponse(303);
    r->addHeader("Location", "/config?saved=1");
    req->send(r);
}

static void handle_clear_history(AsyncWebServerRequest* req) {
    if (!authed(req)) return req->requestAuthentication();
    g_attack_log.clearAll();
    size_t removed = storage_clear_history();
    Serial.printf("[admin] history cleared via web (%u files removed)\n", (unsigned)removed);
    char buf[16];
    snprintf(buf, sizeof(buf), "%u", (unsigned)removed);
    req->send(200, "text/plain", buf);
}

static void send_play_page(AsyncWebServerRequest* req) {
    if (!authed(req)) return req->requestAuthentication();
    if (!req->hasParam("id")) { req->send(400, "text/plain", "missing id"); return; }
    uint32_t id = req->getParam("id")->value().toInt();
    AttackEntry e;
    if (!g_attack_log.getById(id, e) || !e.cast_path.length()) {
        req->send(404, "text/plain", "no cast for id"); return;
    }

    AsyncResponseStream* s = req->beginResponseStream("text/html; charset=utf-8");
    s->print(FPSTR(PAGE_HEAD));
    s->print("<link rel='stylesheet' href='https://cdn.jsdelivr.net/npm/asciinema-player@3.7.1/dist/bundle/asciinema-player.css'/>");
    s->print(FPSTR(PAGE_NAV));
    s->printf("<div class='card'><h3>Session #%u — %s from <code>%s</code></h3>",
              (unsigned)id, e.protocol.c_str(), html_escape(e.ip).c_str());
    s->print("<p class='meta'>");
    s->print(fmt_ts(e.ts)); s->print(" · ");
    s->print(html_escape(e.country));
    if (e.city.length())  { s->print(" · "); s->print(html_escape(e.city)); }
    s->print(" · creds <code>"); s->print(html_escape(e.user));
    s->print("</code>/<code>");  s->print(html_escape(e.pass));
    s->print("</code> · ");      s->print(e.authenticated ? "logged in" : "rejected");
    s->printf(" · %.1fs</p>", e.duration_ms / 1000.0f);
    if (e.pubkeys.length()) {
        s->print("<details class='card' style='margin:8px 0;background:#1a1a2e'>"
                 "<summary>SSH public keys offered (");
        // count lines
        int nk = 1;
        for (size_t i=0;i<e.pubkeys.length();++i) if (e.pubkeys[i]=='\n') nk++;
        s->printf("%d)</summary><pre style='white-space:pre-wrap;word-break:break-all;font-size:11px'>", nk);
        s->print(html_escape(e.pubkeys));
        s->print("</pre></details>");
    }
    s->print("<div id='player' style='margin:8px 0;max-width:880px;font-size:12px'>"
             "<p class='meta'>Loading session…</p></div>");
    s->printf("<p><a class='iconlink' href='/cast?id=%u&dl=1' "
              "title='Download asciinema .cast file' aria-label='Download .cast'>"
              "&#x2B07;&#xFE0F;</a> <span class='meta'>asciinema .cast recording</span></p></div>",
              (unsigned)id);
    s->print("<script src='https://cdn.jsdelivr.net/npm/asciinema-player@3.7.1/dist/bundle/asciinema-player.min.js'></script>");
    // Pre-fetch the cast ourselves with credentials:same-origin — the player's
    // own fetch() doesn't always reattach the HTTP basic-auth header that the
    // browser used for the dashboard page, so its promise gets rejected with
    // 401 and you see "Rejection" in the console.
    s->print("<script>");
    // Visibly surface any promise rejection so the player isn't a silent dead
    // square in the page anymore.
    s->print("window.addEventListener('unhandledrejection',function(ev){"
             "var c=document.getElementById('player');"
             "if(c)c.innerHTML='<p style=\"color:#e94560\">Player error: '"
             "+(ev.reason&&ev.reason.message?ev.reason.message:String(ev.reason))+'</p>';"
             "});");
    s->printf("var cont=document.getElementById('player');"
              "fetch('/cast?id=%u',{credentials:'same-origin',cache:'no-store'})"
              ".then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.text();})"
              ".then(function(data){cont.innerHTML='';"
              "try{AsciinemaPlayer.create({data:data},cont,"
              "{autoPlay:true,fit:'width',terminalFontSize:'11px',terminalLineHeight:1.2,idleTimeLimit:2});}"
              "catch(e){cont.innerHTML='<p style=\"color:#e94560\">Player init failed: '+e.message+'</p>';"
              "console.error('player init',e);}})"
              ".catch(function(err){cont.innerHTML="
              "'<p style=\"color:#e94560\">Failed to load session: '+err.message+'</p>';"
              "console.error('cast fetch failed',err);});",
              (unsigned)id);
    s->print("</script>");
    s->print(FPSTR(PAGE_FOOT));
    req->send(s);
}

static void send_cast(AsyncWebServerRequest* req) {
    if (!authed(req)) return req->requestAuthentication();
    if (!req->hasParam("id")) { req->send(400, "text/plain", "missing id"); return; }
    uint32_t id = req->getParam("id")->value().toInt();
    AttackEntry e;
    if (!g_attack_log.getById(id, e) || !e.cast_path.length() || !LittleFS.exists(e.cast_path)) {
        req->send(404, "text/plain", "not found"); return;
    }
    File f = LittleFS.open(e.cast_path, "r");
    if (!f) { req->send(500, "text/plain", "open failed"); return; }
    size_t sz = f.size();
    // Cap to keep heap safe; casts are tiny by design.
    static const size_t CAST_MAX = 512 * 1024;
    if (sz > CAST_MAX) sz = CAST_MAX;
    String body;
    body.reserve(sz + 1);
    {
        uint8_t buf[512];
        size_t left = sz;
        while (left) {
            size_t n = f.read(buf, left > sizeof(buf) ? sizeof(buf) : left);
            if (!n) break;
            body.concat((const char*)buf, n);
            left -= n;
        }
    }
    f.close();
    bool dl = req->hasParam("dl");
    AsyncWebServerResponse* r = req->beginResponse(200, "application/x-asciicast", body);
    r->addHeader("Cache-Control", "no-store");
    if (dl) {
        String fn = e.cast_path.substring(e.cast_path.lastIndexOf('/') + 1);
        r->addHeader("Content-Disposition", String("attachment; filename=\"") + fn + "\"");
    }
    req->send(r);
}

static void send_sessions_page(AsyncWebServerRequest* req) {
    if (!authed(req)) return req->requestAuthentication();
    auto names = storage_list_dir("/sessions");
    String body;
    body += FPSTR(PAGE_HEAD);
    body += FPSTR(PAGE_NAV);
    body += "<div class='card'><h3>Stored sessions ("; body += names.size(); body += ")</h3><ul>";
    for (auto& n : names) {
        String full = String("/sessions/") + n;
        File f = LittleFS.open(full, "r");
        size_t sz = f ? f.size() : 0;
        if (f) f.close();
        body += "<li><a href='/raw?path="; body += full; body += "'>"; body += n;
        body += "</a> <span class='meta'>"; body += sz; body += " B</span></li>";
    }
    body += "</ul></div>";
    body += FPSTR(PAGE_FOOT);
    req->send(200, "text/html; charset=utf-8", body);
}

static void send_raw(AsyncWebServerRequest* req) {
    if (!authed(req)) return req->requestAuthentication();
    if (!req->hasParam("path")) { req->send(400, "text/plain", "missing path"); return; }
    String p = req->getParam("path")->value();
    if (!p.startsWith("/sessions/") && !p.startsWith("/attacks/")) {
        req->send(403, "text/plain", "forbidden"); return;
    }
    if (!LittleFS.exists(p)) { req->send(404, "text/plain", "not found"); return; }
    File f = LittleFS.open(p, "r");
    if (!f) { req->send(500, "text/plain", "open failed"); return; }
    size_t sz = f.size();
    static const size_t RAW_MAX = 512 * 1024;
    if (sz > RAW_MAX) sz = RAW_MAX;
    String body;
    body.reserve(sz + 1);
    {
        uint8_t buf[512];
        size_t left = sz;
        while (left) {
            size_t n = f.read(buf, left > sizeof(buf) ? sizeof(buf) : left);
            if (!n) break;
            body.concat((const char*)buf, n);
            left -= n;
        }
    }
    f.close();
    String fn = p.substring(p.lastIndexOf('/') + 1);
    AsyncWebServerResponse* r = req->beginResponse(200, "application/x-asciicast", body);
    r->addHeader("Content-Disposition", String("attachment; filename=\"") + fn + "\"");
    req->send(r);
}

static void api_attacks(AsyncWebServerRequest* req) {
    if (!authed(req)) return req->requestAuthentication();
    auto v = g_attack_log.recent(100);
    JsonDocument d;
    JsonArray a = d.to<JsonArray>();
    for (auto& e : v) {
        JsonObject o = a.add<JsonObject>();
        e.toJson(o);
    }
    String body; serializeJson(d, body);
    req->send(200, "application/json", body);
}

static void api_scan(AsyncWebServerRequest* req) {
    int n = WiFi.scanComplete();
    if (n == WIFI_SCAN_FAILED || n == -2) {
        WiFi.scanNetworks(true, false, false, 250);
        req->send(202, "application/json", "{\"scanning\":true}");
        return;
    }
    if (n == WIFI_SCAN_RUNNING) {
        req->send(202, "application/json", "{\"scanning\":true}");
        return;
    }
    JsonDocument d;
    JsonArray a = d["networks"].to<JsonArray>();
    for (int i = 0; i < n && i < 20; ++i) {
        JsonObject o = a.add<JsonObject>();
        o["ssid"] = WiFi.SSID(i);
        o["rssi"] = WiFi.RSSI(i);
        o["enc"]  = (int)WiFi.encryptionType(i);
    }
    String body; serializeJson(d, body);
    WiFi.scanDelete();
    req->send(200, "application/json", body);
}

// -------- Captive portal: setup page --------
static const char PORTAL_HTML[] PROGMEM = R"HTML(
<!doctype html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>HoneyOpus setup</title>
<style>
body{margin:0;background:#0e0f13;color:#e7e9ee;font:14px/1.4 -apple-system,Segoe UI,Roboto,Helvetica,sans-serif}
main{max-width:480px;margin:24px auto;padding:18px}
h1{color:#f0b429;font-size:20px;margin:0 0 14px}
.card{background:#171a21;border:1px solid #262a35;border-radius:10px;padding:14px;margin-bottom:14px}
label{display:block;margin:8px 0 4px;color:#9098a8;font-size:12px;text-transform:uppercase;letter-spacing:.05em}
input,select{width:100%;background:#0c0d12;color:#e7e9ee;border:1px solid #262a35;border-radius:6px;padding:9px 10px;font:14px ui-monospace,Menlo,monospace}
button{margin-top:14px;width:100%;background:#f0b429;border:none;color:#0e0f13;font-weight:600;padding:11px;border-radius:6px;font-size:14px}
.row{display:flex;gap:10px;align-items:center}
.row > *{flex:1}
.meta{color:#9098a8;font-size:12px;margin-top:6px}
.aplist li{cursor:pointer;padding:6px 8px;border-bottom:1px solid #262a35}
.aplist li:hover{background:#1b1f29}
ul{list-style:none;margin:0;padding:0;border:1px solid #262a35;border-radius:6px}
.bar{height:6px;background:#262a35;border-radius:3px;overflow:hidden;margin-top:4px}
.bar>span{display:block;height:100%;background:#41d693}
</style></head><body><main>
<h1>&#127855; HoneyOpus setup</h1>
<div class="card">
  <p class="meta">Pick a network or type an SSID, then enter the password.</p>
  <ul id="aplist" class="aplist"><li class="meta">scanning…</li></ul>
</div>
<div class="card">
  <form method="POST" action="/portal/save">
    <label>SSID</label><input name="wifi_ssid" id="ssid" required>
    <label>Password</label><input name="wifi_pass" id="pass" type="password">
    <label>Hostname</label><input name="hostname" value="honeyopus">
    <button type="submit">Connect</button>
  </form>
</div>
<div class="card meta">After saving, HoneyOpus will reboot and join your network. Find it via the IP shown on the OLED, or http://honeyopus.local/.</div>
</main>
<script>
function refresh(){fetch('/api/scan').then(r=>r.json()).then(j=>{
  if(j.scanning){setTimeout(refresh,1500);return;}
  var u=document.getElementById('aplist');u.innerHTML='';
  (j.networks||[]).sort((a,b)=>b.rssi-a.rssi).forEach(n=>{
    var li=document.createElement('li');
    var bar=Math.max(0,Math.min(100,2*(n.rssi+100)));
    li.innerHTML='<b>'+n.ssid+'</b>'+(n.enc?' &#128274;':'')+'<div class=bar><span style=width:'+bar+'%></span></div>';
    li.onclick=()=>{document.getElementById('ssid').value=n.ssid;document.getElementById('pass').focus();};
    u.appendChild(li);
  });
});}refresh();
</script></body></html>
)HTML";

static void send_portal(AsyncWebServerRequest* req) {
    auto* r = req->beginResponse_P(200, "text/html; charset=utf-8", PORTAL_HTML);
    r->addHeader("Cache-Control", "no-store");
    req->send(r);
}

static void portal_save(AsyncWebServerRequest* req) {
    auto& c = g_config.get();
    if (req->hasParam("wifi_ssid", true)) c.wifi_ssid = req->getParam("wifi_ssid", true)->value();
    if (req->hasParam("wifi_pass", true)) c.wifi_pass = req->getParam("wifi_pass", true)->value();
    if (req->hasParam("hostname", true) && req->getParam("hostname", true)->value().length())
        c.hostname = req->getParam("hostname", true)->value();
    g_config.save();
    String body = "<!doctype html><meta charset='utf-8'><title>Saved</title>"
                  "<body style='font-family:sans-serif;background:#0e0f13;color:#e7e9ee;padding:24px'>"
                  "<h2 style='color:#f0b429'>Saved</h2>"
                  "<p>HoneyOpus is rebooting and joining <b>" + html_escape(c.wifi_ssid) +
                  "</b>. Reconnect to your normal network and look for it on the LAN.</p></body>";
    req->send(200, "text/html; charset=utf-8", body);
    req->onDisconnect([](){
        delay(500);
        ESP.restart();
    });
}

// Captive portal redirect handler: any URL while in AP mode -> /portal.
class CaptiveHandler : public AsyncWebHandler {
public:
    bool canHandle(AsyncWebServerRequest* req) override {
        if (wifi_mode() != NetMode::FallbackAP) return false;
        String h = req->host();
        if (h == WiFi.softAPIP().toString()) return false;
        return true;
    }
    void handleRequest(AsyncWebServerRequest* req) override {
        auto* r = req->beginResponse(302, "text/plain", "captive");
        r->addHeader("Location", String("http://") + WiFi.softAPIP().toString() + "/portal");
        req->send(r);
    }
};

void web_begin() {
    s_server.on("/",          HTTP_GET,  send_dashboard);
    s_server.on("/config",    HTTP_GET,  send_config_page);
    s_server.on("/config",    HTTP_POST, handle_config_post);
    s_server.on("/admin/clear_history", HTTP_POST, handle_clear_history);
    s_server.on("/sessions",  HTTP_GET,  send_sessions_page);
    s_server.on("/raw",       HTTP_GET,  send_raw);
    s_server.on("/cast",      HTTP_GET,  send_cast);
    s_server.on("/play",      HTTP_GET,  send_play_page);
    s_server.on("/api/attacks", HTTP_GET, api_attacks);
    s_server.on("/api/scan",  HTTP_GET,  api_scan);

    s_server.on("/portal",    HTTP_GET,  send_portal);
    s_server.on("/portal/save", HTTP_POST, portal_save);

    // Captive-portal probe URLs: respond 204 in STA mode (real internet)
    // and 302 in AP mode (handled by CaptiveHandler below).
    auto probe = [](AsyncWebServerRequest* r) { r->send(204); };
    s_server.on("/generate_204", HTTP_GET, probe);
    s_server.on("/gen_204",      HTTP_GET, probe);
    s_server.on("/hotspot-detect.html", HTTP_GET, [](AsyncWebServerRequest* r){
        r->send(200, "text/html", "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>");
    });

    s_server.addHandler(new CaptiveHandler());

    s_server.onNotFound([](AsyncWebServerRequest* req) {
        if (wifi_mode() == NetMode::FallbackAP) {
            auto* r = req->beginResponse(302, "text/plain", "captive");
            r->addHeader("Location", String("http://") + WiFi.softAPIP().toString() + "/portal");
            req->send(r);
            return;
        }
        req->send(404, "text/plain", "not found");
    });

    s_server.begin();
    Serial.printf("[web] http://%s/ (AP fallback http://%s/portal)\n",
                  WiFi.localIP().toString().c_str(),
                  WiFi.softAPIP().toString().c_str());
}

} // namespace honeyopus
