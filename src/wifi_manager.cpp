#include "wifi_manager.h"
#include "config.h"
#include "display.h"
#include "restart_reason.h"

#include <WiFi.h>
#include <DNSServer.h>
#include <WiFiClient.h>

namespace honeyopus {

static NetMode s_mode = NetMode::Boot;
static String s_ap_ssid;
static String s_ap_pass = "honeyopus";
static uint32_t s_last_attempt = 0;
static uint32_t s_attempts = 0;
static DNSServer s_dns;
static bool s_dns_running = false;
// Tracks the last time we observed a healthy network (STA connected OR
// running as fallback AP). Used to reboot after a prolonged total outage,
// which is the only reliable way to recover from rare LWIP/Wi-Fi-driver
// states that AutoReconnect + WiFi.begin can't unwedge.
static uint32_t s_last_healthy = 0;
static const uint32_t kWifiOutageRebootMs = 3 * 60 * 1000;
// Outbound connectivity probe — catches the "associated but no traffic"
// failure mode where WiFi.status() == WL_CONNECTED but LWIP can't actually
// route packets (e.g. after certain router-side deauths).
static const uint32_t kProbeIntervalMs = 60 * 1000;
static const uint32_t kProbeTimeoutMs  = 3000;
static const uint8_t  kProbeFailLimit  = 3;
static uint32_t s_last_probe = 0;
static uint8_t  s_probe_fails = 0;
static volatile bool s_event_disconnected = false;
// Last STA disconnect reason captured by the event handler. Logged once
// from wifi_loop() when it changes — the event handler runs on the WiFi
// task and must stay short. Reasons are documented in
// esp_wifi_types.h::wifi_err_reason_t (e.g. 2=AUTH_EXPIRE, 6=NOT_AUTHED,
// 8=ASSOC_LEAVE, 15=4WAY_HANDSHAKE_TIMEOUT, 200/201/202=AUTH_FAIL).
static volatile uint8_t s_last_disc_reason   = 0;
static volatile bool    s_last_disc_logged   = true;
// On boot we don't yet have a reason to report; flip false the first
// time the handler captures one so wifi_loop() can surface it.

NetMode wifi_mode() { return s_mode; }
String wifi_ip_string() {
    if (s_mode == NetMode::FallbackAP) return WiFi.softAPIP().toString();
    return WiFi.localIP().toString();
}
String wifi_ap_ssid() { return s_ap_ssid; }

static void on_wifi_event_(WiFiEvent_t event, WiFiEventInfo_t info) {
    switch (event) {
        case ARDUINO_EVENT_WIFI_STA_DISCONNECTED:
            // Flag for the loop task — keep the handler short, it runs on
            // the WiFi event task and must not call WiFi.begin() directly.
            s_event_disconnected = true;
            s_last_disc_reason = info.wifi_sta_disconnected.reason;
            s_last_disc_logged = false;
            break;
        case ARDUINO_EVENT_WIFI_STA_GOT_IP:
            s_event_disconnected = false;
            s_probe_fails = 0;
            s_last_healthy = millis();
            break;
        default:
            break;
    }
}

// Map a wifi_err_reason_t value to a short human label. Covers the
// codes we actually see in the field — auth failure, deauth, beacon
// timeout, handshake timeout, AP not found, plus a generic fallback.
static const char* disc_reason_label_(uint8_t reason) {
    switch (reason) {
        case 1:   return "UNSPECIFIED";
        case 2:   return "AUTH_EXPIRE";
        case 3:   return "AUTH_LEAVE";
        case 4:   return "ASSOC_EXPIRE";
        case 5:   return "ASSOC_TOOMANY";
        case 6:   return "NOT_AUTHED";
        case 7:   return "NOT_ASSOCED";
        case 8:   return "ASSOC_LEAVE";
        case 15:  return "4WAY_HANDSHAKE_TIMEOUT";
        case 16:  return "GROUP_KEY_UPDATE_TIMEOUT";
        case 200: return "BEACON_TIMEOUT";
        case 201: return "NO_AP_FOUND";
        case 202: return "AUTH_FAIL";
        case 203: return "ASSOC_FAIL";
        case 204: return "HANDSHAKE_TIMEOUT";
        case 205: return "CONNECTION_FAIL";
        default:  return "?";
    }
}

static bool probe_outbound_() {
    // Cheap "is the upstream really reachable" check: a short TCP connect
    // to the default gateway on port 53 (every consumer router answers).
    // Falls back to 1.1.1.1 if no gateway is known yet.
    IPAddress target = WiFi.gatewayIP();
    if (target == IPAddress(0,0,0,0)) target = IPAddress(1,1,1,1);
    WiFiClient c;
    c.setTimeout(kProbeTimeoutMs / 1000);
    bool ok = c.connect(target, 53, kProbeTimeoutMs);
    c.stop();
    return ok;
}

static void start_ap_() {
    String mac = WiFi.macAddress();
    mac.replace(":", "");
    s_ap_ssid = String("HoneyOpus-") + mac.substring(8);
    WiFi.mode(WIFI_AP);
    // softAPConfig() MUST come before softAP() — calling it after has been
    // observed on certain arduino-esp32 versions to leave the AP listening
    // on the framework default (192.168.4.1 most of the time, but not
    // always) and the captive portal then advertises the wrong IP. See
    // ESP32 stability review W5.
    IPAddress ap_ip(192, 168, 4, 1);
    IPAddress ap_nm(255, 255, 255, 0);
    WiFi.softAPConfig(ap_ip, ap_ip, ap_nm);
    WiFi.softAP(s_ap_ssid.c_str(), s_ap_pass.c_str());
    if (s_dns_running) { s_dns.stop(); s_dns_running = false; }
    s_dns.setErrorReplyCode(DNSReplyCode::NoError);
    s_dns.start(53, "*", ap_ip);
    s_dns_running = true;
    s_mode = NetMode::FallbackAP;
    Serial.printf("[wifi] AP up SSID=%s pass=%s ip=%s\n",
                  s_ap_ssid.c_str(), s_ap_pass.c_str(), ap_ip.toString().c_str());
    g_display.showStatus("AP MODE", s_ap_ssid, ap_ip.toString());
    g_display.wakeFromButton();
}

void wifi_force_ap() { start_ap_(); }

void wifi_try_sta() {
    auto& cfg = g_config.get();
    if (cfg.wifi_ssid.length() == 0) {
        start_ap_();
        return;
    }
    if (s_dns_running) { s_dns.stop(); s_dns_running = false; }
    WiFi.mode(WIFI_STA);
    WiFi.setHostname(cfg.hostname.c_str());
    WiFi.begin(cfg.wifi_ssid.c_str(), cfg.wifi_pass.c_str());
    s_mode = NetMode::ConnectingSTA;
    s_attempts++;
    s_last_attempt = millis();
    Serial.printf("[wifi] connecting to %s (attempt %u)\n",
                  cfg.wifi_ssid.c_str(), (unsigned)s_attempts);
    g_display.showStatus("WiFi...", cfg.wifi_ssid);
}

void wifi_begin() {
    WiFi.persistent(false);
    WiFi.setAutoReconnect(true);
    WiFi.onEvent(on_wifi_event_);
    s_last_healthy = millis();
    s_last_probe = millis();
    s_probe_fails = 0;
    s_event_disconnected = false;
    wifi_try_sta();
}

void wifi_loop() {
    if (s_dns_running) s_dns.processNextRequest();

    auto status = WiFi.status();

    // Surface the last STA disconnect reason exactly once per occurrence.
    // Lets the operator distinguish "wrong password" (AUTH_FAIL) from
    // "router rebooted" (BEACON_TIMEOUT) from "AP gone" (NO_AP_FOUND)
    // without grepping ESP-IDF headers. See ESP32 stability review W1.
    if (!s_last_disc_logged) {
        uint8_t r = s_last_disc_reason;
        s_last_disc_logged = true;
        Serial.printf("[wifi] STA disconnect reason=%u (%s)\n",
                      (unsigned)r, disc_reason_label_(r));
    }

    // Event-driven disconnect path — fires immediately on Reason 6/8/15
    // etc., without waiting for status() polling to catch up.
    if (s_event_disconnected && s_mode == NetMode::OnlineSTA) {
        Serial.println("[wifi] event: STA disconnected, forcing reconnect");
        s_mode = NetMode::ConnectingSTA;
        s_attempts = 0;
        s_event_disconnected = false;
        WiFi.disconnect(false, true);
        wifi_try_sta();
        return;
    }

    if (s_mode == NetMode::ConnectingSTA) {
        if (status == WL_CONNECTED) {
            s_mode = NetMode::OnlineSTA;
            s_last_healthy = millis();
            s_last_probe = millis();
            s_probe_fails = 0;
            Serial.printf("[wifi] STA connected ip=%s\n", WiFi.localIP().toString().c_str());
            g_display.showStatus("Online", g_config.get().wifi_ssid, WiFi.localIP().toString());
            g_display.wakeFromButton();
        } else if (millis() - s_last_attempt > 25000) {
            // give up STA attempts, drop to AP after 3
            if (s_attempts >= 3) start_ap_();
            else wifi_try_sta();
        }
    } else if (s_mode == NetMode::OnlineSTA) {
        if (status != WL_CONNECTED) {
            // Will auto-reconnect; if that fails for 30 s, fall back.
            if (millis() - s_last_attempt > 30000) {
                Serial.println("[wifi] STA lost, retrying...");
                // Force a clean STA stack — AutoReconnect alone has been
                // observed to silently stay in WL_DISCONNECTED forever after
                // certain router-side de-auths (e.g. Reason 6 NOT_AUTHED).
                WiFi.disconnect(false, true);
                s_attempts = 0;
                wifi_try_sta();
            }
        } else {
            s_last_attempt = millis();
            // Only update s_last_healthy on a positive probe (or right
            // after GOT_IP, handled in the event callback). Letting
            // status()==WL_CONNECTED alone refresh it is what hid 6 hours
            // of LWIP-stuck silence in the wild.
            // Outbound probe is observability-only by default. Many
            // routers don't accept TCP/53 on the gateway IP, so a
            // fail-count threshold would kick perfectly healthy
            // networks every few minutes (W4 in the stability review).
            // Operators who want the historical "kick STA on probe
            // fails" behaviour can enable wifi_probe_kick.
            const auto& cfg = g_config.get();
            if (cfg.wifi_probe_enabled &&
                millis() - s_last_probe > kProbeIntervalMs) {
                s_last_probe = millis();
                if (probe_outbound_()) {
                    s_probe_fails = 0;
                    s_last_healthy = millis();
                } else {
                    s_probe_fails++;
                    Serial.printf("[wifi] probe failed (%u/%u) gw=%s%s\n",
                                  (unsigned)s_probe_fails, (unsigned)kProbeFailLimit,
                                  WiFi.gatewayIP().toString().c_str(),
                                  cfg.wifi_probe_kick ? "" : " (observability-only)");
                    if (cfg.wifi_probe_kick && s_probe_fails >= kProbeFailLimit) {
                        Serial.println("[wifi] probe-stuck — kicking STA");
                        s_probe_fails = 0;
                        WiFi.disconnect(false, true);
                        s_mode = NetMode::ConnectingSTA;
                        s_attempts = 0;
                        wifi_try_sta();
                    }
                }
            }
        }
    } else if (s_mode == NetMode::FallbackAP) {
        // AP itself counts as healthy — admin can still reach the
        // dashboard from the SoftAP SSID.
        s_last_healthy = millis();
    }

    // Last-resort self-heal. If we've spent kWifiOutageRebootMs with neither
    // a working STA association nor an AP up, reboot. This is a deliberate
    // sledgehammer for the rare cases where WiFi.begin() / AutoReconnect
    // get stuck in an unrecoverable state and the device would otherwise
    // need manual power-cycling.
    if (s_last_healthy != 0 &&
        (millis() - s_last_healthy) > kWifiOutageRebootMs) {
        Serial.printf("[wifi] outage > %u s, rebooting to recover\n",
                      (unsigned)(kWifiOutageRebootMs / 1000));
        restart::restart_with(restart::kReasonWifiOutage);
    }
}

} // namespace honeyopus
