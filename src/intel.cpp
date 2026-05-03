#include "intel.h"
#include "config.h"
#include "geoip.h"

#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <ArduinoJson.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/task.h>

namespace honeyopus {

// RFC1918 / loopback / link-local / CGNAT / IPv6 ULA & link-local. We never
// report these to public threat-intel feeds — submitting LAN addresses pollutes
// the dataset and can get the API key revoked.
bool intel_ip_is_private(const String& ip) {
    if (ip.length() == 0) return true;
    if (ip == "::1" || ip.startsWith("127.")) return true;
    if (ip.startsWith("10.")) return true;
    if (ip.startsWith("192.168.")) return true;
    if (ip.startsWith("169.254.")) return true;
    if (ip.startsWith("100.")) {
        int second = ip.substring(4).toInt();
        if (second >= 64 && second <= 127) return true;
    }
    if (ip.startsWith("172.")) {
        int second = ip.substring(4).toInt();
        if (second >= 16 && second <= 31) return true;
    }
    if (ip.startsWith("0.")) return true;
    if (ip.startsWith("224.") || ip.startsWith("239.")) return true;
    String low = ip; low.toLowerCase();
    if (low.startsWith("fe80:") || low.startsWith("fe80::")) return true;
    if (low.length() && (low[0] == 'f' && (low[1] == 'c' || low[1] == 'd'))) return true;
    if (low.startsWith("ff")) return true;
    return false;
}

static QueueHandle_t s_q = nullptr;

bool intel_report_abuseipdb(AttackEntry& e) {
    auto& cfg = g_config.get();
    if (!cfg.abuseipdb_enabled || cfg.abuseipdb_key.length() == 0) return false;
    if (e.reported_abuseipdb) return true;
    if (intel_ip_is_private(e.ip)) {
        Serial.printf("[abuseipdb] skip private/LAN ip=%s\n", e.ip.c_str());
        return false;
    }

    WiFiClientSecure cs;
    cs.setInsecure();
    HTTPClient http;
    if (!http.begin(cs, "https://api.abuseipdb.com/api/v2/report")) return false;
    http.addHeader("Key", cfg.abuseipdb_key);
    http.addHeader("Accept", "application/json");
    http.addHeader("Content-Type", "application/x-www-form-urlencoded");
    http.setTimeout(10000);

    // Categories per AbuseIPDB taxonomy: 18=Brute-Force, 22=SSH, 23=IoT Targeted.
    // For Telnet attacks 14=Port Scan and 15=Hacking are also useful, but 18+23 are the
    // most descriptive and supported on every account tier.
    String cats = (e.protocol == "ssh") ? "18,22,23" : "18,23";
    String body = "ip=" + e.ip;
    body += "&categories=" + cats;
    body += "&comment=";
    String comment = cfg.abuseipdb_comment;
    comment += " [proto=" + e.protocol + " user=" + e.user + "]";
    // URL-encode comment minimally.
    for (size_t i = 0; i < comment.length(); ++i) {
        char c = comment[i];
        if (isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.' || c == '~') body += c;
        else if (c == ' ') body += '+';
        else { char buf[4]; snprintf(buf, sizeof(buf), "%%%02X", (unsigned char)c); body += buf; }
    }

    int code = http.POST(body);
    String resp = http.getString();
    http.end();
    if (code >= 200 && code < 300) {
        e.reported_abuseipdb = true;
        Serial.printf("[abuseipdb] %s reported, http=%d\n", e.ip.c_str(), code);
        return true;
    }
    Serial.printf("[abuseipdb] failed http=%d resp=%s\n", code, resp.c_str());
    return false;
}

bool intel_report_otx(AttackEntry& e) {
    auto& cfg = g_config.get();
    if (!cfg.otx_enabled || cfg.otx_key.length() == 0) return false;
    if (e.reported_otx) return true;
    if (intel_ip_is_private(e.ip)) {
        Serial.printf("[otx] skip private/LAN ip=%s\n", e.ip.c_str());
        return false;
    }

    WiFiClientSecure cs;
    cs.setInsecure();
    HTTPClient http;
    if (!http.begin(cs, "https://otx.alienvault.com/api/v1/pulses/create")) return false;
    http.addHeader("X-OTX-API-KEY", cfg.otx_key);
    http.addHeader("Content-Type", "application/json");
    http.setTimeout(10000);

    JsonDocument d;
    d["name"] = cfg.otx_pulse_name + " — " + e.ip;
    String desc = "ESP32-C3 honeypot capture. Protocol=";
    desc += e.protocol; desc += " user="; desc += e.user;
    if (e.country.length()) { desc += " country="; desc += e.country_code; }
    d["description"] = desc;
    d["public"] = false;
    JsonArray tlp = d["tags"].to<JsonArray>();
    tlp.add("honeypot"); tlp.add("brute-force"); tlp.add(e.protocol.c_str());
    JsonArray inds = d["indicators"].to<JsonArray>();
    JsonObject i = inds.add<JsonObject>();
    i["indicator"] = e.ip;
    i["type"] = "IPv4";
    i["description"] = "Brute-force source captured by HoneyOpus";

    String body;
    serializeJson(d, body);
    int code = http.POST(body);
    String resp = http.getString();
    http.end();
    if (code >= 200 && code < 300) {
        e.reported_otx = true;
        Serial.printf("[otx] %s reported, http=%d\n", e.ip.c_str(), code);
        return true;
    }
    Serial.printf("[otx] failed http=%d resp=%s\n", code, resp.c_str());
    return false;
}

void intel_report_all(AttackEntry& e) {
    intel_report_abuseipdb(e);
    intel_report_otx(e);
}

static void intelTask_(void*) {
    uint32_t id;
    for (;;) {
        if (xQueueReceive(s_q, &id, portMAX_DELAY) != pdTRUE) continue;
        AttackEntry e;
        if (!g_attack_log.getById(id, e)) continue;
        if (!e.geo_resolved && g_config.get().geoip_enabled) geoip_lookup(e);
        intel_report_all(e);
        g_attack_log.update(e);
    }
}

void intel_begin() {
    if (s_q) return;
    s_q = xQueueCreate(8, sizeof(uint32_t));
    xTaskCreatePinnedToCore(intelTask_, "intel", 8192, nullptr, 1, nullptr, tskNO_AFFINITY);
}

void intel_enqueue(uint32_t id) {
    if (!s_q) return;
    xQueueSend(s_q, &id, 0);
}

} // namespace honeyopus
