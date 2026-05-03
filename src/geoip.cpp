#include "geoip.h"
#include "config.h"

#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <ArduinoJson.h>

namespace honeyopus {

bool geoip_lookup(AttackEntry& e) {
    auto& cfg = g_config.get();
    if (!cfg.geoip_enabled) return false;

    String url = cfg.geoip_url;
    int idx = url.indexOf("{ip}");
    if (idx < 0) {
        if (url.endsWith("/")) url += e.ip;
        else url += "/" + e.ip;
    } else {
        url = url.substring(0, idx) + e.ip + url.substring(idx + 4);
    }

    HTTPClient http;
    bool ok = false;
    if (url.startsWith("https://")) {
        WiFiClientSecure cs;
        cs.setInsecure();
        ok = http.begin(cs, url);
    } else {
        ok = http.begin(url);
    }
    if (!ok) return false;
    http.setTimeout(8000);
    int code = http.GET();
    if (code != 200) {
        http.end();
        return false;
    }
    String body = http.getString();
    http.end();

    JsonDocument d;
    if (deserializeJson(d, body) != DeserializationError::Ok) return false;

    // ip-api.com uses "status":"success"; ipapi.co/co just returns fields.
    String status = (const char*)(d["status"] | "");
    if (status.length() && status != "success") return false;

    // Try common field names across providers.
    auto pick = [&](std::initializer_list<const char*> keys) -> String {
        for (auto k : keys) {
            const char* v = d[k] | (const char*)nullptr;
            if (v && *v) return String(v);
        }
        return String("");
    };
    e.country      = pick({"country", "country_name"});
    e.country_code = pick({"countryCode", "country_code", "country"});
    if (e.country_code.length() > 3) e.country_code = e.country_code.substring(0, 2);
    e.city         = pick({"city"});
    e.region       = pick({"regionName", "region", "state"});
    e.isp          = pick({"isp", "org"});
    e.asn          = pick({"as", "asn"});
    if (d["lat"].is<float>())  e.lat = d["lat"].as<float>();
    if (d["lon"].is<float>())  e.lon = d["lon"].as<float>();
    if (d["latitude"].is<float>())  e.lat = d["latitude"].as<float>();
    if (d["longitude"].is<float>()) e.lon = d["longitude"].as<float>();
    e.geo_resolved = e.country.length() || e.city.length() || e.lat != 0;
    return e.geo_resolved;
}

} // namespace honeyopus
