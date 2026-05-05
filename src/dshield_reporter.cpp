#include "dshield_reporter.h"
#include "config.h"
#include <HTTPClient.h>

namespace honeyopus {

static void dshield_submit_task(void* arg) {
    auto* entry_copy = (AttackEntry*)arg;
    auto& cfg = g_config.get();
    
    if (!cfg.dshield_enabled || cfg.dshield_email.length() == 0 || cfg.dshield_apikey.length() == 0) {
        delete entry_copy;
        vTaskDelete(nullptr);
        return;
    }

    // Build JSON payload for DShield
    // DShield expects email, apikey, and log data
    String json = "{";
    json += "\"email\":\"" + cfg.dshield_email + "\",";
    json += "\"apikey\":\"" + cfg.dshield_apikey + "\",";
    json += "\"format\":\"json\",";
    json += "\"log\":{";
    json += "\"timestamp\":\"" + String(entry_copy->ts) + "\",";
    json += "\"src_ip\":\"" + entry_copy->ip + "\",";
    json += "\"dst_port\":" + String(entry_copy->port) + ",";
    json += "\"protocol\":\"" + entry_copy->protocol + "\",";
    json += "\"username\":\"" + entry_copy->user + "\",";
    json += "\"authenticated\":" + String(entry_copy->authenticated ? "true" : "false") + ",";
    json += "\"attempts\":" + String(entry_copy->auth_attempts) + ",";
    json += "\"commands\":" + String(entry_copy->commands);
    json += "}}";

    HTTPClient http;
    http.setConnectTimeout(5000);
    http.setTimeout(10000);
    
    if (http.begin("https://dshield.org/api/handler/submit/")) {
        http.addHeader("Content-Type", "application/json");
        int httpCode = http.POST(json);
        
        if (httpCode == HTTP_CODE_OK || httpCode == HTTP_CODE_CREATED) {
            Serial.printf("[dshield] submitted attack id=%u ip=%s\n",
                          (unsigned)entry_copy->id, entry_copy->ip.c_str());
        } else {
            Serial.printf("[dshield] submission failed id=%u ip=%s http=%d\n",
                          (unsigned)entry_copy->id, entry_copy->ip.c_str(), httpCode);
        }
        http.end();
    } else {
        Serial.printf("[dshield] connection failed id=%u ip=%s\n",
                      (unsigned)entry_copy->id, entry_copy->ip.c_str());
    }
    
    delete entry_copy;
    vTaskDelete(nullptr);
}

bool DShieldReporter::submit(const AttackEntry& entry) {
    if (!g_config.get().dshield_enabled) return true;
    
    // Spawn background task so we don't block the attack logger
    auto* entry_copy = new AttackEntry(entry);
    if (xTaskCreatePinnedToCore(dshield_submit_task, "dshield",
                                4096, entry_copy, 5, nullptr, PRO_CPU_NUM) != pdPASS) {
        delete entry_copy;
        Serial.printf("[dshield] task creation failed\n");
        return false;
    }
    return true;
}

bool DShieldReporter::isConfigured() {
    auto& cfg = g_config.get();
    return cfg.dshield_enabled && cfg.dshield_email.length() > 0 && cfg.dshield_apikey.length() > 0;
}

} // namespace honeyopus
