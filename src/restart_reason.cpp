#include "restart_reason.h"

#include <Preferences.h>

namespace honeyopus {
namespace restart {

// NVS namespace + key shape:
//   "rstr" / "last"            → last reason label (string)
//   "rstr" / "last_uptime"     → uptime in seconds at the moment of restart
//   "rstr" / "<reason>_n"      → per-reason counter (uint32_t)
//   "rstr" / "total"           → sum of all reason counters
// Keys stay under the 15-char NVS limit.
static const char* kNs = "rstr";

void log_on_boot() {
    Preferences p;
    if (!p.begin(kNs, true)) {
        Serial.println("[restart] no prior reason recorded");
        return;
    }
    String last = p.getString("last", "");
    uint32_t at = p.getUInt("last_uptime", 0);
    uint32_t total = p.getUInt("total", 0);
    if (last.length() == 0 && total == 0) {
        Serial.println("[restart] first boot (no reason history)");
        p.end();
        return;
    }
    Serial.printf("[restart] last=%s at_uptime=%us  total=%u",
                  last.length() ? last.c_str() : "?",
                  (unsigned)at, (unsigned)total);
    // Walk a small list of the labels we write so the log shows what
    // actually got bumped. Not exhaustive — unknown labels appended in
    // future firmware revisions still bump correctly, just don't appear
    // here until added.
    static const char* kLabels[] = {
        kReasonHeapLow,
        kReasonWifiOutage,
        kReasonTelnetStuck,
        kReasonPortalSaved,
        kReasonOomNew,
        kReasonUserAction,
    };
    for (const char* lbl : kLabels) {
        char key[24];
        snprintf(key, sizeof(key), "%s_n", lbl);
        uint32_t n = p.getUInt(key, 0);
        if (n) Serial.printf(" %s=%u", lbl, (unsigned)n);
    }
    Serial.println();
    p.end();
}

[[noreturn]] void restart_with(const char* reason) {
    // Best-effort: never let a flash hiccup keep us from rebooting.
    // The whole point of this path is recovery; if we can't even
    // commit the counter, the reboot still has to happen.
    {
        Preferences p;
        if (p.begin(kNs, false)) {
            const char* lbl = (reason && *reason) ? reason : "unknown";
            p.putString("last", lbl);
            p.putUInt("last_uptime", (uint32_t)(millis() / 1000));
            char key[24];
            snprintf(key, sizeof(key), "%s_n", lbl);
            uint32_t n = p.getUInt(key, 0);
            p.putUInt(key, n + 1);
            uint32_t total = p.getUInt("total", 0);
            p.putUInt("total", total + 1);
            p.end();
        }
    }
    Serial.printf("[restart] reason=%s — rebooting\n",
                  reason ? reason : "?");
    Serial.flush();
    delay(50);
    ESP.restart();
    // Compiler doesn't always know ESP.restart() doesn't return.
    for (;;) {}
}

} // namespace restart
} // namespace honeyopus
