#pragma once

#include <Arduino.h>
#include "attack_log.h"

namespace honeyopus {

// Submit attacks to DShield (https://dshield.org/).
// The submission includes source IP, protocol, port, and action taken.
// Requires valid DShield email and API key in the configuration.
class DShieldReporter {
public:
    // Submit a single attack entry to DShield.
    // Returns true if the submission was successful (or skipped because disabled).
    // Submissions are done asynchronously to avoid blocking the attack logging flow.
    static bool submit(const AttackEntry& entry);

    // Check if DShield reporting is fully configured and enabled.
    static bool isConfigured();
};

} // namespace honeyopus
