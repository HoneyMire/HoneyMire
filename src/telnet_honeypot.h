#pragma once

#include <Arduino.h>

namespace honeyopus {

// Starts a FreeRTOS listener task on port HONEYOPUS_TELNET_PORT.
// It only does anything once WiFi is connected.
void telnet_begin();

} // namespace honeyopus
