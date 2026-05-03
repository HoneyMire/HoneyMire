#pragma once

#include <Arduino.h>

namespace honeyopus {

enum class NetMode { Boot, ConnectingSTA, OnlineSTA, FallbackAP };

void wifi_begin();
void wifi_loop();

NetMode wifi_mode();
String wifi_ip_string();
String wifi_ap_ssid();          // SSID used in AP mode

// Forces AP mode for setup; persistent until creds are saved or device reboots.
void wifi_force_ap();

// Tries to (re)connect to STA using credentials in g_config.
void wifi_try_sta();

} // namespace honeyopus
