#include "display.h"
#include "config.h"
#include "icons.h"

#include <U8g2lib.h>
#include <Wire.h>

namespace honeyopus {

#if HONEYOPUS_DISPLAY_W == 72 && HONEYOPUS_DISPLAY_H == 40
static U8G2_SSD1306_72X40_ER_F_HW_I2C u8g2(U8G2_R0, /*reset=*/U8X8_PIN_NONE);
#elif HONEYOPUS_DISPLAY_W == 128 && HONEYOPUS_DISPLAY_H == 64
static U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2(U8G2_R0, /*reset=*/U8X8_PIN_NONE);
#elif HONEYOPUS_DISPLAY_W == 128 && HONEYOPUS_DISPLAY_H == 32
static U8G2_SSD1306_128X32_UNIVISION_F_HW_I2C u8g2(U8G2_R0, /*reset=*/U8X8_PIN_NONE);
#else
#error "Unsupported HONEYOPUS_DISPLAY_W/H combination"
#endif

Display g_display;

void Display::begin() {
    pinMode(HONEYOPUS_BUTTON_PIN, INPUT_PULLUP);
    Wire.begin(HONEYOPUS_I2C_SDA, HONEYOPUS_I2C_SCL);
    u8g2.begin();
    u8g2.setBusClock(400000);
    u8g2.setContrast(255);
}

void Display::powerOn_() {
    if (!on_) {
        u8g2.setPowerSave(0);
        on_ = true;
    }
}

void Display::powerOff_() {
    if (on_) {
        u8g2.clearBuffer();
        u8g2.sendBuffer();
        u8g2.setPowerSave(1);
        on_ = false;
        attack_kind_ = AttackKind::None;
    }
}

void Display::off() { powerOff_(); }

void Display::showBootLogo(uint32_t hold_ms) {
    powerOn_();
    u8g2.clearBuffer();
    // Center logo on whatever display we're on.
    int x = (HONEYOPUS_DISPLAY_W - icons::BOOT_LOGO_W) / 2;
    int y = (HONEYOPUS_DISPLAY_H - icons::BOOT_LOGO_H) / 2;
    if (x < 0) x = 0;
    if (y < 0) y = 0;
    u8g2.drawXBMP(x, y, icons::BOOT_LOGO_W, icons::BOOT_LOGO_H, icons::BOOT_LOGO);
    u8g2.sendBuffer();
    on_until_ms_ = millis() + hold_ms;
}

void Display::showAttack(AttackKind k) {
    if (k == AttackKind::None) return;
    attack_kind_ = k;
    powerOn_();
    u8g2.clearBuffer();
    const uint8_t* bmp = (k == AttackKind::SSH) ? icons::SSH_ICON : icons::TELNET_ICON;
    int x = (HONEYOPUS_DISPLAY_W - icons::TELNET_ICON_W) / 2;
    int y = (HONEYOPUS_DISPLAY_H - icons::TELNET_ICON_H) / 2;
    if (x < 0) x = 0;
    if (y < 0) y = 0;
    u8g2.drawXBMP(x, y, icons::TELNET_ICON_W, icons::TELNET_ICON_H, bmp);
    // Tiny label at the very bottom if there's room.
    if (HONEYOPUS_DISPLAY_H >= 48) {
        u8g2.setFont(u8g2_font_5x7_tr);
        const char* label = (k == AttackKind::SSH) ? "SSH" : "TELNET";
        int tw = u8g2.getStrWidth(label);
        u8g2.drawStr((HONEYOPUS_DISPLAY_W - tw) / 2, HONEYOPUS_DISPLAY_H - 1, label);
    }
    u8g2.sendBuffer();

    uint32_t now = millis();
    uint32_t atk = (uint32_t)g_config.get().attack_icon_seconds * 1000UL;
    uint32_t cap = (uint32_t)g_config.get().display_on_seconds * 1000UL;
    attack_until_ms_ = now + atk;
    on_until_ms_ = now + min(atk, cap);
}

void Display::showStatus(const String& l1, const String& l2, const String& l3) {
    status_l1_ = l1;
    status_l2_ = l2;
    status_l3_ = l3;
    have_status_ = true;
    if (on_) renderStatus_();
}

void Display::renderStatus_() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_5x7_tr);
    int y = 7;
    u8g2.drawStr(0, y, status_l1_.c_str()); y += 9;
    if (status_l2_.length()) { u8g2.drawStr(0, y, status_l2_.c_str()); y += 9; }
    if (status_l3_.length()) { u8g2.drawStr(0, y, status_l3_.c_str()); y += 9; }
    u8g2.sendBuffer();
}

void Display::wakeFromButton() {
    powerOn_();
    if (have_status_) renderStatus_();
    uint32_t cap = (uint32_t)g_config.get().display_on_seconds * 1000UL;
    on_until_ms_ = millis() + cap;
}

void Display::loop() {
    // Button: active-low with simple debounce.
    bool pressed = digitalRead(HONEYOPUS_BUTTON_PIN) == LOW;
    uint32_t now = millis();
    if (pressed != !btn_last_state_) {
        if (now - btn_last_change_ > 30) {
            btn_last_change_ = now;
            btn_last_state_ = !pressed;
            if (pressed) wakeFromButton();
        }
    }

    if (!on_) return;

    // If attack icon is showing and its window expired, fall back to status (if any)
    if (attack_kind_ != AttackKind::None && now >= attack_until_ms_) {
        attack_kind_ = AttackKind::None;
        if (have_status_) renderStatus_();
    }

    if (now >= on_until_ms_) powerOff_();
}

} // namespace honeyopus
