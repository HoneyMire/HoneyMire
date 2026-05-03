#include "asciinema.h"

#include <time.h>

namespace honeyopus {

bool Asciinema::begin(const String& path,
                      uint16_t cols,
                      uint16_t rows,
                      const String& title,
                      const String& shell_cmd) {
    f_ = LittleFS.open(path, "w");
    if (!f_) return false;
    path_ = path;
    start_us_ = micros();
    bytes_ = 0;

    // Asciicast v2 header.
    f_.print("{\"version\":2,\"width\":");
    f_.print(cols);
    f_.print(",\"height\":");
    f_.print(rows);
    time_t t = time(nullptr);
    if (t > 1700000000) {
        f_.print(",\"timestamp\":");
        f_.print((uint32_t)t);
    }
    f_.print(",\"env\":{\"SHELL\":\"");
    // SHELL is constant; just use shell_cmd verbatim (no escapes needed for typical paths).
    f_.print(shell_cmd);
    f_.print("\",\"TERM\":\"xterm-256color\"}");
    if (title.length()) {
        f_.print(",\"title\":\"");
        // title is small and operator-controlled; minimal escape pass.
        for (size_t i = 0; i < title.length(); ++i) {
            char c = title[i];
            if (c == '"' || c == '\\') f_.write('\\');
            f_.write(c);
        }
        f_.print("\"");
    }
    f_.print("}\n");
    return true;
}

void Asciinema::writeEscaped_(const char* data, size_t len) {
    // Emit JSON string body with escapes per RFC 8259 — caller wraps in quotes.
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)data[i];
        switch (c) {
            case '"':  f_.write('\\'); f_.write('"'); break;
            case '\\': f_.write('\\'); f_.write('\\'); break;
            case '\b': f_.write('\\'); f_.write('b'); break;
            case '\f': f_.write('\\'); f_.write('f'); break;
            case '\n': f_.write('\\'); f_.write('n'); break;
            case '\r': f_.write('\\'); f_.write('r'); break;
            case '\t': f_.write('\\'); f_.write('t'); break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    f_.print(buf);
                } else {
                    f_.write(c);
                }
        }
    }
}

void Asciinema::writeEvent_(char kind, const char* data, size_t len) {
    if (!f_) return;
    uint32_t now = micros();
    uint32_t elapsed_us = now - start_us_;
    uint32_t secs = elapsed_us / 1000000UL;
    uint32_t frac = elapsed_us % 1000000UL;
    char tbuf[32];
    snprintf(tbuf, sizeof(tbuf), "[%u.%06u,\"%c\",\"", (unsigned)secs, (unsigned)frac, kind);
    f_.print(tbuf);
    writeEscaped_(data, len);
    f_.print("\"]\n");
    bytes_ += len;
    // Flush periodically to ensure data persists if power is cut. Per-instance
    // counter so concurrent sessions don't race.
    if (millis() - last_flush_ms_ > 500) {
        f_.flush();
        last_flush_ms_ = millis();
    }
}

void Asciinema::out(const char* data, size_t len) { writeEvent_('o', data, len); }
void Asciinema::in (const char* data, size_t len) { writeEvent_('i', data, len); }

void Asciinema::close() {
    if (f_) {
        f_.flush();
        f_.close();
    }
}

} // namespace honeyopus
