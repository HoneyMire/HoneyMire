# HoneyOpus 🍯

A pocket-sized **Telnet + SSH honeypot** for ESP32-C3 boards with the built-in
0.42" 72×40 OLED. Records every captured session as an
[asciicast v2](https://docs.asciinema.org/manual/asciicast/v2/), classifies the
attacker (Mirai bot, IoT loader, manual operator, …), geolocates them, and
optionally submits the IP to **AbuseIPDB** and **AlienVault OTX** in the
background. A web dashboard, captive-portal Wi-Fi setup, and serial CLI are
bundled in.

> Vibe-coded end-to-end with the help of AI — every line in this repo was
> generated, reviewed and shaped through an iterative pair-programming dance.
> File issues if anything looks off and I'll feed them back into the loop.

## ✨ Install from your browser

Plug an ESP32-C3 board into a USB port and head to the **GitHub Pages site**
for this repo (enabled automatically by the workflow on each push to
`main`/`master`). Click *Connect*, pick the serial port, and the latest
firmware is flashed in seconds — no toolchain, no `pio`, no drivers beyond the
stock USB-CDC.

The flasher uses [ESP Web Tools](https://esphome.github.io/esp-web-tools/) and
works in Chrome, Edge and Opera on a desktop computer.

## Hardware

* Any ESP32-C3 SuperMini-class board with a built-in **SSD1306 72×40** OLED
  (I²C on **GPIO 5/6**) — e.g. the popular *01Space ESP32-C3 0.42" OLED*.
* Boot button on **GPIO 9** acts as the *function button*.
* The build also supports a **128×64** or **128×32** OLED — change
  `HONEYOPUS_DISPLAY_W/H` in `platformio.ini`.

## Building from source

```sh
pio run -t upload     # build + flash
pio device monitor    # serial console (115200 baud)
```

The first SSH connection after a fresh flash takes ~30 seconds while the
RSA-2048 host key is generated and persisted to LittleFS. Every subsequent
boot reuses the stored key.

## First boot

1. The OLED briefly shows the **HoneyOpus boot logo** then turns off.
2. With no Wi-Fi credentials saved, the board comes up as a SoftAP named
   **`HoneyOpus-XXXXXX`** (password `honeyopus`). The OLED shows the SSID and
   `192.168.4.1`.
3. Connect to the AP — your phone's captive-portal probe will pop the setup
   page automatically; if not, browse to `http://192.168.4.1/portal`.
4. Pick your network from the live scan, enter the password, hit **Connect**.
   HoneyOpus reboots and joins your LAN.

## Wi-Fi via the serial menu

Open the serial monitor at 115200 baud, press <kbd>m</kbd> (or <kbd>?</kbd>),
and you'll see:

```
HoneyOpus :: menu
  1) Set WiFi SSID
  2) Set WiFi password
  3) Set hostname
  4) Show config
  5) Save & reconnect WiFi
  6) Force AP setup mode
  7) Reset config to defaults
  8) List attacks
  9) List asciinema sessions
  s) Toggle SSH enabled
  t) Toggle Telnet enabled
  k) Set AbuseIPDB API key
  o) Set AlienVault OTX API key
```

## OLED behaviour

The display follows a strict, low-power state machine driven by
`src/display.cpp`:

* **Boot logo** for ≈ 2 s on power-up.
* **Off** the rest of the time.
* When a Telnet or SSH session lands, the matching icon flashes for
  `attack_icon_seconds` (default 15) — never longer than `display_on_seconds`
  (default 30).
* Pressing the **function button** (GPIO 9) wakes the display and shows the
  current status; it goes back to sleep after `display_on_seconds`.

Both timers and the icons are configurable from the dashboard.

## Web dashboard

Once associated, browse to `http://<board-ip>/`.

* **Dashboard** — KPIs and a table of recent attacks: time, protocol, source
  IP, geolocation (flag/city/ISP, 🏠 for LAN), captured credentials,
  classified attack profile (Mirai, IoT loader, manual, scripted, recon, …),
  command count, and links to ▶️ play the asciinema recording in the embedded
  player or ⬇️ download the `.cast` file.
* **Config** — every setting lives behind clean accordions with proper toggle
  switches: Wi-Fi, fake banners/usernames, dashboard auth, geolocation
  endpoint, **AbuseIPDB** + **OTX** toggles and API keys, display timers,
  storage caps. Includes a *Danger zone* button to wipe history while
  preserving configuration.
* **Sessions** — flat list of every `.cast` on flash.
* **`/api/attacks`** — JSON feed of the attack log, suitable for plumbing.

Default dashboard auth is **`admin` / `honeyopus`** — change it in *Config*
after first boot. Authentication is **automatically bypassed for clients on
the local network** so you don't get prompted at home; remote clients always
need to authenticate.

## Threat-intel reporting

Both reporters run from a dedicated FreeRTOS task so the honeypot's I/O is
never blocked. Each captured attack triggers:

1. Geo-IP lookup (`ip-api.com` by default — no key required for low volumes;
   any URL returning `country/city/lat/lon/isp` works).
2. **AbuseIPDB** — submitted with categories `18` (brute-force), `22` (SSH)
   and `23` (IoT-targeted) and your custom comment.
3. **AlienVault OTX** — a private one-IP pulse per attack tagged
   `honeypot/brute-force/<proto>`.

Both are off by default. Enable them in *Config* and paste your API keys.
**Attacks coming from LAN/private IPs are never reported** to either service.

## Asciinema sessions

Every captured session is appended to `/sessions/<timestamp>-<proto>-<rand>.cast`
on LittleFS. The dashboard player streams the file directly; the CLI
equivalent on a workstation is:

```sh
curl -u admin:honeyopus -O http://<board-ip>/cast?id=42
asciinema play 42.cast
```

The ring-buffer is sized by `max_sessions` (default 50) — older files are
deleted on boot.

## Layout

```
src/
  main.cpp                boot + main loop
  config.{h,cpp}          NVS-backed configuration
  display.{h,cpp}         OLED state machine (U8g2)
  icons.h                 boot logo + Telnet/SSH icons (XBM)
  storage.{h,cpp}         LittleFS bring-up + ring trimming
  attack_log.{h,cpp}      JSONL attack log
  attack_classifier.{h,cpp}  bot vs. script vs. human heuristics
  asciinema.{h,cpp}       asciicast v2 writer
  fake_shell.{h,cpp}      Cowrie-lite shell shared by Telnet & SSH
  telnet_honeypot.{h,cpp}
  ssh_honeypot.{h,cpp}    libssh-esp32 server
  geoip.{h,cpp}
  intel.{h,cpp}           AbuseIPDB + OTX reporters (background task)
  wifi_manager.{h,cpp}    STA + SoftAP fallback + DNS hijack
  serial_menu.{h,cpp}
  web_dashboard.{h,cpp}   AsyncWebServer + captive portal + web installer page
web/
  index.html              source for the GitHub Pages web flasher
.github/workflows/
  build-and-deploy.yml    CI: build firmware, merge image, publish Pages
```

## Continuous delivery

Pushing to `main`/`master` (or hitting *Run workflow* in the Actions tab)
triggers `.github/workflows/build-and-deploy.yml`, which:

1. Builds the firmware with PlatformIO.
2. Merges `bootloader + partitions + boot_app0 + app` into a single
   `firmware.bin` with `esptool.py merge_bin`.
3. Generates an ESP-Web-Tools `manifest.json` containing the commit SHA and
   build timestamp.
4. Publishes everything (HTML + firmware) to **GitHub Pages**.

To enable the site on a fresh fork, go to *Settings → Pages* and set
**Source = GitHub Actions**. The workflow takes care of the rest.

## Defending yourself

This is a deliberately exposed-to-the-internet honeypot. Run it on a network
segment you do not care about, behind NAT with **only** ports 22/23
forwarded. Disable SSH or Telnet from the dashboard if you don't want one.
The fake shell never executes anything — it returns canned strings — but
nothing in this project is hardened for production use against a determined
adversary.

## License


MIT. See `LICENSE`.
