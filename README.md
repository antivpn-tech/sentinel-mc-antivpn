# Sentinel Minecraft Connector

<p align="center">
  <a href="https://github.com/antivpn-tech/sentinel-mc-antivpn/releases"><img src="https://img.shields.io/github/v/release/antivpn-tech/sentinel-mc-antivpn?color=2563EB&label=Release" alt="Release"></a>
  <a href="https://kotlinlang.org"><img src="https://img.shields.io/badge/Language-Kotlin-7F52FF.svg" alt="Kotlin"></a>
  <a href="https://papermc.io"><img src="https://img.shields.io/badge/Platform-Paper%20%7C%20Folia%20%7C%20Velocity%20%7C%20BungeeCord-EA580C.svg" alt="Platforms"></a>
  <a href="https://antivpn.tech"><img src="https://img.shields.io/badge/API-api.antivpn.tech-059669.svg" alt="Sentinel API"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-475569.svg" alt="License"></a>
</p>

Sentinel Minecraft Connector is the official universal Kotlin connector linking Minecraft servers and proxy networks directly to the Sentinel Edge Intelligence Network ([antivpn.tech](https://antivpn.tech)).

It provides low-latency proxy and VPN detection, and routing preservation for gaming optimizers (Cloudflare WARP, ExitLag, WTFast, etc.). Delivered as a single universal JAR for Velocity, BungeeCord, Waterfall, Folia, Paper, Purpur, Spigot, and Bukkit.

---

## Key Capabilities

- **Universal Drop-in Binary**: Single artifact automatically initializes on Velocity 3.3+, BungeeCord, Waterfall, Folia, and Paper / Purpur / Spigot 1.8 through 1.21+.
- **Fail-Open Architecture**: Asynchronous non-blocking HTTP/2 queries. If the edge network or remote API is unreachable, queries resolve to `ALLOW` to prevent blocking legitimate players.
- **Gaming Optimizer & WARP Bypass**: Preserves competitive players utilizing latency routing services and privacy proxies (Cloudflare WARP, ExitLag, WTFast, NoPing, Mudfish, GearUP, LagoFast) without false positive kicks.
- **Join-Wave Micro-Batching & Coalescing**: Automatically coalesces duplicate in-flight checks and batches concurrent join waves via `/v1/batch`.
- **Batched Discord Telemetry**: Rate-limit-aware webhook dispatcher consolidates attack waves into structured digest embeds, preventing HTTP 429 webhook drops during floods.
- **IPv4 & IPv6 `/64` Subnet Cache**: High-throughput memory cache eliminates redundant API queries during reconnects and neutralizes rotating IPv6 `/64` bot swarms.
- **Local Lists with CIDR Support**: Administrative `/sentinel` (alias `/antivpn`) commands for in-game username, single IP, and IPv4/IPv6 CIDR subnet whitelisting and blacklisting.

---

## Detection Workflow

```mermaid
flowchart TD
    Join["Connection Request (Pre-Login)"] --> CacheCheck{"In-Memory Cache / Whitelist?"}
    CacheCheck -- Yes --> AllowJoin["Pass (0ms)"]
    CacheCheck -- No --> EdgeAPI["Async Edge Intelligence Query"]
    EdgeAPI --> RiskEval{"Risk Score >= Threshold?"}
    RiskEval -- Yes --> KickThreat["ENFORCE: Disallow & Log"]
    RiskEval -- No --> AllowClean["ALLOW: Connection Accepted"]
```

---

## Authentication and Licenses

To connect to the Sentinel intelligence network:

1. Create an account at [antivpn.tech](https://antivpn.tech).
2. Generate an API license key from the dashboard (Developer, Starter, or Enterprise).
3. Insert your license key (`stl_live_...`) into `plugins/Sentinel/config.yml`.

---

## Installation

1. Download `Sentinel-Minecraft-2.0.3.jar` from the [Releases](https://github.com/antivpn-tech/sentinel-mc-antivpn/releases) page.
2. Place the JAR into your server's `plugins/` directory:
   - Velocity: `/plugins/Sentinel-Minecraft-2.0.3.jar`
   - BungeeCord / Waterfall: `/plugins/Sentinel-Minecraft-2.0.3.jar`
   - Paper / Purpur / Spigot: `/plugins/Sentinel-Minecraft-2.0.3.jar`
3. Start the server to generate default configurations.
4. Configure your license key in `plugins/Sentinel/config.yml` (or `plugins/sentinel/config.yml` on Velocity).
5. Execute `/sentinel reload` to apply settings.

---

## Configuration Reference

```yaml
# ==============================================================================
#                 Sentinel Anti-VPN Protection Configuration
#                        https://antivpn.tech
# ==============================================================================

api:
  # Sentinel Edge Intelligence API endpoint
  endpoint: "https://api.antivpn.tech/v1/check"

  # Your Sentinel License Key (Claim your free Developer key at https://antivpn.tech)
  license-key: "stl_live_your_api_key_here"

  # HTTP connection timeout in milliseconds
  timeout-ms: 2500

# ------------------------------------------------------------------------------
# Protection Mode:
# ENFORCE - Active Blocking Mode (Default). Disallows proxy/VPN connections.
# AUDIT   - Passive Monitoring Mode. Logs detections without kicking players.
# ------------------------------------------------------------------------------
mode: "ENFORCE"

# Risk threshold (0 - 100). Commercial VPNs and proxies rate 85-100.
risk-threshold: 80

# Whitelist gaming VPNs and ping optimizers (Cloudflare WARP, ExitLag, WTFast, NoPing, Mudfish, GearUP, LagoFast)
allow-gaming-optimizers: true

# Graduated Defense Policy (Recommended: true)
# Immediately kicks deterministic threats while protecting mobile/CGNAT pools
graduated-defense: true

# In-memory IP cache duration in minutes
cache-duration-minutes: 30

# Console Logging & Wave Summary
# When true, connection waves are swallowed into a 5-second console summary.
# Toggle in-game or via console at any time with: /sentinel logs <on|off|toggle>
console-logs: true

# ------------------------------------------------------------------------------
# Discord Webhook Telemetry
# ------------------------------------------------------------------------------
discord:
  enabled: true
  webhook-url: ""
  notify-only-on-threat: true
  server-name: "Minecraft Network"

# ------------------------------------------------------------------------------
# Enforcement Disconnect Screen
# Line 1 is reserved and permanently branded with: Sentinel Protection (Cyan Gradient)
# Configure your custom server description and appeal details below (\n or /n)
# Supports legacy (&) and shorthand hex (&#RRGGBB) color codes
# Placeholders: %player%, %ip%, %threat%, %risk%
# ------------------------------------------------------------------------------
enforcement:
  # [Line 1: Reserved by Sentinel Protection]
  kick-message: "&7VPN / Proxy traffic is restricted on this server.\n&8Threat: &f%threat% &7| &8Risk: &f%risk%/100\n&7Join our Discord (&fhttps://discord.gg/yourlink&7) to request VPN access."
```

---

## Commands and Permissions

Administrative commands require the `sentinel.admin` permission (granted to server operators by default). Alias `/antivpn` is supported on all platforms, and `wl` / `bl` can be used as shorthand for `whitelist` / `blacklist`.

| Command | Description |
| :--- | :--- |
| `/sentinel status` | Displays active protection mode, cache volume, list counts, console log state, and webhook state. |
| `/sentinel logs [on\|off\|toggle]` | Toggles Sentinel console wave summaries on or off and persists `console-logs` in `config.yml`. |
| `/sentinel reload` | Reloads `config.yml`, `whitelist.json`, and `blacklist.json`. |
| `/sentinel check <ip\|player>` | Queries live intelligence for an online player or target IP address. |
| `/sentinel whitelist list` | Lists all whitelisted usernames, IP addresses, and CIDR subnets. |
| `/sentinel whitelist add <player\|ip\|cidr>` | Adds a username, IP, or CIDR subnet to the whitelist (bypasses all checks). |
| `/sentinel whitelist remove <player\|ip\|cidr>` | Removes a target from the whitelist. |
| `/sentinel blacklist list` | Lists all blacklisted usernames, IP addresses, and CIDR subnets. |
| `/sentinel blacklist add <player\|ip\|cidr>` | Adds a username, IP, or CIDR subnet to the blacklist (immediate rejection). |
| `/sentinel blacklist remove <player\|ip\|cidr>` | Removes a target from the blacklist. |

---

## Building from Source

Requirements:
- JDK 17 or higher
- Apache Maven 3.8 or higher

```bash
git clone https://github.com/antivpn-tech/sentinel-mc-antivpn.git
cd sentinel-mc-antivpn
mvn clean package
```

The compiled universal JAR will be produced at `target/Sentinel-Minecraft-2.0.3.jar`.

---

## License

This project is licensed under the [MIT License](LICENSE).
