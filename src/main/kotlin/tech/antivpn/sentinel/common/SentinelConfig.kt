package tech.antivpn.sentinel.common

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path

/**
 * Immutable configuration options for the Sentinel protection engine.
 */
data class SentinelConfig(
    val endpoint: String = "https://api.antivpn.tech/v1/check",
    val licenseKey: String = "stl_live_your_api_key_here",
    val timeoutMs: Int = 2500,
    val mode: String = "ENFORCE",
    val riskThreshold: Int = 80,
    val allowGamingOptimizers: Boolean = true,
    val graduatedDefense: Boolean = true,
    val cacheDurationMinutes: Int = 30,
    val consoleLogs: Boolean = true,
    val discordEnabled: Boolean = true,
    val discordWebhookUrl: String = "",
    val discordNotifyOnlyOnThreat: Boolean = true,
    val discordServerName: String = "Minecraft Network",
    val kickMessage: String = "&7VPN / Proxy traffic is restricted on this server.\n&8Threat: &f%threat% &7| &8Risk: &f%risk%/100\n&7Join our Discord (&fhttps://discord.gg/yourlink&7) to request VPN access."
) {
    val safeTimeoutMs: Long
        get() = timeoutMs.toLong().coerceIn(500L, 30_000L)

    val isAuditMode: Boolean
        get() = mode.trim().equals("AUDIT", ignoreCase = true)

    val isDiscordConfigured: Boolean
        get() = discordEnabled && discordWebhookUrl.isNotBlank()

    companion object {
        // Clean slight cyan gradient (#22D3EE -> #0891B2) in universal &x hex format
        const val FORCED_KICK_HEADER =
            "&x&2&2&d&3&e&e&lS&x&2&0&c&f&e&b&le&x&1&f&c&b&e&7&ln&x&1&d&c&7&e&4&lt&x&1&c&c&3&e&0&li&x&1&a&b&f&d&d&ln&x&1&9&b&b&d&9&le&x&1&7&b&7&d&6&ll " +
            "&x&1&5&b&3&d&2&lP&x&1&4&a&f&c&f&lr&x&1&2&a&b&c&b&lo&x&1&1&a&7&c&8&lt&x&0&f&a&3&c&4&le&x&0&e&9&f&c&1&lc&x&0&c&9&b&b&d&lt&x&0&b&9&7&b&a&li&x&0&9&9&3&b&6&lo&x&0&8&9&1&b&2&ln"

        private val HEX_SHORT_REGEX = Regex("""[&§]#([0-9a-fA-F]{6})""")

        @JvmStatic
        fun createDefault(): SentinelConfig = SentinelConfig()

        /**
         * Resolves the desired console log boolean state from a command argument
         * ("on", "off", "toggle", or omitted). Returns null if the argument is unrecognized.
         */
        @JvmStatic
        fun parseConsoleLogsToggle(arg: String?, current: Boolean): Boolean? {
            if (arg.isNullOrBlank()) return !current
            return when (arg.trim().lowercase()) {
                "on", "enable", "enabled", "true" -> true
                "off", "disable", "disabled", "false" -> false
                "toggle" -> !current
                else -> null
            }
        }

        /**
         * Updates `console-logs: <true|false>` in config.yml on disk while preserving
         * all existing comments and formatting.
         */
        @JvmStatic
        fun updateConsoleLogsInFile(configPath: Path, enabled: Boolean) {
            try {
                if (!Files.exists(configPath)) return
                val content = Files.readString(configPath, StandardCharsets.UTF_8)
                val lineRegex = Regex("""(?m)^(\s*console-logs\s*:\s*)(?:true|false)(.*)$""")
                val updated = if (lineRegex.containsMatchIn(content)) {
                    lineRegex.replace(content) { match ->
                        "${match.groupValues[1]}$enabled${match.groupValues[2]}"
                    }
                } else {
                    val suffix = if (content.endsWith("\n")) "" else "\n"
                    "$content$suffix\n# Console Logging & Wave Summary (Toggle via /sentinel logs <on|off>)\nconsole-logs: $enabled\n"
                }
                Files.writeString(configPath, updated, StandardCharsets.UTF_8)
            } catch (_: Exception) {
            }
        }

        /**
         * Converts shorthand &#RRGGBB hex codes into universal &x&R&R&G&G&B&B format.
         */
        @JvmStatic
        fun translateHexCodes(input: String): String {
            return HEX_SHORT_REGEX.replace(input) { match ->
                val hex = match.groupValues[1].lowercase()
                "&x&${hex[0]}&${hex[1]}&${hex[2]}&${hex[3]}&${hex[4]}&${hex[5]}"
            }
        }

        /**
         * Normalizes newline escape sequences (\r\n, literal \n, /n, /N) to standard LF (\n),
         * protecting embedded URLs so links (e.g. Discord or web URLs) remain intact.
         */
        @JvmStatic
        fun normalizeNewlines(input: String): String {
            if (input.isEmpty()) return input

            // Protect URLs and discord invite links from /n replacement
            val urlRegex = Regex("""(?:https?://|www\.|[a-zA-Z0-9-]+\.[a-zA-Z]{2,}/)[^\s)\]"'\\>&§]+""", RegexOption.IGNORE_CASE)
            val urls = mutableListOf<String>()
            val placeholderPrefix = "___SENTINEL_URL_"
            val placeholderSuffix = "___"

            val masked = urlRegex.replace(input) { match ->
                val rawUrl = match.value
                val hasTrailingSlashN = rawUrl.endsWith("/n", ignoreCase = true)
                val cleanUrl = if (hasTrailingSlashN) rawUrl.dropLast(2) else rawUrl
                val idx = urls.size
                urls.add(cleanUrl)
                if (hasTrailingSlashN) "$placeholderPrefix$idx$placeholderSuffix/n" else "$placeholderPrefix$idx$placeholderSuffix"
            }

            var result = masked
                .replace("\r\n", "\n")
                .replace("\\r\\n", "\n")
                .replace("\\n", "\n")
                .replace("\\/n", "\n")
                .replace(Regex("""(?i)/n"""), "\n")

            for ((idx, url) in urls.withIndex()) {
                result = result.replace("$placeholderPrefix$idx$placeholderSuffix", url)
            }

            return result
        }
    }

    /**
     * Builds the complete enforcement kick message.
     * Forces the blue bold header (&9&lSentinel Protection) as the unremovable first line,
     * normalizes line breaks (\n and /n), and strips any redundant legacy headers from older configs.
     */
    fun buildEnforcementKickMessage(
        threat: String = "",
        risk: Int = 0,
        ip: String = "",
        player: String = ""
    ): String {
        var body = normalizeNewlines(kickMessage).trim()

        // Strip legacy or redundant Sentinel Protection / Anti-VPN headers from upgraded configs
        val firstNewline = body.indexOf('\n')
        val firstLine = if (firstNewline >= 0) body.substring(0, firstNewline) else body
        val plainFirstLine = firstLine
            .replace(Regex("""[&§]#[0-9a-fA-F]{6}"""), "")
            .replace(Regex("""[&§][0-9a-fk-orxA-FK-ORX]"""), "")
            .replace(Regex("""[\[\]\-:]"""), "")
            .trim()

        if (plainFirstLine.equals("Sentinel Protection", ignoreCase = true) ||
            plainFirstLine.equals("Sentinel AntiVPN", ignoreCase = true) ||
            plainFirstLine.equals("Sentinel Anti VPN", ignoreCase = true)
        ) {
            body = if (firstNewline >= 0) body.substring(firstNewline + 1).trimStart('\n', '\r', ' ') else ""
        }

        body = translateHexCodes(body)
            .replace("%threat%", threat)
            .replace("%risk%", risk.toString())
            .replace("%ip%", ip)
            .replace("%player%", player)

        return if (body.isEmpty()) {
            FORCED_KICK_HEADER
        } else {
            val formattedBody = if (body.startsWith("&") || body.startsWith("§")) body else "&r$body"
            "$FORCED_KICK_HEADER\n$formattedBody"
        }
    }
}
