package tech.antivpn.sentinel.bungee

import net.md_5.bungee.api.plugin.Plugin
import tech.antivpn.sentinel.common.ConsoleSpamFilter
import tech.antivpn.sentinel.common.ConsoleWaveLogger
import tech.antivpn.sentinel.common.DiscordWebhookNotifier
import tech.antivpn.sentinel.common.SentinelClient
import tech.antivpn.sentinel.common.SentinelConfig
import tech.antivpn.sentinel.common.SentinelListManager
import java.nio.file.Files

/**
 * Main Plugin entrypoint for BungeeCord / Waterfall proxy networks.
 */
class SentinelBungeePlugin : Plugin() {

    @Volatile
    lateinit var sentinelConfig: SentinelConfig
        private set
    @Volatile
    lateinit var sentinelClient: SentinelClient
        private set
    @Volatile
    lateinit var webhookNotifier: DiscordWebhookNotifier
        private set
    @Volatile
    lateinit var listManager: SentinelListManager
        private set
    val waveLogger = ConsoleWaveLogger(
        infoLogger = { logger.info(it) },
        warnLogger = { logger.warning(it) }
    )
    private var spamFilter: ConsoleSpamFilter? = null

    override fun onEnable() {
        loadConfiguration()
        spamFilter = ConsoleSpamFilter.install(waveLogger, listOf(logger, proxy.logger))

        // Register PreLogin event listener
        proxy.pluginManager.registerListener(this, BungeePreLoginListener(this))

        // Register Command
        proxy.pluginManager.registerCommand(this, SentinelBungeeCommand(this))

        logger.info("==================================================")
        logger.info(" Sentinel Anti-VPN Connector v${description.version} (BungeeCord/Waterfall)")
        logger.info(" Mode: ${sentinelConfig.mode} " + if (sentinelConfig.isAuditMode) "(AUDIT - PASSIVE MONITORING)" else "(ACTIVE ENFORCEMENT - BLOCKING VPNS)")
        logger.info(" Risk Threshold: ${sentinelConfig.riskThreshold} / 100")
        logger.info(" Graduated Defense: " + if (sentinelConfig.graduatedDefense) "ENABLED (Soft-alert suspect residential)" else "DISABLED")
        logger.info(" Console Logs: " + if (sentinelConfig.consoleLogs) "ENABLED (5s Wave Summary)" else "DISABLED (Silent Mode)")
        logger.info(" Discord Alerts: " + if (sentinelConfig.isDiscordConfigured) "ENABLED (Rate-Limit Batcher)" else "DISABLED")
        logger.info("==================================================")

        if (sentinelConfig.licenseKey == "stl_live_your_api_key_here" || sentinelConfig.licenseKey == "stl_test_showcase_demo" || sentinelConfig.licenseKey.isBlank()) {
            logger.warning("*************************************************************************")
            if (sentinelConfig.licenseKey == "stl_test_showcase_demo") {
                logger.warning("[Sentinel] WARNING: Public demo sandbox key (stl_test_showcase_demo) in use!")
                logger.warning("[Sentinel] Demo keys are strictly rate-limited (50 req/day) across all servers.")
            } else {
                logger.warning("[Sentinel] WARNING: No production Sentinel API license key configured!")
            }
            logger.warning("[Sentinel] Running in ${sentinelConfig.mode} mode without a production license key.")
            logger.warning("[Sentinel] Requests exceeding limits will fail-open. Configure your key in config.yml.")
            logger.warning("*************************************************************************")
        }
    }

    override fun onDisable() {
        spamFilter?.uninstall()
        spamFilter = null
        if (::sentinelClient.isInitialized) {
            sentinelClient.shutdown()
        }
        if (::webhookNotifier.isInitialized) {
            webhookNotifier.shutdown()
        }
        waveLogger.shutdown()
        logger.info("[Sentinel] BungeeCord proxy shutdown: cache cleared.")
    }

    fun setConsoleLogs(enabled: Boolean) {
        this.sentinelConfig = this.sentinelConfig.copy(consoleLogs = enabled)
        this.waveLogger.consoleLogsEnabled = enabled
        SentinelConfig.updateConsoleLogsInFile(dataFolder.toPath().resolve("config.yml"), enabled)
    }

    fun loadConfiguration() {
        val oldClient = if (::sentinelClient.isInitialized) sentinelClient else null
        val oldWebhook = if (::webhookNotifier.isInitialized) webhookNotifier else null
        try {
            if (!dataFolder.exists()) {
                dataFolder.mkdirs()
            }

            val configPath = dataFolder.toPath().resolve("config.yml")
            if (!Files.exists(configPath)) {
                getResourceAsStream("config.yml")?.use { input ->
                    Files.copy(input, configPath)
                }
            }

            val props = mutableMapOf<String, String>()
            if (Files.exists(configPath)) {
                Files.newBufferedReader(configPath).use { reader ->
                    var rawLine: String?
                    var currentSection = ""
                    var currentKey: String? = null
                    var blockScalarKey: String? = null
                    var blockScalarBaseIndent = -1
                    var blockScalarFold = false
                    while (reader.readLine().also { rawLine = it } != null) {
                        val line = rawLine!!
                        val trimmed = line.trim()
                        val indent = line.indexOfFirst { !it.isWhitespace() }.let { if (it < 0) 0 else it }
                        val isIndented = indent > 0

                        if (blockScalarKey != null) {
                            if (trimmed.isEmpty()) {
                                val existing = props[blockScalarKey]
                                if (!existing.isNullOrEmpty()) {
                                    props[blockScalarKey!!] = "$existing\n"
                                }
                                continue
                            }
                            if (indent > blockScalarBaseIndent) {
                                val existing = props[blockScalarKey]
                                props[blockScalarKey!!] = when {
                                    existing.isNullOrEmpty() -> trimmed
                                    blockScalarFold && existing.endsWith("\n") -> "$existing$trimmed"
                                    blockScalarFold -> "$existing $trimmed"
                                    else -> "$existing\n$trimmed"
                                }
                                continue
                            } else {
                                blockScalarKey = null
                                blockScalarBaseIndent = -1
                            }
                        }

                        if (trimmed.isEmpty() || trimmed.startsWith("#")) continue

                        if (trimmed.startsWith("-") && currentKey != null) {
                            val item = stripYamlValue(trimmed.substring(1).trim())
                            val existing = props[currentKey]
                            props[currentKey] = if (existing == null) item else "$existing\n$item"
                            continue
                        }

                        if (!isIndented) {
                            currentSection = ""
                        }

                        val colonIdx = trimmed.indexOf(':')
                        if (colonIdx > 0) {
                            val key = trimmed.substring(0, colonIdx).trim()
                            val rawVal = trimmed.substring(colonIdx + 1).trim()
                            val rawNoComment = rawVal.substringBefore(" #").substringBefore("\t#").trim()
                            if (rawNoComment == "|" || rawNoComment == "|-" || rawNoComment == ">" || rawNoComment == ">-") {
                                currentKey = currentSection + key
                                blockScalarKey = currentKey
                                blockScalarBaseIndent = indent
                                blockScalarFold = rawNoComment.startsWith(">")
                                props[currentKey] = ""
                            } else if (rawVal.isEmpty() || rawVal.startsWith("#")) {
                                if (!isIndented) {
                                    currentSection = "$key."
                                    currentKey = null
                                } else {
                                    currentKey = currentSection + key
                                }
                            } else {
                                val value = stripYamlValue(rawVal)
                                currentKey = currentSection + key
                                props[currentKey] = value
                            }
                        } else {
                            currentKey = null
                        }
                    }
                }
            }

            val endpoint = props["api.endpoint"] ?: "https://api.antivpn.tech/v1/check"
            val licenseKey = props["api.license-key"] ?: "stl_live_your_api_key_here"
            val timeoutMs = (props["api.timeout-ms"]?.toIntOrNull() ?: 2500).coerceIn(500, 30_000)
            val mode = props["mode"] ?: "ENFORCE"
            val riskThreshold = (props["risk-threshold"]?.toIntOrNull() ?: 80).coerceIn(0, 100)
            val allowGaming = props["allow-gaming-optimizers"]?.toBooleanStrictOrNull() ?: true
            val graduatedDefense = props["graduated-defense"]?.toBooleanStrictOrNull() ?: true
            val cacheMinutes = (props["cache-duration-minutes"]?.toIntOrNull() ?: 30).coerceAtLeast(0)
            val consoleLogs = (props["console-logs"] ?: props["logging.console"])?.toBooleanStrictOrNull() ?: true
            val discordEnabled = props["discord.enabled"]?.toBooleanStrictOrNull() ?: true
            val webhookUrl = props["discord.webhook-url"] ?: ""
            val notifyOnlyThreat = props["discord.notify-only-on-threat"]?.toBooleanStrictOrNull() ?: true
            val serverName = props["discord.server-name"] ?: "BungeeCord Network"
            val kickMessage = props["enforcement.kick-message"]
                ?: "&7VPN / Proxy traffic is restricted on this server.\n&8Threat: &f%threat% &7| &8Risk: &f%risk%/100\n&7Join our Discord (&fhttps://discord.gg/yourlink&7) to request VPN access."

            this.sentinelConfig = SentinelConfig(
                endpoint = endpoint,
                licenseKey = licenseKey,
                timeoutMs = timeoutMs,
                mode = mode,
                riskThreshold = riskThreshold,
                allowGamingOptimizers = allowGaming,
                graduatedDefense = graduatedDefense,
                cacheDurationMinutes = cacheMinutes,
                consoleLogs = consoleLogs,
                discordEnabled = discordEnabled,
                discordWebhookUrl = webhookUrl,
                discordNotifyOnlyOnThreat = notifyOnlyThreat,
                discordServerName = serverName,
                kickMessage = kickMessage
            )
            this.waveLogger.consoleLogsEnabled = this.sentinelConfig.consoleLogs

            this.sentinelClient = SentinelClient(
                this.sentinelConfig,
                infoLogger = { logger.info(it) },
                errorLogger = { logger.warning(it) }
            )

            this.webhookNotifier = DiscordWebhookNotifier(
                this.sentinelConfig,
                errorLogger = { logger.warning(it) }
            )

            if (!::listManager.isInitialized) {
                this.listManager = SentinelListManager(
                    dataFolder.toPath(),
                    infoLogger = { logger.info(it) },
                    warnLogger = { logger.warning(it) }
                )
            } else {
                this.listManager.load()
            }
            oldClient?.shutdown()
            oldWebhook?.shutdown()
        } catch (e: Exception) {
            logger.severe("[Sentinel] Failed to load BungeeCord configuration: ${e.message}")
            if (::sentinelClient.isInitialized && sentinelClient !== oldClient) sentinelClient.shutdown()
            if (::webhookNotifier.isInitialized && webhookNotifier !== oldWebhook) webhookNotifier.shutdown()
            if (oldClient != null && oldWebhook != null && ::sentinelConfig.isInitialized) {
                this.sentinelClient = oldClient
                this.webhookNotifier = oldWebhook
                logger.warning("[Sentinel] Retaining previous active configuration after reload error.")
            } else {
                this.sentinelConfig = SentinelConfig.createDefault()
                this.sentinelClient = SentinelClient(this.sentinelConfig, { logger.info(it) }, { logger.warning(it) })
                this.webhookNotifier = DiscordWebhookNotifier(this.sentinelConfig) { logger.warning(it) }
                this.listManager = SentinelListManager(dataFolder.toPath(), { logger.info(it) }, { logger.warning(it) })
            }
        }
    }

    private fun stripYamlValue(raw: String): String {
        val trimmed = raw.trim()
        if (trimmed.startsWith("\"")) {
            var i = 1
            val sb = StringBuilder()
            while (i < trimmed.length) {
                val c = trimmed[i]
                if (c == '\\' && i + 1 < trimmed.length && (trimmed[i + 1] == '"' || trimmed[i + 1] == '\\')) {
                    sb.append(trimmed[i + 1])
                    i += 2
                    continue
                }
                if (c == '"') {
                    return sb.toString()
                }
                sb.append(c)
                i++
            }
            return sb.toString()
        }
        if (trimmed.startsWith("'")) {
            var i = 1
            val sb = StringBuilder()
            while (i < trimmed.length) {
                val c = trimmed[i]
                if (c == '\'') {
                    if (i + 1 < trimmed.length && trimmed[i + 1] == '\'') {
                        sb.append('\'')
                        i += 2
                        continue
                    }
                    return sb.toString()
                }
                sb.append(c)
                i++
            }
            return sb.toString()
        }
        return trimmed.substringBefore(" #").substringBefore("\t#").trim()
    }
}
