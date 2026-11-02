package tech.antivpn.sentinel.velocity

import com.google.inject.Inject
import com.velocitypowered.api.command.CommandMeta
import com.velocitypowered.api.event.Subscribe
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent
import com.velocitypowered.api.plugin.Plugin
import com.velocitypowered.api.plugin.annotation.DataDirectory
import com.velocitypowered.api.proxy.ProxyServer
import org.slf4j.Logger
import tech.antivpn.sentinel.common.ConsoleSpamFilter
import tech.antivpn.sentinel.common.ConsoleWaveLogger
import tech.antivpn.sentinel.common.DiscordWebhookNotifier
import tech.antivpn.sentinel.common.SentinelClient
import tech.antivpn.sentinel.common.SentinelConfig
import tech.antivpn.sentinel.common.SentinelListManager
import java.io.BufferedReader
import java.nio.file.Files
import java.nio.file.Path

/**
 * Velocity Proxy implementation of the Sentinel Universal Anti-VPN Plugin.
 */
@Plugin(
    id = "sentinel",
    name = "Sentinel",
    version = "2.0.3",
    description = "Enterprise Anti-VPN and Proxy Evasion Protection for Velocity.",
    authors = ["Sentinel"]
)
class SentinelVelocityPlugin @Inject constructor(
    val server: ProxyServer,
    val logger: Logger,
    @DataDirectory val dataDirectory: Path
) {
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
        warnLogger = { logger.warn(it) }
    )
    private var spamFilter: ConsoleSpamFilter? = null

    @Subscribe
    fun onProxyInitialization(event: ProxyInitializeEvent) {
        loadConfiguration()
        spamFilter = ConsoleSpamFilter.install(waveLogger)

        // Register async event listener
        server.eventManager.register(this, VelocityPreLoginListener(this))

        // Register command
        val commandManager = server.commandManager
        val meta: CommandMeta = commandManager.metaBuilder("sentinel")
            .aliases("antivpn")
            .plugin(this)
            .build()
        commandManager.register(meta, SentinelVelocityCommand(this))

        logger.info("==================================================")
        logger.info(" Sentinel Anti-VPN Connector v2.0.3 (Velocity)")
        logger.info(" Mode: {} {}", sentinelConfig.mode, if (sentinelConfig.isAuditMode) "(AUDIT - PASSIVE MONITORING)" else "(ACTIVE ENFORCEMENT - BLOCKING VPNS)")
        logger.info(" Risk Threshold: {} / 100", sentinelConfig.riskThreshold)
        logger.info(" Graduated Defense: {}", if (sentinelConfig.graduatedDefense) "ENABLED (Soft-alert suspect residential)" else "DISABLED")
        logger.info(" Console Logs: {}", if (sentinelConfig.consoleLogs) "ENABLED (5s Wave Summary)" else "DISABLED (Silent Mode)")
        logger.info(" Discord Alerts: {}", if (sentinelConfig.isDiscordConfigured) "ENABLED (Rate-Limit Batcher)" else "DISABLED")
        logger.info("==================================================")

        if (sentinelConfig.licenseKey == "stl_live_your_api_key_here" || sentinelConfig.licenseKey == "stl_test_showcase_demo" || sentinelConfig.licenseKey.isBlank()) {
            logger.warn("*************************************************************************")
            if (sentinelConfig.licenseKey == "stl_test_showcase_demo") {
                logger.warn("[Sentinel] WARNING: Public demo sandbox key (stl_test_showcase_demo) in use!")
                logger.warn("[Sentinel] Demo keys are strictly rate-limited (50 req/day) across all servers.")
            } else {
                logger.warn("[Sentinel] WARNING: No production Sentinel API license key configured!")
            }
            logger.warn("[Sentinel] Running in {} mode without a production license key.", sentinelConfig.mode)
            logger.warn("[Sentinel] Requests exceeding limits will fail-open. Configure your key in config.yml.")
            logger.warn("*************************************************************************")
        }
    }

    @Subscribe
    fun onProxyShutdown(event: ProxyShutdownEvent) {
        spamFilter?.uninstall()
        spamFilter = null
        if (::sentinelClient.isInitialized) {
            sentinelClient.shutdown()
        }
        if (::webhookNotifier.isInitialized) {
            webhookNotifier.shutdown()
        }
        waveLogger.shutdown()
        logger.info("[Sentinel] Velocity proxy shutdown: cache cleared.")
    }

    fun setConsoleLogs(enabled: Boolean) {
        this.sentinelConfig = this.sentinelConfig.copy(consoleLogs = enabled)
        this.waveLogger.consoleLogsEnabled = enabled
        SentinelConfig.updateConsoleLogsInFile(dataDirectory.resolve("config.yml"), enabled)
    }

    fun loadConfiguration() {
        val oldClient = if (::sentinelClient.isInitialized) sentinelClient else null
        val oldWebhook = if (::webhookNotifier.isInitialized) webhookNotifier else null
        try {
            if (!Files.exists(dataDirectory)) {
                Files.createDirectories(dataDirectory)
            }

            val configPath = dataDirectory.resolve("config.yml")
            if (!Files.exists(configPath)) {
                javaClass.getResourceAsStream("/config.yml")?.use { input ->
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
            val serverName = props["discord.server-name"] ?: "Velocity Network"
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
                errorLogger = { logger.warn(it) }
            )

            this.webhookNotifier = DiscordWebhookNotifier(
                this.sentinelConfig,
                errorLogger = { logger.warn(it) }
            )

            if (!::listManager.isInitialized) {
                this.listManager = SentinelListManager(
                    dataDirectory,
                    infoLogger = { logger.info(it) },
                    warnLogger = { logger.warn(it) }
                )
            } else {
                this.listManager.load()
            }
            oldClient?.shutdown()
            oldWebhook?.shutdown()
        } catch (e: Exception) {
            logger.error("[Sentinel] Failed to load configuration: {}", e.message, e)
            if (::sentinelClient.isInitialized && sentinelClient !== oldClient) sentinelClient.shutdown()
            if (::webhookNotifier.isInitialized && webhookNotifier !== oldWebhook) webhookNotifier.shutdown()
            if (oldClient != null && oldWebhook != null && ::sentinelConfig.isInitialized) {
                this.sentinelClient = oldClient
                this.webhookNotifier = oldWebhook
                logger.warn("[Sentinel] Retaining previous active configuration after reload error.")
            } else {
                this.sentinelConfig = SentinelConfig.createDefault()
                this.sentinelClient = SentinelClient(this.sentinelConfig, { logger.info(it) }, { logger.warn(it) })
                this.webhookNotifier = DiscordWebhookNotifier(this.sentinelConfig) { logger.warn(it) }
                this.listManager = SentinelListManager(dataDirectory, { logger.info(it) }, { logger.warn(it) })
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
