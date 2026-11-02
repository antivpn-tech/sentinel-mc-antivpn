package tech.antivpn.sentinel.paper

import org.bukkit.Bukkit
import org.bukkit.ChatColor
import org.bukkit.command.Command
import org.bukkit.command.CommandExecutor
import org.bukkit.command.CommandSender
import org.bukkit.command.TabCompleter
import org.bukkit.entity.Player
import org.bukkit.plugin.java.JavaPlugin
import tech.antivpn.sentinel.common.ConsoleSpamFilter
import tech.antivpn.sentinel.common.ConsoleWaveLogger
import tech.antivpn.sentinel.common.DiscordWebhookNotifier
import tech.antivpn.sentinel.common.SentinelClient
import tech.antivpn.sentinel.common.SentinelConfig
import tech.antivpn.sentinel.common.SentinelListManager
import java.util.Locale

/**
 * Main JavaPlugin entrypoint for Paper / Purpur / Spigot / Bukkit servers.
 */
class SentinelPaperPlugin : JavaPlugin(), CommandExecutor, TabCompleter {

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
        saveDefaultConfig()
        loadConfiguration()
        spamFilter = ConsoleSpamFilter.install(waveLogger, listOf(logger, server.logger))

        // Register pre-login event listener
        server.pluginManager.registerEvents(PaperPreLoginListener(this), this)

        // Register command & tab completer
        getCommand("sentinel")?.let {
            it.setExecutor(this)
            it.tabCompleter = this
        }

        logger.info("==================================================")
        logger.info(" Sentinel Anti-VPN Connector v${description.version} (Paper/Folia/Spigot)")
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
        logger.info("[Sentinel] Disabled and cache purged.")
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
            reloadConfig()
            val c = config
            val consoleLogs = if (c.contains("console-logs")) {
                c.getBoolean("console-logs", true)
            } else {
                c.getBoolean("logging.console", true)
            }

            this.sentinelConfig = SentinelConfig(
                endpoint = c.getString("api.endpoint", "https://api.antivpn.tech/v1/check") ?: "https://api.antivpn.tech/v1/check",
                licenseKey = c.getString("api.license-key", "stl_live_your_api_key_here") ?: "stl_live_your_api_key_here",
                timeoutMs = c.getInt("api.timeout-ms", 2500).coerceIn(500, 30_000),
                mode = c.getString("mode", "ENFORCE") ?: "ENFORCE",
                riskThreshold = c.getInt("risk-threshold", 80).coerceIn(0, 100),
                allowGamingOptimizers = c.getBoolean("allow-gaming-optimizers", true),
                graduatedDefense = c.getBoolean("graduated-defense", true),
                cacheDurationMinutes = c.getInt("cache-duration-minutes", 30).coerceAtLeast(0),
                consoleLogs = consoleLogs,
                discordEnabled = c.getBoolean("discord.enabled", true),
                discordWebhookUrl = c.getString("discord.webhook-url", "") ?: "",
                discordNotifyOnlyOnThreat = c.getBoolean("discord.notify-only-on-threat", true),
                discordServerName = c.getString("discord.server-name", "Minecraft Network") ?: "Minecraft Network",
                kickMessage = if (c.isList("enforcement.kick-message")) {
                    c.getStringList("enforcement.kick-message").joinToString("\n")
                } else {
                    c.getString(
                        "enforcement.kick-message",
                        "&7VPN / Proxy traffic is restricted on this server.\n&8Threat: &f%threat% &7| &8Risk: &f%risk%/100\n&7Join our Discord (&fhttps://discord.gg/yourlink&7) to request VPN access."
                    ) ?: "&7VPN / Proxy traffic is restricted on this server.\n&8Threat: &f%threat% &7| &8Risk: &f%risk%/100\n&7Join our Discord (&fhttps://discord.gg/yourlink&7) to request VPN access."
                }
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
            logger.severe("[Sentinel] Failed to load Paper configuration: ${e.message}")
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

    override fun onCommand(sender: CommandSender, command: Command, label: String, args: Array<out String>): Boolean {
        if (!sender.hasPermission("sentinel.admin")) {
            sender.sendMessage("${ChatColor.RED}You do not have permission to execute Sentinel commands.")
            return true
        }

        if (args.isEmpty() || args[0].equals("status", ignoreCase = true)) {
            sender.sendMessage("${ChatColor.DARK_GRAY}---------------------------------------------")
            sender.sendMessage("${ChatColor.GOLD}${ChatColor.BOLD}Sentinel Anti-VPN Status")
            sender.sendMessage("${ChatColor.GRAY}Mode: " + if (sentinelConfig.isAuditMode) "${ChatColor.YELLOW}AUDIT (Dry-Run)" else "${ChatColor.RED}ENFORCE (Blocking)")
            sender.sendMessage("${ChatColor.GRAY}Risk Threshold: ${ChatColor.WHITE}${sentinelConfig.riskThreshold} / 100")
            sender.sendMessage("${ChatColor.GRAY}Console Logs: " + if (sentinelConfig.consoleLogs) "${ChatColor.GREEN}ENABLED (Wave Summary)" else "${ChatColor.RED}DISABLED (Silent)")
            sender.sendMessage("${ChatColor.GRAY}Cached IPs: ${ChatColor.WHITE}${sentinelClient.cacheSize}")
            sender.sendMessage("${ChatColor.GRAY}Whitelisted: ${ChatColor.GREEN}${listManager.getWhitelistedPlayers().size} players, ${listManager.getWhitelistedIps().size} IPs")
            sender.sendMessage("${ChatColor.GRAY}Blacklisted: ${ChatColor.RED}${listManager.getBlacklistedPlayers().size} players, ${listManager.getBlacklistedIps().size} IPs")
            sender.sendMessage("${ChatColor.GRAY}Discord Webhook: " + if (sentinelConfig.isDiscordConfigured) "${ChatColor.GREEN}Connected" else "${ChatColor.RED}Disabled / Unset")
            sender.sendMessage("${ChatColor.DARK_GRAY}---------------------------------------------")
            return true
        }

        if (args[0].equals("reload", ignoreCase = true)) {
            loadConfiguration()
            sender.sendMessage("${ChatColor.GREEN}[Sentinel] Configuration and whitelist/blacklist reloaded.")
            return true
        }

        if (args[0].equals("logs", ignoreCase = true) || args[0].equals("console", ignoreCase = true)) {
            val nextState = SentinelConfig.parseConsoleLogsToggle(args.getOrNull(1), sentinelConfig.consoleLogs)
            if (nextState == null) {
                sender.sendMessage("${ChatColor.RED}Usage: /sentinel logs [on | off | toggle]")
                return true
            }
            setConsoleLogs(nextState)
            if (nextState) {
                sender.sendMessage("${ChatColor.GREEN}[Sentinel] Console logs and wave summaries are now ENABLED.")
            } else {
                sender.sendMessage("${ChatColor.YELLOW}[Sentinel] Console logs are now DISABLED (silent mode).")
            }
            return true
        }

        // Whitelist commands: /sentinel whitelist [add|remove|list] <player|ip>
        if (args[0].equals("whitelist", ignoreCase = true) || args[0].equals("wl", ignoreCase = true)) {
            if (args.size < 2 || args[1].equals("list", ignoreCase = true)) {
                sender.sendMessage("${ChatColor.DARK_GRAY}---------------------------------------------")
                sender.sendMessage("${ChatColor.GREEN}${ChatColor.BOLD}Sentinel Whitelist")
                sender.sendMessage(
                    "${ChatColor.GRAY}Players (${listManager.getWhitelistedPlayers().size}): " +
                            ChatColor.WHITE + (if (listManager.getWhitelistedPlayers().isEmpty()) "None" else listManager.getWhitelistedPlayers().joinToString(", "))
                )
                sender.sendMessage(
                    "${ChatColor.GRAY}IPs (${listManager.getWhitelistedIps().size}): " +
                            ChatColor.WHITE + (if (listManager.getWhitelistedIps().isEmpty()) "None" else listManager.getWhitelistedIps().joinToString(", "))
                )
                sender.sendMessage("${ChatColor.DARK_GRAY}---------------------------------------------")
                return true
            }

            if (args[1].equals("add", ignoreCase = true) && args.size >= 3) {
                val target = args[2]
                if (!SentinelListManager.isValidTarget(target)) {
                    sender.sendMessage("${ChatColor.RED}[Sentinel] '$target' is not a valid IP address, CIDR subnet, or Minecraft username.")
                    return true
                }
                val added = listManager.addWhitelist(target)
                if (added) {
                    sender.sendMessage("${ChatColor.GREEN}[Sentinel] Added '$target' to the whitelist.")
                } else {
                    sender.sendMessage("${ChatColor.YELLOW}[Sentinel] '$target' is already whitelisted.")
                }
                return true
            }

            if (args[1].equals("remove", ignoreCase = true) && args.size >= 3) {
                val target = args[2]
                val removed = listManager.removeWhitelist(target)
                if (removed) {
                    sender.sendMessage("${ChatColor.GREEN}[Sentinel] Removed '$target' from the whitelist.")
                } else {
                    sender.sendMessage("${ChatColor.RED}[Sentinel] '$target' was not found in the whitelist.")
                }
                return true
            }

            sender.sendMessage("${ChatColor.RED}Usage: /sentinel whitelist [add <player|ip> | remove <player|ip> | list]")
            return true
        }

        // Blacklist commands: /sentinel blacklist [add|remove|list] <player|ip>
        if (args[0].equals("blacklist", ignoreCase = true) || args[0].equals("bl", ignoreCase = true)) {
            if (args.size < 2 || args[1].equals("list", ignoreCase = true)) {
                sender.sendMessage("${ChatColor.DARK_GRAY}---------------------------------------------")
                sender.sendMessage("${ChatColor.RED}${ChatColor.BOLD}Sentinel Blacklist")
                sender.sendMessage(
                    "${ChatColor.GRAY}Players (${listManager.getBlacklistedPlayers().size}): " +
                            ChatColor.WHITE + (if (listManager.getBlacklistedPlayers().isEmpty()) "None" else listManager.getBlacklistedPlayers().joinToString(", "))
                )
                sender.sendMessage(
                    "${ChatColor.GRAY}IPs (${listManager.getBlacklistedIps().size}): " +
                            ChatColor.WHITE + (if (listManager.getBlacklistedIps().isEmpty()) "None" else listManager.getBlacklistedIps().joinToString(", "))
                )
                sender.sendMessage("${ChatColor.DARK_GRAY}---------------------------------------------")
                return true
            }

            if (args[1].equals("add", ignoreCase = true) && args.size >= 3) {
                val target = args[2]
                if (!SentinelListManager.isValidTarget(target)) {
                    sender.sendMessage("${ChatColor.RED}[Sentinel] '$target' is not a valid IP address, CIDR subnet, or Minecraft username.")
                    return true
                }
                val added = listManager.addBlacklist(target)
                if (added) {
                    sender.sendMessage("${ChatColor.RED}[Sentinel] Added '$target' to the blacklist.")
                } else {
                    sender.sendMessage("${ChatColor.YELLOW}[Sentinel] '$target' is already blacklisted.")
                }
                return true
            }

            if (args[1].equals("remove", ignoreCase = true) && args.size >= 3) {
                val target = args[2]
                val removed = listManager.removeBlacklist(target)
                if (removed) {
                    sender.sendMessage("${ChatColor.GREEN}[Sentinel] Removed '$target' from the blacklist.")
                } else {
                    sender.sendMessage("${ChatColor.RED}[Sentinel] '$target' was not found in the blacklist.")
                }
                return true
            }

            sender.sendMessage("${ChatColor.RED}Usage: /sentinel blacklist [add <player|ip> | remove <player|ip> | list]")
            return true
        }

        if (args[0].equals("check", ignoreCase = true) && args.size >= 2) {
            val targetInput = args[1]
            var targetIp: String
            var displayName: String

            if (!SentinelListManager.isSingleIpAddress(targetInput)) {
                val onlinePlayer = Bukkit.getPlayerExact(targetInput) ?: Bukkit.getPlayer(targetInput)
                val inetAddr = onlinePlayer?.address?.address
                if (onlinePlayer != null && inetAddr != null) {
                    targetIp = inetAddr.hostAddress.substringBefore('%')
                    displayName = "${onlinePlayer.name} ($targetIp)"
                } else {
                    sender.sendMessage("${ChatColor.RED}[Sentinel] Player '$targetInput' is not online (or input is not a valid single IP). Provide a direct IP to check an offline target.")
                    return true
                }
            } else {
                targetIp = SentinelListManager.normalizeIp(targetInput)
                displayName = targetIp
            }

            sender.sendMessage("${ChatColor.GRAY}[Sentinel] Querying edge intelligence for $displayName...")
            val finalDisplay = displayName
            val cfg = sentinelConfig
            sentinelClient.evaluate(targetIp).thenAccept { verdict ->
                val isThreat = verdict.isThreat(cfg.riskThreshold, cfg.allowGamingOptimizers)
                val color = when {
                    isThreat || verdict.riskScore >= cfg.riskThreshold -> ChatColor.RED
                    verdict.riskScore >= 40 -> ChatColor.YELLOW
                    else -> ChatColor.GREEN
                }
                sender.sendMessage("${ChatColor.DARK_GRAY}---------------------------------------------")
                sender.sendMessage("${ChatColor.GOLD}[Sentinel Result] ${ChatColor.WHITE}$finalDisplay")
                sender.sendMessage("${ChatColor.GRAY}Verdict Action: $color${verdict.action}")
                sender.sendMessage("${ChatColor.GRAY}Risk Score: $color${verdict.riskScore}/100")
                sender.sendMessage("${ChatColor.GRAY}Threat Type: ${ChatColor.WHITE}${verdict.threatType}")
                sender.sendMessage("${ChatColor.GRAY}ISP: ${ChatColor.WHITE}AS${verdict.asn} ${verdict.provider}")
                sender.sendMessage("${ChatColor.GRAY}Location: ${ChatColor.WHITE}${verdict.getFormattedLocation()}")
                if (verdict.reasons.isNotEmpty()) {
                    sender.sendMessage("${ChatColor.GRAY}Reasons: ${ChatColor.WHITE}${verdict.reasons.joinToString(", ")}")
                }
                sender.sendMessage("${ChatColor.DARK_GRAY}---------------------------------------------")
            }.exceptionally { ex ->
                sender.sendMessage("${ChatColor.RED}[Sentinel] Failed to check $finalDisplay: ${ex.message}")
                null
            }
            return true
        }

        sender.sendMessage("${ChatColor.RED}Usage: /sentinel [status | reload | logs <on|off> | check <ip|player> | whitelist | blacklist]")
        return true
    }

    override fun onTabComplete(sender: CommandSender, command: Command, alias: String, args: Array<out String>): List<String> {
        if (!sender.hasPermission("sentinel.admin")) {
            return emptyList()
        }

        if (args.size == 1) {
            val sub = listOf("status", "reload", "logs", "check", "whitelist", "blacklist")
            return sub.filter { it.startsWith(args[0].lowercase(Locale.ROOT)) }
        }

        if (args.size == 2) {
            if (args[0].equals("logs", ignoreCase = true) || args[0].equals("console", ignoreCase = true)) {
                return listOf("on", "off", "toggle").filter { it.startsWith(args[1].lowercase(Locale.ROOT)) }
            }
            if (args[0].equals("check", ignoreCase = true)) {
                return Bukkit.getOnlinePlayers().map { it.name }.filter { it.lowercase(Locale.ROOT).startsWith(args[1].lowercase(Locale.ROOT)) }
            }
            if (args[0].equals("whitelist", ignoreCase = true) || args[0].equals("wl", ignoreCase = true) ||
                args[0].equals("blacklist", ignoreCase = true) || args[0].equals("bl", ignoreCase = true)
            ) {
                val sub = listOf("add", "remove", "list")
                return sub.filter { it.startsWith(args[1].lowercase(Locale.ROOT)) }
            }
        }

        if (args.size == 3) {
            val isWl = args[0].equals("whitelist", ignoreCase = true) || args[0].equals("wl", ignoreCase = true)
            val isBl = args[0].equals("blacklist", ignoreCase = true) || args[0].equals("bl", ignoreCase = true)
            if (isWl || isBl) {
                if (args[1].equals("add", ignoreCase = true)) {
                    return Bukkit.getOnlinePlayers().map { it.name }.filter { it.lowercase(Locale.ROOT).startsWith(args[2].lowercase(Locale.ROOT)) }
                }
                if (args[1].equals("remove", ignoreCase = true)) {
                    val pool = if (isWl) {
                        listManager.getWhitelistedPlayers() + listManager.getWhitelistedIps()
                    } else {
                        listManager.getBlacklistedPlayers() + listManager.getBlacklistedIps()
                    }
                    return pool.filter { it.lowercase(Locale.ROOT).startsWith(args[2].lowercase(Locale.ROOT)) }
                }
            }
        }

        return emptyList()
    }
}
