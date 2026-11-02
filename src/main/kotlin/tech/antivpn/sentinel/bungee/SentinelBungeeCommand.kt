package tech.antivpn.sentinel.bungee

import net.md_5.bungee.api.ChatColor
import net.md_5.bungee.api.CommandSender
import net.md_5.bungee.api.chat.TextComponent
import net.md_5.bungee.api.plugin.Command
import net.md_5.bungee.api.plugin.TabExecutor
import tech.antivpn.sentinel.common.SentinelConfig
import tech.antivpn.sentinel.common.SentinelListManager
import java.util.Locale

/**
 * BungeeCord / Waterfall implementation of the /sentinel command.
 */
class SentinelBungeeCommand(private val plugin: SentinelBungeePlugin) :
    Command("sentinel", "sentinel.admin", "antivpn"), TabExecutor {

    override fun execute(sender: CommandSender, args: Array<out String>) {
        if (!sender.hasPermission("sentinel.admin")) {
            sender.sendMessage(TextComponent("${ChatColor.RED}You do not have permission to execute Sentinel commands."))
            return
        }

        if (args.isEmpty() || args[0].equals("status", ignoreCase = true)) {
            val config = plugin.sentinelConfig
            sender.sendMessage(TextComponent("${ChatColor.DARK_GRAY}---------------------------------------------"))
            sender.sendMessage(TextComponent("${ChatColor.GOLD}${ChatColor.BOLD}Sentinel Anti-VPN Status (BungeeCord)"))
            sender.sendMessage(TextComponent("${ChatColor.GRAY}Mode: " + if (config.isAuditMode) "${ChatColor.YELLOW}AUDIT (Dry-Run)" else "${ChatColor.RED}ENFORCE (Blocking)"))
            sender.sendMessage(TextComponent("${ChatColor.GRAY}Risk Threshold: ${ChatColor.WHITE}${config.riskThreshold} / 100"))
            sender.sendMessage(TextComponent("${ChatColor.GRAY}Console Logs: " + if (config.consoleLogs) "${ChatColor.GREEN}ENABLED (Wave Summary)" else "${ChatColor.RED}DISABLED (Silent)"))
            sender.sendMessage(TextComponent("${ChatColor.GRAY}Cached IPs: ${ChatColor.WHITE}${plugin.sentinelClient.cacheSize}"))
            sender.sendMessage(TextComponent("${ChatColor.GRAY}Whitelisted: ${ChatColor.GREEN}${plugin.listManager.getWhitelistedPlayers().size} players, ${plugin.listManager.getWhitelistedIps().size} IPs"))
            sender.sendMessage(TextComponent("${ChatColor.GRAY}Blacklisted: ${ChatColor.RED}${plugin.listManager.getBlacklistedPlayers().size} players, ${plugin.listManager.getBlacklistedIps().size} IPs"))
            sender.sendMessage(TextComponent("${ChatColor.GRAY}Discord Webhook: " + if (config.isDiscordConfigured) "${ChatColor.GREEN}Connected" else "${ChatColor.RED}Disabled / Unset"))
            sender.sendMessage(TextComponent("${ChatColor.DARK_GRAY}---------------------------------------------"))
            return
        }

        if (args[0].equals("reload", ignoreCase = true)) {
            plugin.loadConfiguration()
            sender.sendMessage(TextComponent("${ChatColor.GREEN}[Sentinel] Configuration and whitelist/blacklist reloaded."))
            return
        }

        if (args[0].equals("logs", ignoreCase = true) || args[0].equals("console", ignoreCase = true)) {
            val nextState = SentinelConfig.parseConsoleLogsToggle(args.getOrNull(1), plugin.sentinelConfig.consoleLogs)
            if (nextState == null) {
                sender.sendMessage(TextComponent("${ChatColor.RED}Usage: /sentinel logs [on | off | toggle]"))
                return
            }
            plugin.setConsoleLogs(nextState)
            if (nextState) {
                sender.sendMessage(TextComponent("${ChatColor.GREEN}[Sentinel] Console logs and wave summaries are now ENABLED."))
            } else {
                sender.sendMessage(TextComponent("${ChatColor.YELLOW}[Sentinel] Console logs are now DISABLED (silent mode)."))
            }
            return
        }

        // Whitelist commands: /sentinel whitelist [add|remove|list] <player|ip>
        if (args[0].equals("whitelist", ignoreCase = true) || args[0].equals("wl", ignoreCase = true)) {
            if (args.size < 2 || args[1].equals("list", ignoreCase = true)) {
                val players = plugin.listManager.getWhitelistedPlayers()
                val ips = plugin.listManager.getWhitelistedIps()
                sender.sendMessage(TextComponent("${ChatColor.DARK_GRAY}---------------------------------------------"))
                sender.sendMessage(TextComponent("${ChatColor.GREEN}${ChatColor.BOLD}Sentinel Whitelist"))
                sender.sendMessage(TextComponent("${ChatColor.GRAY}Players (${players.size}): ${ChatColor.WHITE}" + if (players.isEmpty()) "None" else players.joinToString(", ")))
                sender.sendMessage(TextComponent("${ChatColor.GRAY}IPs (${ips.size}): ${ChatColor.WHITE}" + if (ips.isEmpty()) "None" else ips.joinToString(", ")))
                sender.sendMessage(TextComponent("${ChatColor.DARK_GRAY}---------------------------------------------"))
                return
            }

            if (args[1].equals("add", ignoreCase = true) && args.size >= 3) {
                val target = args[2]
                if (!SentinelListManager.isValidTarget(target)) {
                    sender.sendMessage(TextComponent("${ChatColor.RED}[Sentinel] '$target' is not a valid IP address, CIDR subnet, or Minecraft username."))
                    return
                }
                val added = plugin.listManager.addWhitelist(target)
                if (added) {
                    sender.sendMessage(TextComponent("${ChatColor.GREEN}[Sentinel] Added '$target' to the whitelist."))
                } else {
                    sender.sendMessage(TextComponent("${ChatColor.YELLOW}[Sentinel] '$target' is already whitelisted."))
                }
                return
            }

            if (args[1].equals("remove", ignoreCase = true) && args.size >= 3) {
                val target = args[2]
                val removed = plugin.listManager.removeWhitelist(target)
                if (removed) {
                    sender.sendMessage(TextComponent("${ChatColor.GREEN}[Sentinel] Removed '$target' from the whitelist."))
                } else {
                    sender.sendMessage(TextComponent("${ChatColor.RED}[Sentinel] '$target' was not found in the whitelist."))
                }
                return
            }

            sender.sendMessage(TextComponent("${ChatColor.RED}Usage: /sentinel whitelist [add <player|ip> | remove <player|ip> | list]"))
            return
        }

        // Blacklist commands: /sentinel blacklist [add|remove|list] <player|ip>
        if (args[0].equals("blacklist", ignoreCase = true) || args[0].equals("bl", ignoreCase = true)) {
            if (args.size < 2 || args[1].equals("list", ignoreCase = true)) {
                val players = plugin.listManager.getBlacklistedPlayers()
                val ips = plugin.listManager.getBlacklistedIps()
                sender.sendMessage(TextComponent("${ChatColor.DARK_GRAY}---------------------------------------------"))
                sender.sendMessage(TextComponent("${ChatColor.RED}${ChatColor.BOLD}Sentinel Blacklist"))
                sender.sendMessage(TextComponent("${ChatColor.GRAY}Players (${players.size}): ${ChatColor.WHITE}" + if (players.isEmpty()) "None" else players.joinToString(", ")))
                sender.sendMessage(TextComponent("${ChatColor.GRAY}IPs (${ips.size}): ${ChatColor.WHITE}" + if (ips.isEmpty()) "None" else ips.joinToString(", ")))
                sender.sendMessage(TextComponent("${ChatColor.DARK_GRAY}---------------------------------------------"))
                return
            }

            if (args[1].equals("add", ignoreCase = true) && args.size >= 3) {
                val target = args[2]
                if (!SentinelListManager.isValidTarget(target)) {
                    sender.sendMessage(TextComponent("${ChatColor.RED}[Sentinel] '$target' is not a valid IP address, CIDR subnet, or Minecraft username."))
                    return
                }
                val added = plugin.listManager.addBlacklist(target)
                if (added) {
                    sender.sendMessage(TextComponent("${ChatColor.RED}[Sentinel] Added '$target' to the blacklist."))
                } else {
                    sender.sendMessage(TextComponent("${ChatColor.YELLOW}[Sentinel] '$target' is already blacklisted."))
                }
                return
            }

            if (args[1].equals("remove", ignoreCase = true) && args.size >= 3) {
                val target = args[2]
                val removed = plugin.listManager.removeBlacklist(target)
                if (removed) {
                    sender.sendMessage(TextComponent("${ChatColor.GREEN}[Sentinel] Removed '$target' from the blacklist."))
                } else {
                    sender.sendMessage(TextComponent("${ChatColor.RED}[Sentinel] '$target' was not found in the blacklist."))
                }
                return
            }

            sender.sendMessage(TextComponent("${ChatColor.RED}Usage: /sentinel blacklist [add <player|ip> | remove <player|ip> | list]"))
            return
        }

        if (args[0].equals("check", ignoreCase = true) && args.size >= 2) {
            val targetInput = args[1]
            var targetIp: String
            var displayName: String

            if (!SentinelListManager.isSingleIpAddress(targetInput)) {
                val onlinePlayer = plugin.proxy.getPlayer(targetInput)
                val inetAddr = (onlinePlayer?.socketAddress as? java.net.InetSocketAddress)?.address
                if (onlinePlayer != null && inetAddr != null) {
                    targetIp = inetAddr.hostAddress.substringBefore('%')
                    displayName = "${onlinePlayer.name} ($targetIp)"
                } else {
                    sender.sendMessage(
                        TextComponent(
                            "${ChatColor.RED}[Sentinel] Player '$targetInput' is not online on this proxy (or input is not a valid single IP). Provide a direct IP to check an offline target."
                        )
                    )
                    return
                }
            } else {
                targetIp = SentinelListManager.normalizeIp(targetInput)
                displayName = targetIp
            }

            sender.sendMessage(TextComponent("${ChatColor.GRAY}[Sentinel] Querying edge intelligence for $displayName..."))
            val finalDisplay = displayName
            val cfg = plugin.sentinelConfig
            plugin.sentinelClient.evaluate(targetIp).thenAccept { verdict ->
                val isThreat = verdict.isThreat(cfg.riskThreshold, cfg.allowGamingOptimizers)
                val color = when {
                    isThreat || verdict.riskScore >= cfg.riskThreshold -> ChatColor.RED
                    verdict.riskScore >= 40 -> ChatColor.YELLOW
                    else -> ChatColor.GREEN
                }
                sender.sendMessage(TextComponent("${ChatColor.DARK_GRAY}---------------------------------------------"))
                sender.sendMessage(TextComponent("${ChatColor.GOLD}[Sentinel Result] ${ChatColor.WHITE}$finalDisplay"))
                sender.sendMessage(TextComponent("${ChatColor.GRAY}Verdict Action: $color${verdict.action}"))
                sender.sendMessage(TextComponent("${ChatColor.GRAY}Risk Score: $color${verdict.riskScore}/100"))
                sender.sendMessage(TextComponent("${ChatColor.GRAY}Threat Type: ${ChatColor.WHITE}${verdict.threatType}"))
                sender.sendMessage(TextComponent("${ChatColor.GRAY}ISP: ${ChatColor.WHITE}AS${verdict.asn} ${verdict.provider}"))
                sender.sendMessage(TextComponent("${ChatColor.GRAY}Location: ${ChatColor.WHITE}${verdict.getFormattedLocation()}"))
                if (verdict.reasons.isNotEmpty()) {
                    sender.sendMessage(TextComponent("${ChatColor.GRAY}Reasons: ${ChatColor.WHITE}${verdict.reasons.joinToString(", ")}"))
                }
                sender.sendMessage(TextComponent("${ChatColor.DARK_GRAY}---------------------------------------------"))
            }.exceptionally { ex ->
                sender.sendMessage(TextComponent("${ChatColor.RED}[Sentinel] Failed to check $finalDisplay: ${ex.message}"))
                null
            }
            return
        }

        sender.sendMessage(TextComponent("${ChatColor.RED}Usage: /sentinel [status | reload | logs <on|off> | check <ip|player> | whitelist | blacklist]"))
    }

    override fun onTabComplete(sender: CommandSender, args: Array<out String>): Iterable<String> {
        if (!sender.hasPermission("sentinel.admin")) {
            return emptyList()
        }

        if (args.isEmpty() || args.size == 1) {
            val prefix = if (args.isEmpty()) "" else args[0].lowercase(Locale.ROOT)
            return listOf("status", "reload", "logs", "check", "whitelist", "blacklist")
                .filter { it.startsWith(prefix) }
        }

        if (args.size == 2) {
            val prefix = args[1].lowercase(Locale.ROOT)
            if (args[0].equals("logs", ignoreCase = true) || args[0].equals("console", ignoreCase = true)) {
                return listOf("on", "off", "toggle").filter { it.startsWith(prefix) }
            }
            if (args[0].equals("check", ignoreCase = true)) {
                return plugin.proxy.players.map { it.name }.filter { it.lowercase(Locale.ROOT).startsWith(prefix) }
            }
            if (args[0].equals("whitelist", ignoreCase = true) || args[0].equals("wl", ignoreCase = true) ||
                args[0].equals("blacklist", ignoreCase = true) || args[0].equals("bl", ignoreCase = true)
            ) {
                return listOf("add", "remove", "list").filter { it.startsWith(prefix) }
            }
        }

        if (args.size == 3) {
            val prefix = args[2].lowercase(Locale.ROOT)
            val isWl = args[0].equals("whitelist", ignoreCase = true) || args[0].equals("wl", ignoreCase = true)
            val isBl = args[0].equals("blacklist", ignoreCase = true) || args[0].equals("bl", ignoreCase = true)
            if (isWl || isBl) {
                if (args[1].equals("add", ignoreCase = true)) {
                    return plugin.proxy.players.map { it.name }.filter { it.lowercase(Locale.ROOT).startsWith(prefix) }
                }
                if (args[1].equals("remove", ignoreCase = true)) {
                    val pool = if (isWl) {
                        plugin.listManager.getWhitelistedPlayers() + plugin.listManager.getWhitelistedIps()
                    } else {
                        plugin.listManager.getBlacklistedPlayers() + plugin.listManager.getBlacklistedIps()
                    }
                    return pool.filter { it.lowercase(Locale.ROOT).startsWith(prefix) }
                }
            }
        }

        return emptyList()
    }
}
