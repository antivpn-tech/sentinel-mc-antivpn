package tech.antivpn.sentinel.velocity

import com.velocitypowered.api.command.CommandSource
import com.velocitypowered.api.command.SimpleCommand
import net.kyori.adventure.text.Component
import net.kyori.adventure.text.format.NamedTextColor
import tech.antivpn.sentinel.common.SentinelConfig
import tech.antivpn.sentinel.common.SentinelListManager
import java.util.Locale

/**
 * Velocity Proxy implementation of the /sentinel command.
 */
class SentinelVelocityCommand(private val plugin: SentinelVelocityPlugin) : SimpleCommand {

    override fun hasPermission(invocation: SimpleCommand.Invocation): Boolean {
        return invocation.source().hasPermission("sentinel.admin")
    }

    override fun execute(invocation: SimpleCommand.Invocation) {
        val source = invocation.source()
        val args = invocation.arguments()

        if (args.isEmpty() || args[0].equals("status", ignoreCase = true)) {
            val config = plugin.sentinelConfig
            source.sendMessage(Component.text("---------------------------------------------", NamedTextColor.DARK_GRAY))
            source.sendMessage(Component.text("Sentinel Anti-VPN Status (Velocity)", NamedTextColor.GOLD))
            source.sendMessage(
                Component.text("Mode: ", NamedTextColor.GRAY).append(
                    if (config.isAuditMode) Component.text("AUDIT (Dry-Run)", NamedTextColor.YELLOW)
                    else Component.text("ENFORCE (Blocking)", NamedTextColor.RED)
                )
            )
            source.sendMessage(
                Component.text("Risk Threshold: ", NamedTextColor.GRAY)
                    .append(Component.text("${config.riskThreshold} / 100", NamedTextColor.WHITE))
            )
            source.sendMessage(
                Component.text("Console Logs: ", NamedTextColor.GRAY).append(
                    if (config.consoleLogs) Component.text("ENABLED (Wave Summary)", NamedTextColor.GREEN)
                    else Component.text("DISABLED (Silent)", NamedTextColor.RED)
                )
            )
            source.sendMessage(
                Component.text("Cached IPs: ", NamedTextColor.GRAY)
                    .append(Component.text("${plugin.sentinelClient.cacheSize}", NamedTextColor.WHITE))
            )
            source.sendMessage(
                Component.text("Whitelisted: ", NamedTextColor.GRAY)
                    .append(Component.text("${plugin.listManager.getWhitelistedPlayers().size} players, ${plugin.listManager.getWhitelistedIps().size} IPs", NamedTextColor.GREEN))
            )
            source.sendMessage(
                Component.text("Blacklisted: ", NamedTextColor.GRAY)
                    .append(Component.text("${plugin.listManager.getBlacklistedPlayers().size} players, ${plugin.listManager.getBlacklistedIps().size} IPs", NamedTextColor.RED))
            )
            source.sendMessage(
                Component.text("Discord Webhook: ", NamedTextColor.GRAY).append(
                    if (config.isDiscordConfigured) Component.text("Connected", NamedTextColor.GREEN)
                    else Component.text("Disabled / Unset", NamedTextColor.RED)
                )
            )
            source.sendMessage(Component.text("---------------------------------------------", NamedTextColor.DARK_GRAY))
            return
        }

        if (args[0].equals("reload", ignoreCase = true)) {
            plugin.loadConfiguration()
            source.sendMessage(Component.text("[Sentinel] Configuration and whitelist/blacklist reloaded.", NamedTextColor.GREEN))
            return
        }

        if (args[0].equals("logs", ignoreCase = true) || args[0].equals("console", ignoreCase = true)) {
            val nextState = SentinelConfig.parseConsoleLogsToggle(args.getOrNull(1), plugin.sentinelConfig.consoleLogs)
            if (nextState == null) {
                source.sendMessage(Component.text("Usage: /sentinel logs [on | off | toggle]", NamedTextColor.RED))
                return
            }
            plugin.setConsoleLogs(nextState)
            if (nextState) {
                source.sendMessage(Component.text("[Sentinel] Console logs and wave summaries are now ENABLED.", NamedTextColor.GREEN))
            } else {
                source.sendMessage(Component.text("[Sentinel] Console logs are now DISABLED (silent mode).", NamedTextColor.YELLOW))
            }
            return
        }

        // Whitelist commands: /sentinel whitelist [add|remove|list] <player|ip>
        if (args[0].equals("whitelist", ignoreCase = true) || args[0].equals("wl", ignoreCase = true)) {
            if (args.size < 2 || args[1].equals("list", ignoreCase = true)) {
                val players = plugin.listManager.getWhitelistedPlayers()
                val ips = plugin.listManager.getWhitelistedIps()
                source.sendMessage(Component.text("---------------------------------------------", NamedTextColor.DARK_GRAY))
                source.sendMessage(Component.text("Sentinel Whitelist", NamedTextColor.GREEN))
                source.sendMessage(
                    Component.text("Players (${players.size}): ", NamedTextColor.GRAY)
                        .append(Component.text(if (players.isEmpty()) "None" else players.joinToString(", "), NamedTextColor.WHITE))
                )
                source.sendMessage(
                    Component.text("IPs (${ips.size}): ", NamedTextColor.GRAY)
                        .append(Component.text(if (ips.isEmpty()) "None" else ips.joinToString(", "), NamedTextColor.WHITE))
                )
                source.sendMessage(Component.text("---------------------------------------------", NamedTextColor.DARK_GRAY))
                return
            }

            if (args[1].equals("add", ignoreCase = true) && args.size >= 3) {
                val target = args[2]
                if (!SentinelListManager.isValidTarget(target)) {
                    source.sendMessage(Component.text("[Sentinel] '$target' is not a valid IP address, CIDR subnet, or Minecraft username.", NamedTextColor.RED))
                    return
                }
                val added = plugin.listManager.addWhitelist(target)
                if (added) {
                    source.sendMessage(Component.text("[Sentinel] Added '$target' to the whitelist.", NamedTextColor.GREEN))
                } else {
                    source.sendMessage(Component.text("[Sentinel] '$target' is already whitelisted.", NamedTextColor.YELLOW))
                }
                return
            }

            if (args[1].equals("remove", ignoreCase = true) && args.size >= 3) {
                val target = args[2]
                val removed = plugin.listManager.removeWhitelist(target)
                if (removed) {
                    source.sendMessage(Component.text("[Sentinel] Removed '$target' from the whitelist.", NamedTextColor.GREEN))
                } else {
                    source.sendMessage(Component.text("[Sentinel] '$target' was not found in the whitelist.", NamedTextColor.RED))
                }
                return
            }

            source.sendMessage(Component.text("Usage: /sentinel whitelist [add <player|ip> | remove <player|ip> | list]", NamedTextColor.RED))
            return
        }

        // Blacklist commands: /sentinel blacklist [add|remove|list] <player|ip>
        if (args[0].equals("blacklist", ignoreCase = true) || args[0].equals("bl", ignoreCase = true)) {
            if (args.size < 2 || args[1].equals("list", ignoreCase = true)) {
                val players = plugin.listManager.getBlacklistedPlayers()
                val ips = plugin.listManager.getBlacklistedIps()
                source.sendMessage(Component.text("---------------------------------------------", NamedTextColor.DARK_GRAY))
                source.sendMessage(Component.text("Sentinel Blacklist", NamedTextColor.RED))
                source.sendMessage(
                    Component.text("Players (${players.size}): ", NamedTextColor.GRAY)
                        .append(Component.text(if (players.isEmpty()) "None" else players.joinToString(", "), NamedTextColor.WHITE))
                )
                source.sendMessage(
                    Component.text("IPs (${ips.size}): ", NamedTextColor.GRAY)
                        .append(Component.text(if (ips.isEmpty()) "None" else ips.joinToString(", "), NamedTextColor.WHITE))
                )
                source.sendMessage(Component.text("---------------------------------------------", NamedTextColor.DARK_GRAY))
                return
            }

            if (args[1].equals("add", ignoreCase = true) && args.size >= 3) {
                val target = args[2]
                if (!SentinelListManager.isValidTarget(target)) {
                    source.sendMessage(Component.text("[Sentinel] '$target' is not a valid IP address, CIDR subnet, or Minecraft username.", NamedTextColor.RED))
                    return
                }
                val added = plugin.listManager.addBlacklist(target)
                if (added) {
                    source.sendMessage(Component.text("[Sentinel] Added '$target' to the blacklist.", NamedTextColor.RED))
                } else {
                    source.sendMessage(Component.text("[Sentinel] '$target' is already blacklisted.", NamedTextColor.YELLOW))
                }
                return
            }

            if (args[1].equals("remove", ignoreCase = true) && args.size >= 3) {
                val target = args[2]
                val removed = plugin.listManager.removeBlacklist(target)
                if (removed) {
                    source.sendMessage(Component.text("[Sentinel] Removed '$target' from the blacklist.", NamedTextColor.GREEN))
                } else {
                    source.sendMessage(Component.text("[Sentinel] '$target' was not found in the blacklist.", NamedTextColor.RED))
                }
                return
            }

            source.sendMessage(Component.text("Usage: /sentinel blacklist [add <player|ip> | remove <player|ip> | list]", NamedTextColor.RED))
            return
        }

        if (args[0].equals("check", ignoreCase = true) && args.size >= 2) {
            val targetInput = args[1]
            var targetIp: String
            var displayName: String

            if (!SentinelListManager.isSingleIpAddress(targetInput)) {
                val onlinePlayer = plugin.server.getPlayer(targetInput)
                val inetAddr = onlinePlayer.orElse(null)?.remoteAddress?.address
                if (onlinePlayer.isPresent && inetAddr != null) {
                    targetIp = inetAddr.hostAddress.substringBefore('%')
                    displayName = "${onlinePlayer.get().username} ($targetIp)"
                } else {
                    source.sendMessage(
                        Component.text(
                            "[Sentinel] Player '$targetInput' is not online on this proxy (or input is not a valid single IP). Provide a direct IP to check an offline target.",
                            NamedTextColor.RED
                        )
                    )
                    return
                }
            } else {
                targetIp = SentinelListManager.normalizeIp(targetInput)
                displayName = targetIp
            }

            source.sendMessage(Component.text("[Sentinel] Querying edge intelligence for $displayName...", NamedTextColor.GRAY))
            val finalDisplay = displayName
            val cfg = plugin.sentinelConfig
            plugin.sentinelClient.evaluate(targetIp).thenAccept { verdict ->
                val isThreat = verdict.isThreat(cfg.riskThreshold, cfg.allowGamingOptimizers)
                val color = when {
                    isThreat || verdict.riskScore >= cfg.riskThreshold -> NamedTextColor.RED
                    verdict.riskScore >= 40 -> NamedTextColor.YELLOW
                    else -> NamedTextColor.GREEN
                }
                source.sendMessage(Component.text("---------------------------------------------", NamedTextColor.DARK_GRAY))
                source.sendMessage(Component.text("[Sentinel Result] $finalDisplay", NamedTextColor.GOLD))
                source.sendMessage(Component.text("Verdict Action: ", NamedTextColor.GRAY).append(Component.text(verdict.action, color)))
                source.sendMessage(Component.text("Risk Score: ", NamedTextColor.GRAY).append(Component.text("${verdict.riskScore}/100", color)))
                source.sendMessage(Component.text("Threat Type: ", NamedTextColor.GRAY).append(Component.text(verdict.threatType, NamedTextColor.WHITE)))
                source.sendMessage(Component.text("ISP: ", NamedTextColor.GRAY).append(Component.text("AS${verdict.asn} ${verdict.provider}", NamedTextColor.WHITE)))
                source.sendMessage(Component.text("Location: ", NamedTextColor.GRAY).append(Component.text(verdict.getFormattedLocation(), NamedTextColor.WHITE)))
                if (verdict.reasons.isNotEmpty()) {
                    source.sendMessage(Component.text("Reasons: ", NamedTextColor.GRAY).append(Component.text(verdict.reasons.joinToString(", "), NamedTextColor.WHITE)))
                }
                source.sendMessage(Component.text("---------------------------------------------", NamedTextColor.DARK_GRAY))
            }.exceptionally { ex ->
                source.sendMessage(Component.text("[Sentinel] Failed to check $finalDisplay: ${ex.message}", NamedTextColor.RED))
                null
            }
            return
        }

        source.sendMessage(Component.text("Usage: /sentinel [status | reload | logs <on|off> | check <ip|player> | whitelist | blacklist]", NamedTextColor.RED))
    }

    override fun suggest(invocation: SimpleCommand.Invocation): List<String> {
        if (!hasPermission(invocation)) {
            return emptyList()
        }
        val args = invocation.arguments()

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
                return plugin.server.allPlayers.map { it.username }.filter { it.lowercase(Locale.ROOT).startsWith(prefix) }
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
                    return plugin.server.allPlayers.map { it.username }.filter { it.lowercase(Locale.ROOT).startsWith(prefix) }
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
