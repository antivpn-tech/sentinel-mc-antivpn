package tech.antivpn.sentinel.bungee

import net.md_5.bungee.api.ChatColor
import net.md_5.bungee.api.chat.TextComponent
import net.md_5.bungee.api.event.PreLoginEvent
import net.md_5.bungee.api.plugin.Listener
import net.md_5.bungee.event.EventHandler
import java.net.InetSocketAddress
import java.util.concurrent.TimeUnit

/**
 * High-performance asynchronous PreLoginEvent handler for BungeeCord and Waterfall proxy networks.
 */
class BungeePreLoginListener(private val plugin: SentinelBungeePlugin) : Listener {

    @EventHandler(priority = -64) // LOWEST priority
    fun onPreLogin(event: PreLoginEvent) {
        if (event.isCancelled) return
        val playerName = event.connection.name
        val socketAddress = event.connection.address as? InetSocketAddress ?: return
        val inetAddress = socketAddress.address ?: return
        val ip = inetAddress.hostAddress.substringBefore('%')

        // 1. Whitelist Check (Fastest Path - Bypasses edge API query)
        if (plugin.listManager.isWhitelisted(playerName, ip)) {
            return
        }

        // 2. Blacklist Check (Immediate Rejection)
        if (plugin.listManager.isBlacklisted(playerName, ip)) {
            val kickMessage = "${ChatColor.RED}You are blacklisted from this server by Sentinel."
            event.isCancelled = true
            event.setCancelReason(*TextComponent.fromLegacyText(kickMessage))
            plugin.waveLogger.logBlacklistBlock(playerName, ip)
            return
        }

        // Register async intent for non-blocking callback execution
        val config = plugin.sentinelConfig
        event.registerIntent(plugin)
        plugin.sentinelClient.evaluate(ip)
            .orTimeout(config.safeTimeoutMs + 1000L, TimeUnit.MILLISECONDS)
            .whenComplete { verdict, ex ->
                try {
                    if (ex != null || verdict == null) {
                        plugin.waveLogger.logEvaluationError(playerName, ip, ex?.message ?: "timeout")
                        return@whenComplete
                    }
                    val isThreat = verdict.isThreat(config.riskThreshold, config.allowGamingOptimizers)

                    if (isThreat || !config.discordNotifyOnlyOnThreat) {
                        val enforce = !config.isAuditMode

                        if (enforce && isThreat) {
                            if (config.graduatedDefense && !verdict.isHardThreat(config.riskThreshold, config.allowGamingOptimizers)) {
                                // Graduated Defense: Allow connection to protect legitimate players on shared mobile CGNAT pools, but alert staff
                                plugin.webhookNotifier.sendAlert(playerName, verdict, false)
                                plugin.waveLogger.logGraduatedDefense(playerName, ip, verdict)
                            } else {
                                // Deterministic hard threat: Enforce kick
                                plugin.webhookNotifier.sendAlert(playerName, verdict, true)
                                val kickMessage = ChatColor.translateAlternateColorCodes(
                                    '&',
                                    config.buildEnforcementKickMessage(
                                        threat = verdict.threatType,
                                        risk = verdict.riskScore,
                                        ip = ip,
                                        player = playerName
                                    )
                                )
                                event.isCancelled = true
                                event.setCancelReason(*TextComponent.fromLegacyText(kickMessage))
                                plugin.waveLogger.logEnforceBlock(playerName, ip, verdict)
                            }
                        } else {
                            plugin.webhookNotifier.sendAlert(playerName, verdict, false)
                            if (isThreat) {
                                plugin.waveLogger.logAuditFlag(playerName, ip, verdict)
                            }
                        }
                    }
                } catch (e: Exception) {
                    plugin.waveLogger.logEvaluationError(playerName, ip, e.message ?: e.javaClass.simpleName)
                } finally {
                    event.completeIntent(plugin)
                }
            }
    }
}
