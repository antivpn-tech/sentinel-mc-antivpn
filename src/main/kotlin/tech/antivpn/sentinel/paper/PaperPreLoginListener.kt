package tech.antivpn.sentinel.paper

import org.bukkit.ChatColor
import org.bukkit.event.EventHandler
import org.bukkit.event.EventPriority
import org.bukkit.event.Listener
import org.bukkit.event.player.AsyncPlayerPreLoginEvent
import java.util.concurrent.TimeUnit

/**
 * Event listener handling asynchronous player pre-login connection verification on Paper/Spigot/Bukkit.
 */
class PaperPreLoginListener(private val plugin: SentinelPaperPlugin) : Listener {

    @EventHandler(priority = EventPriority.LOWEST)
    fun onAsyncPlayerPreLogin(event: AsyncPlayerPreLoginEvent) {
        if (event.loginResult != AsyncPlayerPreLoginEvent.Result.ALLOWED) return
        val playerName = event.name
        val address = event.address ?: return
        val ip = address.hostAddress.substringBefore('%')

        // 1. Whitelist Check (Fastest Path - Bypasses edge API query)
        if (plugin.listManager.isWhitelisted(playerName, ip)) {
            return
        }

        // 2. Blacklist Check (Immediate Rejection)
        if (plugin.listManager.isBlacklisted(playerName, ip)) {
            val kickMessage = "${ChatColor.RED}You are blacklisted from this server by Sentinel."
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_BANNED, kickMessage)
            plugin.waveLogger.logBlacklistBlock(playerName, ip)
            return
        }

        val config = plugin.sentinelConfig

        try {
            // Evaluate IP asynchronously against Sentinel Edge API with bounded timeout
            val verdict = plugin.sentinelClient.evaluate(ip)
                .get(config.safeTimeoutMs + 1000L, TimeUnit.MILLISECONDS)

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
                        event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, kickMessage)
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
        }
    }
}
