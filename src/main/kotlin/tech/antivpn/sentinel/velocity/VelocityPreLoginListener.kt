package tech.antivpn.sentinel.velocity

import com.velocitypowered.api.event.EventTask
import com.velocitypowered.api.event.Subscribe
import com.velocitypowered.api.event.connection.PreLoginEvent
import net.kyori.adventure.text.Component
import net.kyori.adventure.text.format.NamedTextColor
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer
import java.util.concurrent.TimeUnit

/**
 * High-throughput asynchronous PreLoginEvent handler for Velocity proxy networks.
 */
class VelocityPreLoginListener(private val plugin: SentinelVelocityPlugin) {

    companion object {
        private val LEGACY_SERIALIZER = LegacyComponentSerializer.builder()
            .character('&')
            .hexColors()
            .useUnusualXRepeatedCharacterHexFormat()
            .build()
    }

    @Subscribe
    fun onPreLogin(event: PreLoginEvent): EventTask? {
        if (!event.result.isAllowed) return null
        val username = event.username
        val remoteAddress = event.connection.remoteAddress ?: return null
        val address = remoteAddress.address ?: return null
        val ip = address.hostAddress.substringBefore('%')

        // 1. Whitelist Check (Fastest Path - Bypasses edge API query)
        if (plugin.listManager.isWhitelisted(username, ip)) {
            return null
        }

        // 2. Blacklist Check (Immediate Rejection)
        if (plugin.listManager.isBlacklisted(username, ip)) {
            val kickComponent = Component.text("You are blacklisted from this server by Sentinel.", NamedTextColor.RED)
            event.result = PreLoginEvent.PreLoginComponentResult.denied(kickComponent)
            plugin.waveLogger.logBlacklistBlock(username, ip)
            return null
        }

        val config = plugin.sentinelConfig

        return EventTask.withContinuation { continuation ->
            plugin.sentinelClient.evaluate(ip)
                .orTimeout(config.safeTimeoutMs + 1000L, TimeUnit.MILLISECONDS)
                .whenComplete { verdict, ex ->
                    try {
                        if (ex != null || verdict == null) {
                            plugin.waveLogger.logEvaluationError(username, ip, ex?.message ?: "timeout")
                            return@whenComplete
                        }

                        val isThreat = verdict.isThreat(config.riskThreshold, config.allowGamingOptimizers)

                        if (isThreat || !config.discordNotifyOnlyOnThreat) {
                            val enforce = !config.isAuditMode

                            if (enforce && isThreat) {
                                if (config.graduatedDefense && !verdict.isHardThreat(config.riskThreshold, config.allowGamingOptimizers)) {
                                    // Graduated Defense: Allow connection to protect legitimate players on shared mobile CGNAT pools, but alert staff
                                    plugin.webhookNotifier.sendAlert(username, verdict, false)
                                    plugin.waveLogger.logGraduatedDefense(username, ip, verdict)
                                } else {
                                    // Deterministic hard threat: Enforce kick
                                    plugin.webhookNotifier.sendAlert(username, verdict, true)
                                    val formattedKick = config.buildEnforcementKickMessage(
                                        threat = verdict.threatType,
                                        risk = verdict.riskScore,
                                        ip = ip,
                                        player = username
                                    ).replace('§', '&')
                                    val kickComponent = LEGACY_SERIALIZER.deserialize(formattedKick)

                                    event.result = PreLoginEvent.PreLoginComponentResult.denied(kickComponent)
                                    plugin.waveLogger.logEnforceBlock(username, ip, verdict)
                                }
                            } else {
                                plugin.webhookNotifier.sendAlert(username, verdict, false)
                                if (isThreat) {
                                    plugin.waveLogger.logAuditFlag(username, ip, verdict)
                                }
                            }
                        }
                    } catch (e: Exception) {
                        plugin.waveLogger.logEvaluationError(username, ip, e.message ?: e.javaClass.simpleName)
                    } finally {
                        continuation.resume()
                    }
                }
        }
    }
}
