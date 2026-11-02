package tech.antivpn.sentinel.common

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import tech.antivpn.sentinel.common.model.SentinelVerdict
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * High-performance, rate-limit-aware Discord Webhook dispatcher for Sentinel threat intelligence alerts.
 * Features automatic flood aggregation to eliminate Discord HTTP 429 rate limit drops during bot attacks.
 */
class DiscordWebhookNotifier(
    private val config: SentinelConfig,
    private val errorLogger: (String) -> Unit = {}
) {
    private val httpClient: HttpClient = HttpClient.newBuilder()
        .version(HttpClient.Version.HTTP_2)
        .connectTimeout(Duration.ofSeconds(3))
        .build()

    private val alertQueue = ConcurrentLinkedQueue<AlertItem>()
    private val queuedCount = AtomicInteger(0)
    private val scheduler: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { r ->
        val t = Thread(r, "Sentinel-Discord-Batcher")
        t.isDaemon = true
        t
    }

    private val burstCounter = AtomicInteger(0)
    private var lastBurstReset = System.currentTimeMillis()
    @Volatile
    private var rateLimitUntil = 0L

    private data class AlertItem(
        val playerName: String?,
        val verdict: SentinelVerdict,
        val wasEnforced: Boolean,
        val timestamp: Long = System.currentTimeMillis()
    )

    init {
        // Flush queued alerts every 1.5 seconds
        scheduler.scheduleWithFixedDelay(::flushQueue, 1500, 1500, TimeUnit.MILLISECONDS)
    }

    /**
     * Dispatches an asynchronous Discord notification, automatically batching under high-volume floods.
     */
    fun sendAlert(playerName: String?, verdict: SentinelVerdict, wasEnforced: Boolean): CompletableFuture<Void> {
        if (!config.isDiscordConfigured) {
            return CompletableFuture.completedFuture(null)
        }

        var sendImmediately = false
        val now = System.currentTimeMillis()
        synchronized(this) {
            if (now - lastBurstReset > 2000) {
                burstCounter.set(0)
                lastBurstReset = now
            }
            if (now >= rateLimitUntil && burstCounter.get() < 2 && alertQueue.isEmpty()) {
                burstCounter.incrementAndGet()
                sendImmediately = true
            } else if (queuedCount.get() < 2000) {
                alertQueue.add(AlertItem(playerName, verdict, wasEnforced))
                queuedCount.incrementAndGet()
            }
        }

        if (sendImmediately) {
            return dispatchSingleAlert(playerName, verdict, wasEnforced)
        }
        return CompletableFuture.completedFuture(null)
    }

    private fun flushQueue() {
        val drained = mutableListOf<AlertItem>()
        var canSendSingle = false

        synchronized(this) {
            val now = System.currentTimeMillis()
            if (now < rateLimitUntil && !scheduler.isShutdown) {
                return
            }
            if (alertQueue.isEmpty()) {
                queuedCount.set(0)
                return
            }

            var item: AlertItem?
            while (alertQueue.poll().also { item = it } != null) {
                queuedCount.updateAndGet { if (it > 0) it - 1 else 0 }
                item?.let { drained.add(it) }
                if (drained.size >= 250) break
            }
            if (alertQueue.isEmpty()) {
                queuedCount.set(0)
            }

            if (drained.isEmpty()) return

            if (now - lastBurstReset > 2000) {
                burstCounter.set(0)
                lastBurstReset = now
            }
            if (drained.size <= 2) {
                if (burstCounter.get() + drained.size <= 2 || scheduler.isShutdown) {
                    burstCounter.addAndGet(drained.size)
                    canSendSingle = true
                } else {
                    for (item in drained) {
                        if (queuedCount.get() < 2000) {
                            alertQueue.add(item)
                            queuedCount.incrementAndGet()
                        }
                    }
                    return
                }
            } else {
                burstCounter.incrementAndGet()
            }
        }

        if (canSendSingle) {
            for (a in drained) {
                dispatchSingleAlert(a.playerName, a.verdict, a.wasEnforced)
            }
        } else {
            dispatchAggregatedAttackAlert(drained)
        }
    }

    private fun dispatchSingleAlert(playerName: String?, verdict: SentinelVerdict, wasEnforced: Boolean): CompletableFuture<Void> {
        return try {
            val payload = JsonObject()
            payload.addProperty("username", "Sentinel Anti-VPN")

            val embed = JsonObject()
            val isThreat = verdict.isThreat(config.riskThreshold, config.allowGamingOptimizers)
            val isGraduatedAllow = isThreat && !wasEnforced && !config.isAuditMode
            val titlePrefix = when {
                wasEnforced -> "[SENTINEL ENFORCE]"
                isGraduatedAllow -> "[SENTINEL GRADUATED]"
                isThreat -> "[SENTINEL AUDIT]"
                else -> "[SENTINEL ALLOW]"
            }
            val titleSuffix = if (isThreat) "Flagged" else "Verified"
            embed.addProperty("title", "$titlePrefix ${verdict.threatType} $titleSuffix")
            embed.addProperty("color", when {
                wasEnforced -> 0xEF4444
                isThreat -> 0xF59E0B
                else -> 0x10B981
            })
            embed.addProperty("timestamp", Instant.now().toString())

            val fields = JsonArray()
            addField(fields, "Player", "`${sanitizePlayerName(playerName)}`", true)
            addField(fields, "IP Address", "`${verdict.ip}`", true)
            addField(fields, "Risk Rating", "**${verdict.riskScore} / 100** (${getRiskSeverity(verdict.riskScore)})", true)

            val ispVal = "AS${verdict.asn} - ${verdict.provider} (${verdict.getFormattedLocation()})"
            addField(fields, "ISP & Network Details", ispVal, false)
            addField(fields, "Threat Classification", "${verdict.threatType} [Verdict: ${verdict.action}]", true)
            val actionTaken = when {
                wasEnforced -> "BLOCKED (Player Kicked)"
                isGraduatedAllow -> "GRADUATED DEFENSE (Player Allowed - Soft Alert)"
                isThreat -> "AUDIT (Player Allowed - Dry Run Test)"
                else -> "ALLOWED (Clean Connection)"
            }
            addField(fields, "Action Taken", actionTaken, true)

            val reasons = verdict.reasons
            if (reasons.isNotEmpty()) {
                val sb = StringBuilder()
                for (r in reasons) {
                    sb.append("• ").append(r).append("\n")
                }
                val text = if (sb.length > 1024) sb.substring(0, 1021) + "..." else sb.toString()
                addField(fields, "Detection Reasons", text, false)
            }

            embed.add("fields", fields)

            val footer = JsonObject()
            footer.addProperty("text", "Server: ${config.discordServerName} | Edge Latency: ${verdict.durationMs}ms")
            embed.add("footer", footer)

            val embedsArray = JsonArray()
            embedsArray.add(embed)
            payload.add("embeds", embedsArray)

            postWebhook(payload.toString())
        } catch (e: Exception) {
            errorLogger("[Sentinel] Failed to construct single webhook: ${e.message}")
            CompletableFuture.completedFuture(null)
        }
    }

    private fun dispatchAggregatedAttackAlert(batch: List<AlertItem>): CompletableFuture<Void> {
        return try {
            val payload = JsonObject()
            payload.addProperty("username", "Sentinel Security")

            val enforcedCount = batch.count { it.wasEnforced }
            val auditCount = batch.size - enforcedCount
            val isMostlyEnforced = enforcedCount > 0

            val embed = JsonObject()
            embed.addProperty(
                "title",
                if (isMostlyEnforced) "[SENTINEL] High-Volume Threat Wave Neutralized" else "[SENTINEL AUDIT] High-Volume Connection Wave Logged"
            )
            embed.addProperty(
                "description",
                "**${batch.size} connections** processed ($enforcedCount blocked, $auditCount allowed/audited)."
            )
            embed.addProperty("color", if (isMostlyEnforced) 0xEF4444 else 0xF59E0B)
            embed.addProperty("timestamp", Instant.now().toString())

            val fields = JsonArray()
            addField(fields, "Connections Processed", "**${batch.size}** ($enforcedCount blocked)", true)

            val threatCounts = mutableMapOf<String, Int>()
            val samplePlayers = LinkedHashSet<String>()
            val uniqueCountries = LinkedHashSet<String>()

            for (item in batch) {
                threatCounts[item.verdict.threatType] = (threatCounts[item.verdict.threatType] ?: 0) + 1
                if (!item.playerName.isNullOrBlank() && samplePlayers.size < 8) {
                    samplePlayers.add("`${sanitizePlayerName(item.playerName)}`")
                }
                if (item.verdict.country.isNotBlank() && item.verdict.country != "ZZ") {
                    uniqueCountries.add(item.verdict.country)
                }
            }

            val threatsSummary = StringBuilder()
            for ((k, v) in threatCounts) {
                threatsSummary.append("• **$k**: $v\n")
            }
            val threatText = if (threatsSummary.isEmpty()) "None"
            else if (threatsSummary.length > 1024) threatsSummary.substring(0, 1021) + "..."
            else threatsSummary.toString()
            addField(fields, "Threat Breakdown", threatText, false)

            if (samplePlayers.isNotEmpty()) {
                addField(fields, "Sample Players", samplePlayers.joinToString(", "), false)
            }

            if (uniqueCountries.isNotEmpty()) {
                val countriesText = uniqueCountries.joinToString(", ").let {
                    if (it.length > 1024) it.substring(0, 1021) + "..." else it
                }
                addField(fields, "Origin Countries", countriesText, true)
            }

            embed.add("fields", fields)

            val footer = JsonObject()
            footer.addProperty("text", "Server: ${config.discordServerName} | Sentinel Edge Protection Active")
            embed.add("footer", footer)

            val embedsArray = JsonArray()
            embedsArray.add(embed)
            payload.add("embeds", embedsArray)

            postWebhook(payload.toString())
        } catch (e: Exception) {
            errorLogger("[Sentinel] Failed to construct batch webhook: ${e.message}")
            CompletableFuture.completedFuture(null)
        }
    }

    private fun postWebhook(jsonPayload: String): CompletableFuture<Void> {
        val request = try {
            HttpRequest.newBuilder()
                .uri(URI.create(config.discordWebhookUrl.trim()))
                .timeout(Duration.ofSeconds(4))
                .header("Content-Type", "application/json")
                .header("User-Agent", "Sentinel-Minecraft-Discord/2.0.3")
                .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                .build()
        } catch (e: Exception) {
            errorLogger("[Sentinel] Invalid Discord webhook URL configured: ${e.message}")
            return CompletableFuture.completedFuture(null)
        }

        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.discarding())
            .thenAccept { res ->
                if (res.statusCode() == 429) {
                    val retrySec = res.headers().firstValue("Retry-After").orElse("5").toDoubleOrNull() ?: 5.0
                    rateLimitUntil = System.currentTimeMillis() + (retrySec * 1000).toLong().coerceIn(1000L, 60_000L)
                    errorLogger("[Sentinel] Discord webhook rate-limited (HTTP 429); backing off for ${retrySec}s")
                } else if (res.statusCode() >= 400) {
                    errorLogger("[Sentinel] Discord webhook rejected with HTTP status ${res.statusCode()}")
                }
            }
            .orTimeout(5, TimeUnit.SECONDS)
            .exceptionally { ex ->
                errorLogger("[Sentinel] Failed to deliver Discord webhook: ${ex.message}")
                null
            }
    }

    private fun addField(fields: JsonArray, name: String, value: String, inline: Boolean) {
        val f = JsonObject()
        f.addProperty("name", name)
        f.addProperty("value", value)
        f.addProperty("inline", inline)
        fields.add(f)
    }

    private fun sanitizePlayerName(name: String?): String {
        if (name.isNullOrBlank()) return "Unknown"
        return name.replace("`", "")
            .replace("@", "")
            .replace("\n", "")
            .replace("\r", "")
            .trim()
            .take(32)
            .ifEmpty { "Unknown" }
    }

    private fun getRiskSeverity(score: Int): String {
        return when {
            score >= 90 -> "CRITICAL"
            score >= 70 -> "HIGH"
            score >= 40 -> "MEDIUM"
            else -> "LOW"
        }
    }

    fun shutdown() {
        scheduler.shutdown()
        var attempts = 0
        while (!alertQueue.isEmpty() && attempts++ < 10) {
            flushQueue()
        }
        alertQueue.clear()
        queuedCount.set(0)
    }
}
