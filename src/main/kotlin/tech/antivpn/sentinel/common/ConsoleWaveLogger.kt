package tech.antivpn.sentinel.common

import tech.antivpn.sentinel.common.model.SentinelVerdict
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * High-throughput console wave aggregator and spam suppressor.
 * Swallows 100% of individual per-IP block/flag/disconnect log lines and consolidates
 * threat telemetry into a structured 5-second wave summary. Supports live console log toggling.
 */
class ConsoleWaveLogger(
    private val infoLogger: (String) -> Unit,
    private val warnLogger: (String) -> Unit,
    @Volatile var consoleLogsEnabled: Boolean = true
) {
    private val scheduler: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "Sentinel-Console-Wave-Logger").apply { isDaemon = true }
    }

    // Recently blocked IPs and usernames so ConsoleSpamFilter can swallow native server disconnect/login logs
    private val recentlyBlockedIps = ConcurrentHashMap<String, Long>()
    private val recentlyBlockedPlayers = ConcurrentHashMap<String, Long>()
    private val swallowedServerLogCount = AtomicInteger(0)

    @Volatile
    private var lastWaveActivityMs = 0L

    // 5-second window counters (guarded by @Synchronized on this)
    private var windowTotal = 0
    private var windowEnforceBlocks = 0
    private var windowBlacklistBlocks = 0
    private var windowGraduated = 0
    private var windowAudit = 0
    private var windowErrors = 0
    private var riskScoreSum = 0L
    private var riskScoredCount = 0
    private var peakRiskScore = 0

    private val uniqueIps = LinkedHashSet<String>()
    private var uniqueIpOverflow = 0
    private val threatBreakdown = LinkedHashMap<String, Int>()
    private val providerBreakdown = LinkedHashMap<String, Int>()
    private val countryBreakdown = LinkedHashMap<String, Int>()

    // Multi-window cumulative raid tracking
    private var raidTotal = 0
    private var raidBlockedTotal = 0
    private var raidStartTimeMs = 0L
    private var lastInterceptTimeMs = 0L
    private val raidUniqueIps = LinkedHashSet<String>()

    companion object {
        private const val MAX_WINDOW_UNIQUE_IPS = 10_000
        private const val MAX_RAID_UNIQUE_IPS = 25_000
        private const val MAX_RECENT_BLOCKED_TRACKING = 10_000
        private const val RECENT_BLOCK_TTL_MS = 30_000L
        private const val ACTIVE_WAVE_HOLD_MS = 10_000L

        /**
         * Strips Minecraft legacy color codes (&x, §x) and ANSI escape sequences (\u001B[...m)
         * without regex allocations for high-speed log filtering.
         */
        @JvmStatic
        fun stripFormatting(input: String): String {
            if (!input.contains('§') && !input.contains('&') && !input.contains('\u001B')) {
                return input
            }
            val sb = StringBuilder(input.length)
            var i = 0
            val len = input.length
            while (i < len) {
                val c = input[i]
                if ((c == '§' || c == '&') && i + 1 < len) {
                    i += 2
                    continue
                }
                if (c == '\u001B' && i + 1 < len && input[i + 1] == '[') {
                    i += 2
                    while (i < len && input[i] != 'm') {
                        i++
                    }
                    i++
                    continue
                }
                sb.append(c)
                i++
            }
            return sb.toString()
        }
    }

    init {
        scheduler.scheduleWithFixedDelay(::flushSummary, 5, 5, TimeUnit.SECONDS)
    }

    private fun trackBlockedTarget(playerName: String?, ip: String, now: Long) {
        val cleanIp = ip.trim().removeSurrounding("[", "]").substringBefore('%')
        if (cleanIp.isNotEmpty() && recentlyBlockedIps.size < MAX_RECENT_BLOCKED_TRACKING) {
            recentlyBlockedIps[cleanIp] = now
        }
        if (!playerName.isNullOrBlank() && recentlyBlockedPlayers.size < MAX_RECENT_BLOCKED_TRACKING) {
            recentlyBlockedPlayers[playerName.trim().lowercase(Locale.ROOT)] = now
        }
    }

    private fun recordCommonMetrics(ip: String, verdict: SentinelVerdict?, isBlocked: Boolean, now: Long) {
        if (raidStartTimeMs == 0L || (now - lastInterceptTimeMs > 15_000L && windowTotal == 0)) {
            raidStartTimeMs = now
            raidTotal = 0
            raidBlockedTotal = 0
            raidUniqueIps.clear()
        }
        lastInterceptTimeMs = now
        windowTotal++
        raidTotal++
        if (isBlocked) {
            raidBlockedTotal++
        }
        if (windowTotal >= 2 || raidTotal >= 3) {
            lastWaveActivityMs = now
        }

        val cleanIp = ip.trim().removeSurrounding("[", "]").substringBefore('%')
        if (cleanIp.isNotEmpty()) {
            if (uniqueIps.size < MAX_WINDOW_UNIQUE_IPS) {
                uniqueIps.add(cleanIp)
            } else if (!uniqueIps.contains(cleanIp)) {
                uniqueIpOverflow++
            }
            if (raidUniqueIps.size < MAX_RAID_UNIQUE_IPS) {
                raidUniqueIps.add(cleanIp)
            }
        }

        if (verdict != null) {
            val threat = verdict.threatType.ifBlank { "Unknown Threat" }
            threatBreakdown[threat] = (threatBreakdown[threat] ?: 0) + 1

            if (verdict.riskScore > 0) {
                riskScoreSum += verdict.riskScore
                riskScoredCount++
                if (verdict.riskScore > peakRiskScore) {
                    peakRiskScore = verdict.riskScore
                }
            }

            val providerLabel = formatProviderLabel(verdict)
            if (providerLabel != null && providerBreakdown.size < 256) {
                providerBreakdown[providerLabel] = (providerBreakdown[providerLabel] ?: 0) + 1
            }

            val country = verdict.country.trim().uppercase(Locale.ROOT)
            if (country.isNotEmpty() && country != "ZZ" && country != "UNKNOWN" && countryBreakdown.size < 256) {
                countryBreakdown[country] = (countryBreakdown[country] ?: 0) + 1
            }
        }
    }

    private fun formatProviderLabel(verdict: SentinelVerdict): String? {
        val provider = verdict.provider.trim()
        val hasValidProvider = provider.isNotEmpty() &&
            !provider.equals("Unknown Provider", ignoreCase = true) &&
            !provider.equals("Fail-Open Fallback", ignoreCase = true)
        if (verdict.asn <= 0L && !hasValidProvider) return null

        val shortProvider = if (hasValidProvider) {
            provider.split(Regex("\\s+")).take(2).joinToString(" ").take(20)
        } else {
            ""
        }
        return when {
            verdict.asn > 0L && shortProvider.isNotEmpty() -> "AS${verdict.asn} $shortProvider"
            verdict.asn > 0L -> "AS${verdict.asn}"
            else -> shortProvider
        }
    }

    @Synchronized
    fun logBlacklistBlock(playerName: String?, ip: String, now: Long = System.currentTimeMillis()) {
        trackBlockedTarget(playerName, ip, now)
        recordCommonMetrics(ip, null, isBlocked = true, now = now)
        windowBlacklistBlocks++
        threatBreakdown["Blacklist"] = (threatBreakdown["Blacklist"] ?: 0) + 1
        riskScoreSum += 100
        riskScoredCount++
        if (peakRiskScore < 100) peakRiskScore = 100
    }

    @Synchronized
    fun logEnforceBlock(playerName: String?, ip: String, verdict: SentinelVerdict, now: Long = System.currentTimeMillis()) {
        trackBlockedTarget(playerName, ip, now)
        recordCommonMetrics(ip, verdict, isBlocked = true, now = now)
        windowEnforceBlocks++
    }

    @Synchronized
    fun logGraduatedDefense(playerName: String?, ip: String, verdict: SentinelVerdict, now: Long = System.currentTimeMillis()) {
        recordCommonMetrics(ip, verdict, isBlocked = false, now = now)
        windowGraduated++
    }

    @Synchronized
    fun logAuditFlag(playerName: String?, ip: String, verdict: SentinelVerdict, now: Long = System.currentTimeMillis()) {
        recordCommonMetrics(ip, verdict, isBlocked = false, now = now)
        windowAudit++
    }

    @Synchronized
    fun logEvaluationError(playerName: String?, ip: String, reason: String, now: Long = System.currentTimeMillis()) {
        windowErrors++
        if (windowErrors >= 2) {
            lastWaveActivityMs = now
        }
    }

    fun recordSwallowedServerLog() {
        swallowedServerLogCount.incrementAndGet()
    }

    fun isWaveActive(now: Long = System.currentTimeMillis()): Boolean {
        return windowTotal >= 2 || (lastWaveActivityMs > 0L && now - lastWaveActivityMs <= ACTIVE_WAVE_HOLD_MS)
    }

    /**
     * Determines whether a native server/proxy console log message (from Paper, Spigot, Velocity, or BungeeCord)
     * is pre-login/disconnect IP spam that should be swallowed into the wave summary.
     */
    fun shouldSuppressServerLog(loggerName: String?, message: String?, now: Long = System.currentTimeMillis()): Boolean {
        if (message.isNullOrEmpty()) return false

        // Never suppress Sentinel's own wave summary, status, or startup banners
        if (message.contains("[Sentinel]") || message.contains("Sentinel Anti-VPN")) {
            return false
        }

        // 1. Direct match on raw cyan gradient kick header or blacklist kick reason
        if (message.contains("§x§2§2§d§3§e§e§lS", ignoreCase = true) ||
            message.contains("&x&2&2&d&3&e&e&lS", ignoreCase = true) ||
            message.contains("blacklisted from this server by Sentinel", ignoreCase = true)
        ) {
            recordSwallowedServerLog()
            return true
        }

        val plain = stripFormatting(message)

        // 2. Match stripped Sentinel Protection kick screen text
        if (plain.contains("Sentinel Protection", ignoreCase = true) ||
            plain.contains("blacklisted from this server by Sentinel", ignoreCase = true) ||
            plain.contains("VPN / Proxy traffic is restricted", ignoreCase = true)
        ) {
            recordSwallowedServerLog()
            return true
        }

        // 3. Check if this is a server login / pre-login / disconnect lifecycle message
        val isPreLoginChatter = plain.contains("InitialHandler") ||
            plain.contains("[initial connection]") ||
            plain.contains("UUID of player ") ||
            plain.contains("Disconnecting ")
        val isDisconnectChatter = plain.contains("lost connection:") ||
            plain.contains("has disconnected") ||
            plain.contains("has connected") ||
            plain.contains("GameProfile")

        if (!isPreLoginChatter && !isDisconnectChatter) {
            return false
        }

        // During an active attack wave, swallow all pre-login chatter and initial connection disconnects
        if (isWaveActive(now)) {
            if (isPreLoginChatter ||
                plain.contains("GameProfile") ||
                plain.contains("lost connection: Disconnected") ||
                plain.contains("lost connection: Timed out")
            ) {
                recordSwallowedServerLog()
                return true
            }
        }

        // Check if the connection log references a recently blocked IP or player
        for ((blockedIp, ts) in recentlyBlockedIps) {
            if (now - ts <= RECENT_BLOCK_TTL_MS && plain.contains(blockedIp)) {
                recordSwallowedServerLog()
                return true
            }
        }
        for ((blockedPlayer, ts) in recentlyBlockedPlayers) {
            if (now - ts <= RECENT_BLOCK_TTL_MS && blockedPlayer.length >= 3 && plain.contains(blockedPlayer, ignoreCase = true)) {
                recordSwallowedServerLog()
                return true
            }
        }

        return false
    }

    /**
     * Evaluates parameterized log templates (e.g. Log4j2 `{}` or JUL `{0}`) before full string formatting.
     */
    fun shouldSuppressServerLogTemplate(
        loggerName: String?,
        format: String?,
        params: Array<out Any?>?,
        now: Long = System.currentTimeMillis()
    ): Boolean {
        if (format.isNullOrEmpty()) return false
        if (params.isNullOrEmpty()) {
            return shouldSuppressServerLog(loggerName, format, now)
        }
        if (shouldSuppressServerLog(loggerName, format, now)) {
            return true
        }
        val mightBeConnectionLog = format.contains("Disconnecting") ||
            format.contains("lost connection") ||
            format.contains("disconnected") ||
            format.contains("connected") ||
            format.contains("InitialHandler") ||
            format.contains("UUID of player") ||
            format.contains("{}") ||
            format.contains("{0}")
        if (!mightBeConnectionLog) return false

        val combined = buildString(format.length + params.size * 32) {
            append(format)
            for (p in params) {
                if (p != null) {
                    append(' ').append(p.toString())
                }
            }
        }
        return shouldSuppressServerLog(loggerName, combined, now)
    }

    private fun evictExpiredBlockedTargets(now: Long) {
        if (recentlyBlockedIps.isNotEmpty()) {
            recentlyBlockedIps.entries.removeIf { now - it.value > RECENT_BLOCK_TTL_MS }
        }
        if (recentlyBlockedPlayers.isNotEmpty()) {
            recentlyBlockedPlayers.entries.removeIf { now - it.value > RECENT_BLOCK_TTL_MS }
        }
    }

    @Synchronized
    fun flushSummary() {
        flushSummaryAt(System.currentTimeMillis())
    }

    @Synchronized
    fun flushSummaryAt(now: Long) {
        evictExpiredBlockedTargets(now)
        val extraSwallowed = swallowedServerLogCount.getAndSet(0)

        if (windowTotal <= 0 && windowErrors <= 0) {
            // If a multi-connection threat wave was active and has now subsided, emit a completion notice
            if (raidTotal >= 5 && lastInterceptTimeMs > 0L && now - lastInterceptTimeMs >= 4500L) {
                val finalRaidTotal = raidTotal
                val finalRaidBlocked = raidBlockedTotal
                val finalRaidUnique = raidUniqueIps.size.coerceAtLeast(1)
                val durationSec = ((lastInterceptTimeMs - raidStartTimeMs) / 1000L).coerceAtLeast(5L)

                raidTotal = 0
                raidBlockedTotal = 0
                raidStartTimeMs = 0L
                lastInterceptTimeMs = 0L
                raidUniqueIps.clear()

                if (consoleLogsEnabled) {
                    infoLogger(
                        "[Sentinel] Threat Wave Subsided: $finalRaidTotal total connections intercepted ($finalRaidBlocked blocked, $finalRaidUnique unique IPs) over ${durationSec}s."
                    )
                }
            }
            return
        }

        val total = windowTotal
        val enforceBlocks = windowEnforceBlocks
        val blacklistBlocks = windowBlacklistBlocks
        val blocked = enforceBlocks + blacklistBlocks
        val graduated = windowGraduated
        val audit = windowAudit
        val errors = windowErrors
        val uniqueIpCount = (uniqueIps.size + uniqueIpOverflow).coerceAtLeast(if (total > 0) 1 else 0)
        val avgRisk = if (riskScoredCount > 0) (riskScoreSum / riskScoredCount).toInt() else 0
        val peakRisk = peakRiskScore
        val hasRiskStats = riskScoredCount > 0
        val currentRaidTotal = raidTotal
        val elapsedRaidSec = if (raidStartTimeMs > 0L) ((now - raidStartTimeMs) / 1000L).coerceAtLeast(5L) else 5L
        val totalSwallowedLogs = total + extraSwallowed + errors

        val actionParts = mutableListOf<String>()
        if (blocked > 0) actionParts.add("$blocked blocked")
        if (graduated > 0) actionParts.add("$graduated graduated defense")
        if (audit > 0) actionParts.add("$audit audited")
        if (errors > 0) actionParts.add("$errors eval errors")

        val topThreats = threatBreakdown.entries
            .sortedByDescending { it.value }
            .take(4)
            .joinToString(", ") { "${it.key}: ${it.value}" }

        val topProviders = providerBreakdown.entries
            .sortedByDescending { it.value }
            .take(3)
            .joinToString(", ") { "${it.key}: ${it.value}" }

        val topCountries = countryBreakdown.entries
            .sortedByDescending { it.value }
            .take(4)
            .joinToString(", ") { "${it.key}: ${it.value}" }

        // Reset 5-second window state
        windowTotal = 0
        windowEnforceBlocks = 0
        windowBlacklistBlocks = 0
        windowGraduated = 0
        windowAudit = 0
        windowErrors = 0
        riskScoreSum = 0L
        riskScoredCount = 0
        peakRiskScore = 0
        uniqueIps.clear()
        uniqueIpOverflow = 0
        threatBreakdown.clear()
        providerBreakdown.clear()
        countryBreakdown.clear()

        if (!consoleLogsEnabled) {
            return
        }

        val ratePerSec = String.format(Locale.US, "%.1f", total / 5.0)
        val summary = buildString {
            append("[Sentinel] Threat Wave Summary (5s): ")
            append("$total connections intercepted (${actionParts.joinToString(", ")})")
            append(" | Rate: ${ratePerSec}/s | Unique IPs: $uniqueIpCount")
            if (hasRiskStats) {
                append(" | Risk: avg $avgRisk/100 (peak $peakRisk)")
            }
            if (topThreats.isNotEmpty()) {
                append(" | Threats: $topThreats")
            }
            if (topProviders.isNotEmpty()) {
                append(" | Providers: $topProviders")
            }
            if (topCountries.isNotEmpty()) {
                append(" | Origins: $topCountries")
            }
            if (currentRaidTotal > total || total >= 5) {
                append(" | Raid Total: $currentRaidTotal (${elapsedRaidSec}s)")
            }
            append(" | Swallowed: $totalSwallowedLogs logs")
        }

        if (blocked > 0 || graduated > 0 || errors > 0) {
            warnLogger(summary)
        } else {
            infoLogger(summary)
        }
    }

    fun shutdown() {
        scheduler.shutdown()
        flushSummary()
    }
}
