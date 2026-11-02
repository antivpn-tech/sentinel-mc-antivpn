package tech.antivpn.sentinel.common

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import tech.antivpn.sentinel.common.model.SentinelVerdict
import java.net.InetAddress
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * High-performance, non-blocking asynchronous HTTP client for the Sentinel Edge API.
 * Supports single-IP checks, automatic join-wave micro-batching (/v1/batch), and in-flight coalescing.
 */
class SentinelClient(
    private val config: SentinelConfig,
    private val infoLogger: (String) -> Unit = {},
    private val errorLogger: (String) -> Unit = {}
) {
    private val requestTimeoutMs: Long = config.timeoutMs.toLong().coerceIn(500L, 30_000L)

    private val httpClient: HttpClient = HttpClient.newBuilder()
        .version(HttpClient.Version.HTTP_2)
        .connectTimeout(Duration.ofMillis(requestTimeoutMs))
        .build()

    private val cache = ConcurrentHashMap<String, CacheEntry>()
    private val inFlight = ConcurrentHashMap<String, CompletableFuture<SentinelVerdict>>()
    private val activeRequests = AtomicInteger(0)
    private val waveQueue = ConcurrentLinkedQueue<PendingCheck>()
    private val waveQueueSize = AtomicInteger(0)
    private val waveScheduled = AtomicBoolean(false)
    private val batchScheduler: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { runnable ->
        Thread(runnable, "Sentinel-JoinWave-Batcher").apply { isDaemon = true }
    }
    private var hasWarnedUnconfiguredKey = false

    init {
        batchScheduler.scheduleWithFixedDelay(::evictExpiredCache, 5, 5, TimeUnit.MINUTES)
    }

    private data class PendingCheck(
        val ip: String,
        val future: CompletableFuture<SentinelVerdict>
    )

    private data class CacheEntry(
        val verdict: SentinelVerdict,
        val expiresAt: Long
    ) {
        val isValid: Boolean
            get() = System.currentTimeMillis() < expiresAt
    }

    @Volatile
    private var backoffUntil: Long = 0
    @Volatile
    private var lastTransientErrorLogMs: Long = 0

    private fun logTransientError(message: String) {
        if (!config.consoleLogs) return
        val now = System.currentTimeMillis()
        if (now - lastTransientErrorLogMs >= 10_000L) {
            lastTransientErrorLogMs = now
            errorLogger(message)
        }
    }

    companion object {
        private const val MAX_BATCH_SIZE = 20
        private const val JOIN_WAVE_WINDOW_MS = 15L
        private const val MAX_CACHE_ENTRIES = 50_000
    }

    /**
     * Evaluates an IP address asynchronously.
     * Guaranteed fail-open: On timeout or network failure, returns an ALLOW verdict.
     * Automatically coalesces duplicate in-flight checks and batches concurrent join waves via /v1/batch.
     */
    private fun cleanIp(raw: String): String {
        val stripped = raw.trim().removeSurrounding("[", "]").substringBefore('%').trim()
        if (stripped.startsWith("::ffff:", ignoreCase = true)) {
            val v4Candidate = stripped.substring(7)
            if (!v4Candidate.contains(':') && v4Candidate.contains('.')) {
                return v4Candidate
            }
        }
        return stripped
    }

    fun evaluate(ip: String?): CompletableFuture<SentinelVerdict> {
        if (ip.isNullOrBlank() || isLocalAddress(ip)) {
            return CompletableFuture.completedFuture(SentinelVerdict.fallbackAllow(if (ip.isNullOrBlank()) "unknown" else cleanIp(ip)))
        }

        val normalizedIp = cleanIp(ip)

        // Guard unconfigured / placeholder license keys
        if (isKeyUnconfigured()) {
            warnUnconfiguredKeyOnce()
            return CompletableFuture.completedFuture(SentinelVerdict.fallbackAllow(normalizedIp))
        }

        // 1. Check in-memory cache (checks direct IP and IPv6 /64 prefix to prevent rotation attacks)
        val subnetKey = getSubnetKey(normalizedIp)
        val cached = cache[normalizedIp] ?: cache[subnetKey]
        if (cached != null && cached.isValid) {
            val verdict = if (cached.verdict.ip == normalizedIp) cached.verdict else cached.verdict.copy(ip = normalizedIp)
            return CompletableFuture.completedFuture(verdict)
        }

        // Check if currently under HTTP 429 rate limit backoff
        val now = System.currentTimeMillis()
        if (now < backoffUntil) {
            return CompletableFuture.completedFuture(SentinelVerdict.fallbackAllow(normalizedIp))
        }

        // 2. Coalesce identical concurrent in-flight requests (same IP or /64 IPv6 subnet)
        val existingInFlight = inFlight[subnetKey]
        if (existingInFlight != null) {
            return existingInFlight.handle { v, ex ->
                if (ex != null || v == null) SentinelVerdict.fallbackAllow(normalizedIp)
                else if (v.ip == normalizedIp) v else v.copy(ip = normalizedIp)
            }
        }

        val resultFuture = CompletableFuture<SentinelVerdict>()
        val previous = inFlight.putIfAbsent(subnetKey, resultFuture)
        if (previous != null) {
            return previous.handle { v, ex ->
                if (ex != null || v == null) SentinelVerdict.fallbackAllow(normalizedIp)
                else if (v.ip == normalizedIp) v else v.copy(ip = normalizedIp)
            }
        }
        resultFuture.orTimeout(requestTimeoutMs + 800L, TimeUnit.MILLISECONDS)
        resultFuture.whenComplete { _, _ ->
            inFlight.remove(subnetKey, resultFuture)
        }
        val safeView = resultFuture.handle { v, ex ->
            if (ex != null || v == null) SentinelVerdict.fallbackAllow(normalizedIp)
            else if (v.ip == normalizedIp) v else v.copy(ip = normalizedIp)
        }

        // 3. If another edge check is already in-flight or queued, coalesce into a micro-batch wave (/v1/batch)
        if (activeRequests.get() > 0 || waveQueueSize.get() > 0) {
            enqueueWaveCheck(normalizedIp, resultFuture)
            return safeView
        }

        // 4. First check in an idle window fires immediately (zero artificial latency)
        activeRequests.incrementAndGet()
        sendSingleCheck(normalizedIp).whenComplete { verdict, ex ->
            activeRequests.decrementAndGet()
            if (ex != null) {
                resultFuture.complete(SentinelVerdict.fallbackAllow(normalizedIp))
            } else {
                resultFuture.complete(verdict ?: SentinelVerdict.fallbackAllow(normalizedIp))
            }
        }
        return safeView
    }

    private fun enqueueWaveCheck(ip: String, future: CompletableFuture<SentinelVerdict>) {
        val currentSize: Int
        synchronized(this) {
            waveQueue.add(PendingCheck(ip, future))
            currentSize = waveQueueSize.incrementAndGet()
        }
        if (currentSize >= MAX_BATCH_SIZE) {
            flushWaveQueue()
            return
        }
        scheduleWaveFlush()
    }

    private fun scheduleWaveFlush() {
        if (waveScheduled.compareAndSet(false, true)) {
            try {
                batchScheduler.schedule({
                    waveScheduled.set(false)
                    flushWaveQueue()
                }, JOIN_WAVE_WINDOW_MS, TimeUnit.MILLISECONDS)
            } catch (_: Exception) {
                waveScheduled.set(false)
                flushWaveQueue()
            }
        }
    }

    private fun flushWaveQueue() {
        while (true) {
            val batch = mutableListOf<PendingCheck>()
            synchronized(this) {
                while (batch.size < MAX_BATCH_SIZE) {
                    val next = waveQueue.poll() ?: break
                    waveQueueSize.updateAndGet { if (it > 0) it - 1 else 0 }
                    batch.add(next)
                }
                if (waveQueue.isEmpty()) {
                    waveQueueSize.set(0)
                }
            }
            if (batch.isEmpty()) return

            if (batch.size == 1) {
                val single = batch[0]
                activeRequests.incrementAndGet()
                sendSingleCheck(single.ip).whenComplete { verdict, ex ->
                    activeRequests.decrementAndGet()
                    single.future.complete(if (ex == null && verdict != null) verdict else SentinelVerdict.fallbackAllow(single.ip))
                }
            } else {
                val ips = batch.map { it.ip }
                activeRequests.incrementAndGet()
                sendBatchChunk(ips).whenComplete { verdictMap, ex ->
                    activeRequests.decrementAndGet()
                    for (item in batch) {
                        val verdict = if (ex == null && verdictMap != null) {
                            verdictMap[item.ip] ?: SentinelVerdict.fallbackAllow(item.ip)
                        } else {
                            SentinelVerdict.fallbackAllow(item.ip)
                        }
                        item.future.complete(verdict)
                    }
                }
            }

        }
    }

    /**
     * Evaluates a batch of IP addresses concurrently using POST /v1/batch.
     * Automatically serves cached/local IPs from memory and chunks uncached IPs into groups of 20.
     * Guaranteed fail-open on timeout or network failure.
     */
    fun evaluateBatch(ips: List<String>): CompletableFuture<Map<String, SentinelVerdict>> {
        if (ips.isEmpty()) {
            return CompletableFuture.completedFuture(emptyMap())
        }

        val results = ConcurrentHashMap<String, SentinelVerdict>()
        val uncached = LinkedHashSet<String>()
        val now = System.currentTimeMillis()
        val keyUnconfigured = isKeyUnconfigured()
        if (keyUnconfigured) {
            warnUnconfiguredKeyOnce()
        }

        for (rawIp in ips) {
            val trimmed = cleanIp(rawIp)
            if (trimmed.isEmpty()) continue

            if (isLocalAddress(trimmed) || keyUnconfigured || now < backoffUntil) {
                results[trimmed] = SentinelVerdict.fallbackAllow(trimmed)
                continue
            }

            val subnetKey = getSubnetKey(trimmed)
            val cached = cache[trimmed] ?: cache[subnetKey]
            if (cached != null && cached.isValid) {
                results[trimmed] = if (cached.verdict.ip == trimmed) cached.verdict else cached.verdict.copy(ip = trimmed)
            } else {
                uncached.add(trimmed)
            }
        }

        if (uncached.isEmpty()) {
            return CompletableFuture.completedFuture(results)
        }

        val chunks = uncached.chunked(MAX_BATCH_SIZE)
        val chunkFutures = chunks.map { chunk ->
            sendBatchChunk(chunk).thenAccept { chunkMap ->
                results.putAll(chunkMap)
            }
        }

        return CompletableFuture.allOf(*chunkFutures.toTypedArray())
            .thenApply {
                for (rawIp in ips) {
                    val trimmed = cleanIp(rawIp)
                    if (trimmed.isNotEmpty()) {
                        val v = results[trimmed] ?: SentinelVerdict.fallbackAllow(trimmed)
                        results[trimmed] = v
                        val rawTrimmed = rawIp.trim()
                        if (rawTrimmed.isNotEmpty() && rawTrimmed != trimmed) {
                            results.putIfAbsent(rawTrimmed, v)
                        }
                    }
                }
                results.toMap()
            }
            .exceptionally {
                for (rawIp in ips) {
                    val trimmed = cleanIp(rawIp)
                    if (trimmed.isNotEmpty()) {
                        val v = results[trimmed] ?: SentinelVerdict.fallbackAllow(trimmed)
                        results[trimmed] = v
                        val rawTrimmed = rawIp.trim()
                        if (rawTrimmed.isNotEmpty() && rawTrimmed != trimmed) {
                            results.putIfAbsent(rawTrimmed, v)
                        }
                    }
                }
                results.toMap()
            }
    }

    private fun sendSingleCheck(normalizedIp: String): CompletableFuture<SentinelVerdict> {
        return try {
            val encodedIp = URLEncoder.encode(normalizedIp, StandardCharsets.UTF_8)
            val baseEndpoint = config.endpoint.trim()
            val separator = if (baseEndpoint.contains('?')) "&" else "?"
            val url = "${baseEndpoint}${separator}ip=$encodedIp"
            val cleanKey = config.licenseKey.trim()

            val request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofMillis(requestTimeoutMs))
                .header("User-Agent", "Sentinel-Minecraft/2.0.3")
                .header("Accept", "application/json")
                .header("Authorization", "Bearer $cleanKey")
                .header("X-Sentinel-Key", cleanKey)
                .GET()
                .build()

            httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenApply { response ->
                    val status = response.statusCode()
                    monitorQuotaHeader(response)

                    if (status == 200) {
                        val verdict = parseVerdict(normalizedIp, response.body())
                        cacheVerdict(normalizedIp, verdict)
                        verdict
                    } else if (status == 429) {
                        val retryAfter = (response.headers().firstValue("Retry-After").orElse("5").toLongOrNull() ?: 5L).coerceIn(1L, 300L)
                        backoffUntil = System.currentTimeMillis() + (retryAfter * 1000)
                        logTransientError("[Sentinel] ⚠️ Rate limit exceeded (HTTP 429). Backing off edge queries for ${retryAfter}s.")
                        SentinelVerdict.fallbackAllow(normalizedIp)
                    } else if (status == 401 || status == 403) {
                        backoffUntil = System.currentTimeMillis() + 60_000L
                        logTransientError("[Sentinel] 🚨 Edge API returned HTTP $status (Quota Depleted or Invalid Key): ${response.body()}. Backing off for 60s and failing open.")
                        SentinelVerdict.fallbackAllow(normalizedIp)
                    } else {
                        logTransientError("[Sentinel] Edge API returned HTTP $status (failing open).")
                        SentinelVerdict.fallbackAllow(normalizedIp)
                    }
                }
                .orTimeout(requestTimeoutMs + 500L, TimeUnit.MILLISECONDS)
                .exceptionally { ex ->
                    logTransientError("[Sentinel] Connection failure communicating with Sentinel Edge API: ${ex.message} (failing open)")
                    SentinelVerdict.fallbackAllow(normalizedIp)
                }
        } catch (e: Exception) {
            logTransientError("[Sentinel] Failed to construct evaluation request: ${e.message}")
            CompletableFuture.completedFuture(SentinelVerdict.fallbackAllow(normalizedIp))
        }
    }

    private fun sendBatchChunk(chunk: List<String>): CompletableFuture<Map<String, SentinelVerdict>> {
        if (chunk.isEmpty()) {
            return CompletableFuture.completedFuture(emptyMap())
        }
        return try {
            val batchUrl = resolveBatchEndpoint(config.endpoint)
            val payload = JsonObject().apply {
                val arr = JsonArray()
                chunk.forEach { arr.add(it) }
                add("ips", arr)
            }.toString()

            val cleanKey = config.licenseKey.trim()
            val request = HttpRequest.newBuilder()
                .uri(URI.create(batchUrl))
                .timeout(Duration.ofMillis(requestTimeoutMs))
                .header("User-Agent", "Sentinel-Minecraft/2.0.3")
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .header("Authorization", "Bearer $cleanKey")
                .header("X-Sentinel-Key", cleanKey)
                .POST(HttpRequest.BodyPublishers.ofString(payload, StandardCharsets.UTF_8))
                .build()

            httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenApply { response ->
                    val status = response.statusCode()
                    monitorQuotaHeader(response)

                    if (status == 200) {
                        val verdicts = parseBatchVerdicts(chunk, response.body())
                        verdicts.forEach { (ip, verdict) -> cacheVerdict(ip, verdict) }
                        verdicts
                    } else if (status == 429) {
                        val retryAfter = (response.headers().firstValue("Retry-After").orElse("5").toLongOrNull() ?: 5L).coerceIn(1L, 300L)
                        backoffUntil = System.currentTimeMillis() + (retryAfter * 1000)
                        logTransientError("[Sentinel] ⚠️ Batch rate limit exceeded (HTTP 429). Backing off edge queries for ${retryAfter}s.")
                        chunk.associateWith { SentinelVerdict.fallbackAllow(it) }
                    } else if (status == 401 || status == 403) {
                        backoffUntil = System.currentTimeMillis() + 60_000L
                        logTransientError("[Sentinel] 🚨 Edge API returned HTTP $status on batch check: ${response.body()}. Backing off for 60s and failing open.")
                        chunk.associateWith { SentinelVerdict.fallbackAllow(it) }
                    } else {
                        logTransientError("[Sentinel] Edge API returned HTTP $status for batch check (${chunk.size} IPs).")
                        chunk.associateWith { SentinelVerdict.fallbackAllow(it) }
                    }
                }
                .orTimeout(requestTimeoutMs + 500L, TimeUnit.MILLISECONDS)
                .exceptionally { ex ->
                    logTransientError("[Sentinel] Batch connection failure communicating with Sentinel Edge API: ${ex.message} (failing open)")
                    chunk.associateWith { SentinelVerdict.fallbackAllow(it) }
                }
        } catch (e: Exception) {
            logTransientError("[Sentinel] Failed to construct batch evaluation request: ${e.message}")
            CompletableFuture.completedFuture(chunk.associateWith { SentinelVerdict.fallbackAllow(it) })
        }
    }

    private fun monitorQuotaHeader(response: HttpResponse<*>) {
        val quotaRemainingOpt = response.headers().firstValue("X-Sentinel-Quota-Remaining")
        if (quotaRemainingOpt.isPresent) {
            val remaining = quotaRemainingOpt.get().toLongOrNull()
            if (remaining != null && remaining in 1..499) {
                errorLogger("[Sentinel] ⚠️ Monthly license quota running low: Only $remaining checks remaining in active billing cycle!")
            }
        }
    }

    private fun cacheVerdict(ip: String, verdict: SentinelVerdict) {
        if (verdict.reasonCodes.contains("EDGE_API_TIMEOUT_FAIL_OPEN")) {
            return
        }
        val ttlMs = config.cacheDurationMinutes.toLong() * 60 * 1000
        if (ttlMs <= 0) return
        if (cache.size >= MAX_CACHE_ENTRIES) {
            evictExpiredCache()
            if (cache.size >= MAX_CACHE_ENTRIES) {
                // Evict ~10% of entries instead of wiping the entire cache during a flood
                val toRemove = MAX_CACHE_ENTRIES / 10
                val iterator = cache.keys.iterator()
                var removed = 0
                while (iterator.hasNext() && removed < toRemove) {
                    iterator.next()
                    iterator.remove()
                    removed++
                }
            }
        }
        val expiry = System.currentTimeMillis() + ttlMs
        if (ip.contains(":")) {
            cache[getSubnetKey(ip)] = CacheEntry(verdict, expiry)
        } else {
            cache[ip] = CacheEntry(verdict, expiry)
        }
    }

    private fun evictExpiredCache() {
        val now = System.currentTimeMillis()
        cache.entries.removeIf { now >= it.value.expiresAt }
    }

    private fun isKeyUnconfigured(): Boolean {
        val clean = config.licenseKey.trim()
        return clean.isBlank() || clean == "stl_live_your_api_key_here"
    }

    private fun warnUnconfiguredKeyOnce() {
        if (!hasWarnedUnconfiguredKey) {
            hasWarnedUnconfiguredKey = true
            errorLogger("[Sentinel] ⚠️ Protection paused (failing open): No active license key configured in config.yml. Claim your key at https://antivpn.tech")
        }
    }

    internal fun resolveBatchEndpoint(endpoint: String): String {
        val withoutQuery = endpoint.trim().substringBefore('?').trimEnd('/')
        return when {
            withoutQuery.endsWith("/v1/check") -> withoutQuery.removeSuffix("/v1/check") + "/v1/batch"
            withoutQuery.endsWith("/api/check") -> withoutQuery.removeSuffix("/api/check") + "/api/batch"
            withoutQuery.endsWith("/check") -> withoutQuery.removeSuffix("/check") + "/batch"
            withoutQuery.endsWith("/v1/batch") || withoutQuery.endsWith("/api/batch") -> withoutQuery
            else -> "$withoutQuery/v1/batch"
        }
    }

    internal fun parseBatchVerdicts(requestedIps: List<String>, jsonBody: String): Map<String, SentinelVerdict> {
        val out = LinkedHashMap<String, SentinelVerdict>()
        val byNormalizedIp = HashMap<String, SentinelVerdict>()
        val requestedSet = requestedIps.toSet()
        try {
            val root = JsonParser.parseString(jsonBody).asJsonObject
            if (root.has("results") && root.get("results").isJsonArray) {
                val resultsArray = root.getAsJsonArray("results")
                for (i in 0 until resultsArray.size()) {
                    val elem = resultsArray.get(i)
                    if (elem != null && elem.isJsonObject) {
                        val obj = elem.asJsonObject
                        val hasExplicitIp = obj.has("ip") && !obj.get("ip").isJsonNull && obj.get("ip").asString.isNotBlank()
                        val itemIp = if (hasExplicitIp) {
                            obj.get("ip").asString.trim().substringBefore('%')
                        } else {
                            requestedIps.getOrNull(i) ?: "unknown"
                        }
                        val verdict = parseVerdict(itemIp, obj.toString())
                        byNormalizedIp[SentinelListManager.normalizeIp(itemIp)] = verdict
                        if (requestedSet.isEmpty() || requestedSet.contains(itemIp)) {
                            out[itemIp] = verdict
                        }
                        if (i < requestedIps.size) {
                            val reqIp = requestedIps[i]
                            if (!hasExplicitIp || SentinelListManager.normalizeIp(reqIp) == SentinelListManager.normalizeIp(itemIp)) {
                                out[reqIp] = if (verdict.ip == reqIp) verdict else verdict.copy(ip = reqIp)
                            }
                        }
                    }
                }
            }
        } catch (e: Exception) {
            errorLogger("[Sentinel] Error parsing batch verdict payload: ${e.message} | Raw: $jsonBody")
        }

        for (ip in requestedIps) {
            if (!out.containsKey(ip)) {
                val byNorm = byNormalizedIp[SentinelListManager.normalizeIp(ip)]
                out[ip] = if (byNorm != null) {
                    if (byNorm.ip == ip) byNorm else byNorm.copy(ip = ip)
                } else {
                    SentinelVerdict.fallbackAllow(ip)
                }
            }
        }
        return out
    }

    /**
     * Canonicalizes IPv6 addresses to their /64 subnet prefix (handling :: zero compression)
     * to prevent rotating IPv6 bot swarm attacks from depleting license quota.
     */
    fun getSubnetKey(ip: String): String {
        if (!ip.contains(":")) return ip
        return try {
            val cleanIp = ip.trim().substringBefore('%')
            val literal = if (cleanIp.startsWith("[")) cleanIp else "[$cleanIp]"
            val bytes = InetAddress.getByName(literal).address
            if (bytes.size == 16) {
                val h0 = ((bytes[0].toInt() and 0xFF) shl 8) or (bytes[1].toInt() and 0xFF)
                val h1 = ((bytes[2].toInt() and 0xFF) shl 8) or (bytes[3].toInt() and 0xFF)
                val h2 = ((bytes[4].toInt() and 0xFF) shl 8) or (bytes[5].toInt() and 0xFF)
                val h3 = ((bytes[6].toInt() and 0xFF) shl 8) or (bytes[7].toInt() and 0xFF)
                "%x:%x:%x:%x::/64".format(h0, h1, h2, h3)
            } else {
                ip
            }
        } catch (_: Exception) {
            ip
        }
    }

    internal fun parseVerdict(ip: String, jsonBody: String): SentinelVerdict {
        return try {
            val root = JsonParser.parseString(jsonBody).asJsonObject

            val action = if (root.has("action") && !root.get("action").isJsonNull) root.get("action").asString else "ALLOW"
            val riskScore = if (root.has("risk_score") && !root.get("risk_score").isJsonNull) root.get("risk_score").asInt else 0
            val confidence = if (root.has("confidence") && !root.get("confidence").isJsonNull) root.get("confidence").asDouble else (if (action == "ALLOW") 0.99 else 0.90)
            val threatType = if (root.has("threat_type") && !root.get("threat_type").isJsonNull) root.get("threat_type").asString else "Clean Residential"
            val isVpn = root.has("is_vpn") && !root.get("is_vpn").isJsonNull && root.get("is_vpn").asBoolean
            val isGamingOptimizer = root.has("is_gaming_optimizer") && !root.get("is_gaming_optimizer").isJsonNull && root.get("is_gaming_optimizer").asBoolean
            val isPrivacyRelay = root.has("is_privacy_relay") && !root.get("is_privacy_relay").isJsonNull && root.get("is_privacy_relay").asBoolean
            val asn = if (root.has("asn") && !root.get("asn").isJsonNull) root.get("asn").asLong else 0L
            val provider = if (root.has("provider") && !root.get("provider").isJsonNull) root.get("provider").asString else "Unknown Provider"
            val hostname = if (root.has("hostname") && !root.get("hostname").isJsonNull) root.get("hostname").asString else null
            val country = if (root.has("country") && !root.get("country").isJsonNull) root.get("country").asString else "ZZ"
            val city = if (root.has("city") && !root.get("city").isJsonNull) root.get("city").asString else null
            val region = if (root.has("region") && !root.get("region").isJsonNull) root.get("region").asString else null
            val durationMs = when {
                root.has("execution_time_ms") && !root.get("execution_time_ms").isJsonNull -> root.get("execution_time_ms").asLong
                root.has("duration_ms") && !root.get("duration_ms").isJsonNull -> root.get("duration_ms").asLong
                else -> 0L
            }

            val reasonCodes = mutableListOf<String>()
            if (root.has("reason_codes") && root.get("reason_codes").isJsonArray) {
                val array = root.getAsJsonArray("reason_codes")
                for (elem in array) {
                    if (!elem.isJsonNull) {
                        reasonCodes.add(elem.asString)
                    }
                }
            }

            val reasons = mutableListOf<String>()
            if (root.has("reasons") && root.get("reasons").isJsonArray) {
                val array = root.getAsJsonArray("reasons")
                for (elem in array) {
                    if (!elem.isJsonNull) {
                        reasons.add(elem.asString)
                    }
                }
            }

            if (reasonCodes.isEmpty() && reasons.isNotEmpty()) {
                reasonCodes.addAll(reasons)
            } else if (reasons.isEmpty() && reasonCodes.isNotEmpty()) {
                reasons.addAll(reasonCodes)
            }

            SentinelVerdict(
                ip = ip,
                action = action,
                riskScore = riskScore,
                confidence = confidence,
                threatType = threatType,
                isVpn = isVpn,
                isGamingOptimizer = isGamingOptimizer,
                isPrivacyRelay = isPrivacyRelay,
                asn = asn,
                provider = provider,
                hostname = hostname,
                country = country,
                city = city,
                region = region,
                reasonCodes = reasonCodes,
                reasons = reasons,
                durationMs = durationMs
            )
        } catch (e: Exception) {
            errorLogger("[Sentinel] Error parsing verdict payload: ${e.message} | Raw: $jsonBody")
            SentinelVerdict.fallbackAllow(ip)
        }
    }

    fun isCached(ip: String?): Boolean {
        if (ip.isNullOrBlank()) return false
        val trimmed = cleanIp(ip)
        val entry = cache[trimmed] ?: cache[getSubnetKey(trimmed)]
        return entry != null && entry.isValid
    }

    /**
     * Returns the cached verdict for an IP without triggering any new evaluation or HTTP request.
     * Checks the direct IP key first, then the IPv4/IPv6 subnet aggregation key.
     */
    fun getCachedVerdict(ip: String?): SentinelVerdict? {
        if (ip.isNullOrBlank()) return null
        val trimmed = cleanIp(ip)
        val entry = cache[trimmed] ?: cache[getSubnetKey(trimmed)]
        if (entry != null && entry.isValid) {
            return if (entry.verdict.ip == trimmed) entry.verdict else entry.verdict.copy(ip = trimmed)
        }
        return null
    }

    fun clearCache() {
        cache.clear()
    }

    fun shutdown() {
        batchScheduler.shutdownNow()
        while (true) {
            val pending = waveQueue.poll() ?: break
            pending.future.complete(SentinelVerdict.fallbackAllow(pending.ip))
        }
        waveQueueSize.set(0)
        for ((key, future) in inFlight) {
            future.complete(SentinelVerdict.fallbackAllow(key))
        }
        inFlight.clear()
        cache.clear()
    }

    val cacheSize: Int
        get() {
            evictExpiredCache()
            return cache.size
        }

    private fun isLocalAddress(ip: String): Boolean {
        var clean = ip.trim().removeSurrounding("[", "]").lowercase().substringBefore('%')
        if (clean.startsWith("::ffff:")) {
            clean = clean.removePrefix("::ffff:")
        }
        if (clean == "127.0.0.1" || clean == "0.0.0.0" || clean == "localhost" ||
            clean == "0:0:0:0:0:0:0:1" || clean == "0:0:0:0:0:0:0:0" || clean == "::1" || clean == "::"
        ) {
            return true
        }
        if (clean.startsWith("10.") || clean.startsWith("192.168.") || clean.startsWith("127.") ||
            clean.startsWith("169.254.") || clean.startsWith("0.")
        ) {
            return true
        }
        if (clean.startsWith("172.")) {
            val secondOctet = clean.removePrefix("172.").substringBefore('.').toIntOrNull()
            if (secondOctet != null && secondOctet in 16..31) {
                return true
            }
        }
        if (clean.startsWith("100.")) {
            val secondOctet = clean.removePrefix("100.").substringBefore('.').toIntOrNull()
            if (secondOctet != null && secondOctet in 64..127) {
                return true
            }
        }
        if (clean.contains(':')) {
            val firstHextet = clean.substringBefore(':')
            if (firstHextet.length == 4 && (
                firstHextet.startsWith("fc") || firstHextet.startsWith("fd") ||
                firstHextet.startsWith("fe8") || firstHextet.startsWith("fe9") ||
                firstHextet.startsWith("fea") || firstHextet.startsWith("feb")
            )) {
                return true
            }
        }
        return false
    }
}
