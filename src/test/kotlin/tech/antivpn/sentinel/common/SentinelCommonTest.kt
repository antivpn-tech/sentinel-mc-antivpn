package tech.antivpn.sentinel.common

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import tech.antivpn.sentinel.common.model.SentinelVerdict
import java.nio.file.Path

class SentinelCommonTest {

    @Test
    fun testConfigDefaultsAreEnforce() {
        val config = SentinelConfig.createDefault()
        assertEquals("ENFORCE", config.mode)
        assertFalse(config.isAuditMode)
        assertEquals(80, config.riskThreshold)
        assertTrue(config.allowGamingOptimizers)
    }

    @Test
    fun testVerdictThreatEvaluation() {
        val vpnVerdict = SentinelVerdict(
            ip = "1.1.1.1",
            action = "BLOCK",
            riskScore = 95,
            confidence = 0.98,
            threatType = "Commercial VPN",
            reasonCodes = listOf("CARRIER_COMMERCIAL_VPN", "HOSTING_INFRASTRUCTURE_MATCH"),
            isVpn = true,
            isGamingOptimizer = false
        )
        assertTrue(vpnVerdict.isThreat(threshold = 80, allowGamingOptimizers = true))
        assertTrue(vpnVerdict.isHardThreat(threshold = 80, allowGamingOptimizers = true))
        assertFalse(vpnVerdict.isSuspectResidentialTunnel())

        val residentialVerdict = SentinelVerdict(
            ip = "185.1.2.3",
            action = "ALLOW",
            riskScore = 75,
            confidence = 0.82,
            threatType = "Residential Proxy",
            reasonCodes = listOf("RESIDENTIAL_TUNNEL_PROXY"),
            isVpn = false,
            isGamingOptimizer = false
        )
        assertTrue(residentialVerdict.isSuspectResidentialTunnel())
        assertTrue(residentialVerdict.isThreat(threshold = 80, allowGamingOptimizers = true))
        // In default enforce mode, suspect residential proxy is not a hard threat (graduated defense applies)
        assertFalse(residentialVerdict.isHardThreat(threshold = 80, allowGamingOptimizers = true))

        val highRiskResidentialVerdict = residentialVerdict.copy(action = "BLOCK", riskScore = 88)
        assertTrue(highRiskResidentialVerdict.isThreat(threshold = 80, allowGamingOptimizers = true))
        assertFalse(highRiskResidentialVerdict.isHardThreat(threshold = 80, allowGamingOptimizers = true))

        val gamingVerdict = SentinelVerdict(
            ip = "2.2.2.2",
            action = "BLOCK",
            riskScore = 90,
            confidence = 0.95,
            threatType = "Gaming Optimizer",
            reasonCodes = listOf("GAMING_OPTIMIZER_ROUTE"),
            isVpn = true,
            isGamingOptimizer = true
        )
        // Gaming optimizer should be allowed when allowGamingOptimizers is true
        assertFalse(gamingVerdict.isThreat(threshold = 80, allowGamingOptimizers = true))
        assertFalse(gamingVerdict.isHardThreat(threshold = 80, allowGamingOptimizers = true))
        // And blocked when allowGamingOptimizers is false
        assertTrue(gamingVerdict.isThreat(threshold = 80, allowGamingOptimizers = false))
        assertTrue(gamingVerdict.isHardThreat(threshold = 80, allowGamingOptimizers = false))

        val cleanVerdict = SentinelVerdict(
            ip = "3.3.3.3",
            action = "ALLOW",
            riskScore = 0,
            confidence = 0.99,
            threatType = "Clean Residential",
            reasonCodes = listOf("CARRIER_RESIDENTIAL_CLEAN"),
            isVpn = false,
            isGamingOptimizer = false
        )
        assertFalse(cleanVerdict.isThreat(threshold = 80, allowGamingOptimizers = true))
        assertFalse(cleanVerdict.isHardThreat(threshold = 80, allowGamingOptimizers = true))
        assertFalse(cleanVerdict.isSuspectResidentialTunnel())

        val privacyRelayVerdict = SentinelVerdict(
            ip = "104.28.1.1",
            action = "ALLOW",
            riskScore = 35,
            confidence = 0.95,
            threatType = "Privacy Relay",
            reasonCodes = listOf("PRIVACY_RELAY_VERIFIED"),
            isVpn = false,
            isPrivacyRelay = true
        )
        // Privacy relay (e.g. Cloudflare WARP) should not be flagged when allowGamingOptimizers is true
        assertFalse(privacyRelayVerdict.isThreat(threshold = 30, allowGamingOptimizers = true))
        assertFalse(privacyRelayVerdict.isHardThreat(threshold = 30, allowGamingOptimizers = true))

        // Privacy relay should be flagged when allowGamingOptimizers is false
        assertTrue(privacyRelayVerdict.isThreat(threshold = 30, allowGamingOptimizers = false))
        assertTrue(privacyRelayVerdict.isHardThreat(threshold = 30, allowGamingOptimizers = false))
    }

    @Test
    fun testPrivacyRelayParsing() {
        val client = SentinelClient(SentinelConfig.createDefault())
        val json = """
            {
                "ip": "104.28.1.1",
                "action": "ALLOW",
                "risk_score": 35,
                "threat_type": "Privacy Relay",
                "is_vpn": false,
                "is_privacy_relay": true,
                "asn": 13335,
                "provider": "Cloudflare WARP",
                "reason_codes": ["PRIVACY_RELAY_VERIFIED"]
            }
        """.trimIndent()

        val verdict = client.parseVerdict("104.28.1.1", json)
        assertTrue(verdict.isPrivacyRelay)
        assertFalse(verdict.isVpn)
        assertEquals(35, verdict.riskScore)
        assertEquals("Privacy Relay", verdict.threatType)
        assertEquals("Cloudflare WARP", verdict.provider)
        assertFalse(verdict.isThreat(threshold = 30, allowGamingOptimizers = true))
        assertTrue(verdict.isThreat(threshold = 30, allowGamingOptimizers = false))
    }

    @Test
    fun testListManagerPersistence(@TempDir tempDir: Path) {
        val manager = SentinelListManager(tempDir)

        assertTrue(manager.addWhitelist("notch"))
        assertTrue(manager.addWhitelist("1.2.3.4"))
        assertTrue(manager.isWhitelisted("notch", null))
        assertTrue(manager.isWhitelisted(null, "1.2.3.4"))
        assertFalse(manager.isWhitelisted("jeb", "5.6.7.8"))

        assertTrue(manager.addBlacklist("badplayer"))
        assertTrue(manager.addBlacklist("9.9.9.9"))
        assertTrue(manager.isBlacklisted("badplayer", null))
        assertTrue(manager.isBlacklisted(null, "9.9.9.9"))

        // CIDR subnet support
        assertTrue(manager.addWhitelist("198.51.100.0/24"))
        assertTrue(manager.isWhitelisted(null, "198.51.100.42"))
        assertFalse(manager.isWhitelisted(null, "198.51.101.42"))

        assertTrue(manager.addBlacklist("2001:db8:abcd::/48"))
        assertTrue(manager.isBlacklisted(null, "2001:db8:abcd:0001::1"))
        assertFalse(manager.isBlacklisted(null, "2001:db8:abce:0001::1"))

        // Reload from disk to verify JSON persistence
        val reloaded = SentinelListManager(tempDir)
        assertTrue(reloaded.isWhitelisted("notch", "1.2.3.4"))
        assertTrue(reloaded.isWhitelisted(null, "198.51.100.99"))
        assertTrue(reloaded.isBlacklisted("badplayer", "9.9.9.9"))
        assertTrue(reloaded.isBlacklisted(null, "2001:db8:abcd::5"))
    }

    @Test
    fun testBatchEndpointAndParsing() {
        val client = SentinelClient(SentinelConfig.createDefault())
        assertEquals(
            "https://api.antivpn.tech/v1/batch",
            client.resolveBatchEndpoint("https://api.antivpn.tech/v1/check")
        )
        assertEquals(
            "https://example.com/api/batch",
            client.resolveBatchEndpoint("https://example.com/api/check")
        )
        assertEquals(
            "https://api.antivpn.tech/v1/batch",
            client.resolveBatchEndpoint("https://api.antivpn.tech/v1/check/?timeout=1000")
        )
        assertTrue(SentinelListManager.isSingleIpAddress("1.2.3.4"))
        assertTrue(SentinelListManager.isSingleIpAddress("[2001:db8::1]"))
        assertFalse(SentinelListManager.isSingleIpAddress("1.2.3.0/24"))
        assertTrue(SentinelListManager.isIpAddress("1.2.3.0/24"))

        val batchJson = """
            {
                "count": 2,
                "results": [
                    {
                        "ip": "185.220.101.1",
                        "action": "BLOCK",
                        "risk_score": 99,
                        "confidence": 0.99,
                        "threat_type": "Tor Exit Node",
                        "is_vpn": true,
                        "reason_codes": ["TOR_EXIT_NODE"]
                    },
                    {
                        "ip": "8.8.8.8",
                        "action": "ALLOW",
                        "risk_score": 0,
                        "confidence": 0.99,
                        "threat_type": "Clean Residential",
                        "is_vpn": false,
                        "reason_codes": ["CARRIER_RESIDENTIAL_CLEAN"]
                    }
                ]
            }
        """.trimIndent()

        val ipv6BatchJson = """
            {
                "count": 1,
                "results": [
                    {
                        "ip": "2001:db8::1",
                        "action": "BLOCK",
                        "risk_score": 95,
                        "confidence": 0.99,
                        "threat_type": "Commercial VPN",
                        "is_vpn": true,
                        "reason_codes": ["CARRIER_COMMERCIAL_VPN"]
                    }
                ]
            }
        """.trimIndent()
        val parsedIpv6 = client.parseBatchVerdicts(listOf("2001:db8:0:0:0:0:0:1"), ipv6BatchJson)
        assertEquals("BLOCK", parsedIpv6["2001:db8:0:0:0:0:0:1"]?.action)
        assertEquals(95, parsedIpv6["2001:db8:0:0:0:0:0:1"]?.riskScore)

        val parsed = client.parseBatchVerdicts(listOf("185.220.101.1", "8.8.8.8", "9.9.9.9"), batchJson)
        assertEquals(3, parsed.size)
        assertEquals("BLOCK", parsed["185.220.101.1"]?.action)
        assertEquals(99, parsed["185.220.101.1"]?.riskScore)
        assertEquals("ALLOW", parsed["8.8.8.8"]?.action)
        // Missing IP in batch response fails open safely
        assertEquals("ALLOW", parsed["9.9.9.9"]?.action)

        // Unconfigured key fails open on evaluateBatch without throwing
        val fallbackBatch = client.evaluateBatch(listOf("1.1.1.1", "127.0.0.1")).join()
        assertEquals("ALLOW", fallbackBatch["1.1.1.1"]?.action)
        assertEquals("ALLOW", fallbackBatch["127.0.0.1"]?.action)
    }

    @Test
    fun testForcedCyanGradientKickHeader() {
        val config = SentinelConfig.createDefault()
        val message = config.buildEnforcementKickMessage(
            threat = "Commercial VPN",
            risk = 90,
            ip = "1.2.3.4",
            player = "TestPlayer"
        )

        // Line 1 must be strictly forced as the cyan gradient Sentinel Protection header
        val lines = message.split("\n")
        assertTrue(lines.isNotEmpty())
        assertEquals(SentinelConfig.FORCED_KICK_HEADER, lines[0])
        assertTrue(lines[1].contains("VPN / Proxy traffic is restricted on this server."))
        assertTrue(lines[2].contains("Commercial VPN"))
        assertTrue(lines[2].contains("90/100"))
    }

    @Test
    fun testKickMessageForcedEvenWhenConfigEmpty() {
        // Even if server owner blanks out kickMessage, line 1 cannot be removed
        val blankConfig = SentinelConfig(kickMessage = "   ")
        val message = blankConfig.buildEnforcementKickMessage("Tor Exit Node", 99, "5.6.7.8", "BadActor")
        assertEquals(SentinelConfig.FORCED_KICK_HEADER, message)
    }

    @Test
    fun testStripLegacySentinelProtectionHeader() {
        // Upgraded configs that still contain older red &c&l header must have it stripped to avoid duplicate lines
        val oldConfig = SentinelConfig(
            kickMessage = "&c&lSentinel Protection\n&7Custom server kick message\n&8Threat: %threat%"
        )
        val formatted = oldConfig.buildEnforcementKickMessage(threat = "Datacenter VPS", risk = 85, ip = "1.1.1.1", player = "Test")
        val lines = formatted.split("\n")
        assertEquals(SentinelConfig.FORCED_KICK_HEADER, lines[0])
        assertEquals("&7Custom server kick message", lines[1])
        assertEquals("&8Threat: Datacenter VPS", lines[2])
        // Must NOT contain old &c&l header
        assertFalse(formatted.contains("&c&lSentinel Protection"))
    }

    @Test
    fun testNewlineAndSlashNNormalization() {
        // Test literal \n and /n conversion
        val slashNConfig = SentinelConfig(
            kickMessage = "&7First Line/n&7Second Line\\n&8Threat: %threat%/n&7Join (&fhttps://discord.gg/nothing&7) to appeal."
        )
        val message = slashNConfig.buildEnforcementKickMessage("Commercial VPN", 92, "9.9.9.9", "Player")
        val lines = message.split("\n")

        assertEquals(SentinelConfig.FORCED_KICK_HEADER, lines[0])
        assertEquals("&7First Line", lines[1])
        assertEquals("&7Second Line", lines[2])
        assertEquals("&8Threat: Commercial VPN", lines[3])
        assertEquals("&7Join (&fhttps://discord.gg/nothing&7) to appeal.", lines[4])

        // Verify URL containing /nothing was preserved and NOT split
        assertTrue(lines[4].contains("https://discord.gg/nothing"))
        assertFalse(lines[4].contains("https://discord.gg\n"))
    }

    @Test
    fun testConsoleWaveLoggerAggregatesFloods() {
        val infoLogs = mutableListOf<String>()
        val warnLogs = mutableListOf<String>()
        val waveLogger = ConsoleWaveLogger(
            infoLogger = { infoLogs.add(it) },
            warnLogger = { warnLogs.add(it) }
        )
        try {
            val vpnVerdict = SentinelVerdict(
                ip = "198.51.100.1",
                action = "BLOCK",
                riskScore = 95,
                threatType = "Commercial VPN",
                isVpn = true,
                asn = 9009,
                provider = "M247 Europe SRL",
                country = "NL"
            )
            val gradVerdict = SentinelVerdict(
                ip = "203.0.113.5",
                action = "ALLOW",
                riskScore = 70,
                confidence = 0.75,
                threatType = "Residential Tunnel",
                country = "US"
            )

            val t0 = 1_000_000L
            // All individual per-IP events must be swallowed into the wave summary (zero individual IP lines)
            waveLogger.logEnforceBlock("Bot1", "198.51.100.1", vpnVerdict, t0)
            waveLogger.logEnforceBlock("Bot2", "198.51.100.2", vpnVerdict, t0 + 100L)
            waveLogger.logEnforceBlock("Bot3", "198.51.100.3", vpnVerdict, t0 + 200L)
            waveLogger.logEnforceBlock("Bot4", "198.51.100.4", vpnVerdict, t0 + 300L)
            waveLogger.logGraduatedDefense("Player5", "203.0.113.5", gradVerdict, t0 + 400L)
            waveLogger.logBlacklistBlock("BadActor6", "192.0.2.9", t0 + 500L)
            waveLogger.logEvaluationError("BotErr", "198.51.100.77", "Timeout", t0 + 600L)

            assertEquals(0, warnLogs.size, "Individual IP logs must be 100% swallowed until summary flush")
            assertEquals(0, infoLogs.size, "No individual info logs should be emitted during wave")

            waveLogger.flushSummaryAt(t0 + 5_000L)
            assertEquals(1, warnLogs.size, "Summary flush must emit exactly 1 aggregated warning line")
            val summary = warnLogs.last()
            assertTrue(summary.contains("Threat Wave Summary (5s): 6 connections intercepted (5 blocked, 1 graduated defense, 1 eval errors)"))
            assertTrue(summary.contains("Rate: 1.2/s | Unique IPs: 6"))
            assertTrue(summary.contains("Risk: avg 91/100 (peak 100)"))
            assertTrue(summary.contains("Threats: Commercial VPN: 4, Residential Tunnel: 1, Blacklist: 1"))
            assertTrue(summary.contains("Providers: AS9009 M247 Europe: 4"))
            assertTrue(summary.contains("Origins: NL: 4, US: 1"))
            assertTrue(summary.contains("Swallowed: 7 logs"))
        } finally {
            waveLogger.shutdown()
        }
    }

    @Test
    fun testConsoleLogsToggleAndSuppression(@TempDir tempDir: Path) {
        val infoLogs = mutableListOf<String>()
        val warnLogs = mutableListOf<String>()
        val waveLogger = ConsoleWaveLogger(
            infoLogger = { infoLogs.add(it) },
            warnLogger = { warnLogs.add(it) },
            consoleLogsEnabled = false
        )
        try {
            val vpnVerdict = SentinelVerdict(
                ip = "198.51.100.10",
                action = "BLOCK",
                riskScore = 95,
                threatType = "Commercial VPN",
                isVpn = true
            )
            waveLogger.logEnforceBlock("BotSilent", "198.51.100.10", vpnVerdict, 1_000_000L)
            waveLogger.flushSummaryAt(1_005_000L)
            assertEquals(0, warnLogs.size, "When consoleLogsEnabled is false, no summary logs should be emitted")

            // Native server disconnect log for the blocked IP must STILL be suppressed even when console logs are off
            assertTrue(
                waveLogger.shouldSuppressServerLog(
                    "com.velocitypowered.proxy.connection.MinecraftConnection",
                    "[initial connection] /198.51.100.10:54321 has disconnected",
                    1_001_000L
                ),
                "Blocked IP native disconnect spam must be swallowed"
            )
            // Legacy Paper hex-formatted kick message must be stripped and suppressed
            assertTrue(
                waveLogger.shouldSuppressServerLog(
                    "net.minecraft.server.network.ServerLoginPacketListenerImpl",
                    "Disconnecting BotSilent (/203.0.113.99:41222): §x§2§2§d§3§e§e§lS§x§2§0§c§9§e§a§le§x§1§e§b§f§e§6§ln§x§1§c§b§5§e§2§lt§x§1§a§a§b§d§e§li§x§1§8§a§1§d§a§ln§x§1§6§9§7§d§6§le§x§1§4§8§d§d§2§ll §x§1§2§8§3§c§e§lP§x§1§0§7§9§c§a§lr§x§0§e§6§f§c§6§lo§x§0§c§6§5§c§2§lt§x§0§a§5§b§b§e§le§x§0§8§5§1§b§a§lc§x§0§6§4§7§b§6§lt§x§0§4§3§d§b§2§li§x§0§2§3§3§a§e§lo§x§0§2§8§4§c§7§ln",
                    1_001_000L
                ),
                "Paper/Bungee hex-formatted Sentinel Protection kick log must be swallowed"
            )
            // Normal unrelated server chat or startup logs must NOT be suppressed
            assertFalse(
                waveLogger.shouldSuppressServerLog(
                    "net.minecraft.server.MinecraftServer",
                    "[Server thread/INFO]: Done (3.412s)! For help, type \"help\"",
                    1_001_000L
                ),
                "Normal server startup logs must never be suppressed"
            )

            // Re-enable console logs and verify summaries emit again
            waveLogger.consoleLogsEnabled = true
            waveLogger.logEnforceBlock("BotLoud", "198.51.100.11", vpnVerdict, 2_000_000L)
            waveLogger.flushSummaryAt(2_005_000L)
            assertEquals(1, warnLogs.size, "When consoleLogsEnabled is re-enabled, summary must emit")

            // Verify config toggle parsing & file persistence
            assertEquals(false, SentinelConfig.parseConsoleLogsToggle("off", true))
            assertEquals(true, SentinelConfig.parseConsoleLogsToggle("on", false))
            assertEquals(false, SentinelConfig.parseConsoleLogsToggle("toggle", true))
            assertEquals(true, SentinelConfig.parseConsoleLogsToggle(null, false))
            assertNull(SentinelConfig.parseConsoleLogsToggle("invalid", true))

            val cfgFile = tempDir.resolve("config.yml")
            java.nio.file.Files.writeString(
                cfgFile,
                "# Header comment\nmode: \"ENFORCE\"\nconsole-logs: true\n"
            )
            SentinelConfig.updateConsoleLogsInFile(cfgFile, false)
            val updatedText = java.nio.file.Files.readString(cfgFile)
            assertTrue(updatedText.contains("console-logs: false"))
            assertTrue(updatedText.contains("# Header comment"))
        } finally {
            waveLogger.shutdown()
        }
    }
}
