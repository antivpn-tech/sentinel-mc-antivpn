package tech.antivpn.sentinel.common

import org.apache.logging.log4j.Level
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Marker
import org.apache.logging.log4j.core.Filter
import org.apache.logging.log4j.core.LogEvent
import org.apache.logging.log4j.core.Logger
import org.apache.logging.log4j.core.LoggerContext
import org.apache.logging.log4j.core.filter.AbstractFilter
import org.apache.logging.log4j.message.Message
import java.util.logging.Handler
import java.util.logging.LogRecord
import java.util.logging.Logger as JulLogger

/**
 * Installs low-level console log filters onto Log4j2 (Paper, Folia, Spigot, Waterfall, Velocity)
 * and Java Util Logging (BungeeCord, Bukkit) to swallow native server connection/disconnect IP spam
 * when Sentinel blocks threats or mitigates a high-volume attack wave.
 */
class ConsoleSpamFilter private constructor(
    private val log4jUninstall: (() -> Unit)?,
    private val julUninstall: (() -> Unit)?
) {
    fun uninstall() {
        try {
            log4jUninstall?.invoke()
        } catch (_: Throwable) {
        }
        try {
            julUninstall?.invoke()
        } catch (_: Throwable) {
        }
    }

    companion object {
        @JvmStatic
        fun install(
            waveLogger: ConsoleWaveLogger,
            julLoggers: List<JulLogger> = emptyList()
        ): ConsoleSpamFilter {
            val log4jCleanup = try {
                Log4jFilterInstaller.install(waveLogger)
            } catch (_: Throwable) {
                null
            }
            val julCleanup = try {
                JulFilterInstaller.install(waveLogger, julLoggers)
            } catch (_: Throwable) {
                null
            }
            return ConsoleSpamFilter(log4jCleanup, julCleanup)
        }
    }
}

private object JulFilterInstaller {
    fun install(waveLogger: ConsoleWaveLogger, extraLoggers: List<JulLogger>): () -> Unit {
        val targetLoggers = LinkedHashSet<JulLogger>()
        try {
            targetLoggers.add(JulLogger.getLogger(""))
        } catch (_: Throwable) {
        }
        try {
            targetLoggers.add(JulLogger.getLogger("BungeeCord"))
        } catch (_: Throwable) {
        }
        try {
            targetLoggers.add(JulLogger.getLogger("Minecraft"))
        } catch (_: Throwable) {
        }
        for (l in extraLoggers) {
            targetLoggers.add(l)
            l.parent?.let { targetLoggers.add(it) }
        }

        val previousLoggerFilters = LinkedHashMap<JulLogger, java.util.logging.Filter?>()
        val previousHandlerFilters = LinkedHashMap<Handler, java.util.logging.Filter?>()

        for (logger in targetLoggers) {
            val prev = logger.filter
            previousLoggerFilters[logger] = prev
            logger.filter = java.util.logging.Filter { record: LogRecord? ->
                if (record != null && waveLogger.shouldSuppressServerLogTemplate(
                        record.loggerName,
                        record.message,
                        record.parameters
                    )
                ) {
                    return@Filter false
                }
                prev?.isLoggable(record) ?: true
            }

            for (handler in logger.handlers) {
                if (!previousHandlerFilters.containsKey(handler)) {
                    val prevHandlerFilter = handler.filter
                    previousHandlerFilters[handler] = prevHandlerFilter
                    handler.filter = java.util.logging.Filter { record: LogRecord? ->
                        if (record != null && waveLogger.shouldSuppressServerLogTemplate(
                                record.loggerName,
                                record.message,
                                record.parameters
                            )
                        ) {
                            return@Filter false
                        }
                        prevHandlerFilter?.isLoggable(record) ?: true
                    }
                }
            }
        }

        return {
            for ((logger, prev) in previousLoggerFilters) {
                try {
                    logger.filter = prev
                } catch (_: Throwable) {
                }
            }
            for ((handler, prev) in previousHandlerFilters) {
                try {
                    handler.filter = prev
                } catch (_: Throwable) {
                }
            }
        }
    }
}

private object Log4jFilterInstaller {
    fun install(waveLogger: ConsoleWaveLogger): (() -> Unit)? {
        val filter = object : AbstractFilter(Filter.Result.DENY, Filter.Result.NEUTRAL) {
            override fun filter(event: LogEvent?): Filter.Result {
                if (event == null) return Filter.Result.NEUTRAL
                val formatted = try {
                    event.message?.formattedMessage
                } catch (_: Throwable) {
                    null
                }
                return if (waveLogger.shouldSuppressServerLog(event.loggerName, formatted)) {
                    Filter.Result.DENY
                } else {
                    Filter.Result.NEUTRAL
                }
            }

            override fun filter(
                logger: Logger?,
                level: Level?,
                marker: Marker?,
                msg: Message?,
                t: Throwable?
            ): Filter.Result {
                val formatted = try {
                    msg?.formattedMessage
                } catch (_: Throwable) {
                    null
                }
                return if (waveLogger.shouldSuppressServerLog(logger?.name, formatted)) {
                    Filter.Result.DENY
                } else {
                    Filter.Result.NEUTRAL
                }
            }

            override fun filter(
                logger: Logger?,
                level: Level?,
                marker: Marker?,
                msg: Any?,
                t: Throwable?
            ): Filter.Result {
                return if (waveLogger.shouldSuppressServerLog(logger?.name, msg?.toString())) {
                    Filter.Result.DENY
                } else {
                    Filter.Result.NEUTRAL
                }
            }

            override fun filter(
                logger: Logger?,
                level: Level?,
                marker: Marker?,
                msg: String?,
                p0: Any?
            ): Filter.Result {
                return if (waveLogger.shouldSuppressServerLogTemplate(logger?.name, msg, arrayOf(p0))) {
                    Filter.Result.DENY
                } else {
                    Filter.Result.NEUTRAL
                }
            }

            override fun filter(
                logger: Logger?,
                level: Level?,
                marker: Marker?,
                msg: String?,
                p0: Any?,
                p1: Any?
            ): Filter.Result {
                return if (waveLogger.shouldSuppressServerLogTemplate(logger?.name, msg, arrayOf(p0, p1))) {
                    Filter.Result.DENY
                } else {
                    Filter.Result.NEUTRAL
                }
            }

            override fun filter(
                logger: Logger?,
                level: Level?,
                marker: Marker?,
                msg: String?,
                p0: Any?,
                p1: Any?,
                p2: Any?
            ): Filter.Result {
                return if (waveLogger.shouldSuppressServerLogTemplate(logger?.name, msg, arrayOf(p0, p1, p2))) {
                    Filter.Result.DENY
                } else {
                    Filter.Result.NEUTRAL
                }
            }
        }

        filter.start()
        val rootLogger = LogManager.getRootLogger() as? Logger
        val context = rootLogger?.context ?: (LogManager.getContext(false) as? LoggerContext)
        rootLogger?.addFilter(filter)
        context?.configuration?.addFilter(filter)
        context?.configuration?.rootLogger?.addFilter(filter)
        context?.updateLoggers()

        return {
            try {
                context?.configuration?.removeFilter(filter)
                context?.configuration?.rootLogger?.removeFilter(filter)
                context?.updateLoggers()
                filter.stop()
            } catch (_: Throwable) {
            }
        }
    }
}
