package com.godaddy.asherah.appencryption.persistence;

import com.godaddy.asherah.jni.AsherahConfig;
import org.json.JSONObject;

import java.lang.reflect.Method;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import javax.sql.DataSource;

/**
 * JDBC/RDBMS metastore adapter. Maps to metastore="rdbms" in the native config.
 * Compatible with the canonical godaddy/asherah JdbcMetastoreImpl.
 */
public class JdbcMetastoreImpl implements Metastore<JSONObject> {

    private final String connectionString;
    private final Integer poolMaxOpen;
    private final Integer poolMaxIdle;
    private final Long poolMaxLifetimeSeconds;
    private final Long poolMaxIdleTimeSeconds;

    private JdbcMetastoreImpl(final Builder builder) {
        this.connectionString = normalizeConnectionString(builder.connectionString);
        this.poolMaxOpen = builder.poolMaxOpen;
        this.poolMaxIdle = builder.poolMaxIdle;
        this.poolMaxLifetimeSeconds = builder.poolMaxLifetimeSeconds;
        this.poolMaxIdleTimeSeconds = builder.poolMaxIdleTimeSeconds;
    }

    public void applyConfig(final AsherahConfig.Builder builder) {
        builder.metastore("rdbms");
        if (connectionString != null) {
            builder.connectionString(connectionString);
        }
        if (poolMaxOpen != null) {
            builder.poolMaxOpen(poolMaxOpen);
        }
        if (poolMaxIdle != null) {
            builder.poolMaxIdle(poolMaxIdle);
        }
        if (poolMaxLifetimeSeconds != null) {
            builder.poolMaxLifetime(poolMaxLifetimeSeconds);
        }
        if (poolMaxIdleTimeSeconds != null) {
            builder.poolMaxIdleTime(poolMaxIdleTimeSeconds);
        }
    }

    public static Builder newBuilder(final String connectionString) {
        return new Builder(connectionString);
    }

    /**
     * Overload accepting a DataSource for canonical API compat.
     * Best-effort extraction of connection URL + common pool settings
     * (for example HikariCP/DBCP-style getters) and maps them into
     * native AsherahConfig fields.
     */
    public static Builder newBuilder(final DataSource dataSource) {
        Objects.requireNonNull(dataSource, "dataSource");
        return new Builder(tryExtractConnectionString(dataSource))
                .withPoolMaxOpen(tryExtractMaxOpen(dataSource))
                .withPoolMaxIdle(tryExtractMaxIdle(dataSource))
                .withPoolMaxLifetime(toSecondsCeil(tryExtractMaxLifetimeMillis(dataSource)))
                .withPoolMaxIdleTime(toSecondsCeil(tryExtractMaxIdleTimeMillis(dataSource)));
    }

    @Override
    public Optional<JSONObject> load(final String keyId, final Instant created) {
        throw new UnsupportedOperationException("Metastore operations are handled by the native layer");
    }

    @Override
    public Optional<JSONObject> loadLatest(final String keyId) {
        throw new UnsupportedOperationException("Metastore operations are handled by the native layer");
    }

    @Override
    public boolean store(final String keyId, final Instant created, final JSONObject value) {
        throw new UnsupportedOperationException("Metastore operations are handled by the native layer");
    }

    public static final class Builder {
        private final String connectionString;
        private Integer poolMaxOpen;
        private Integer poolMaxIdle;
        private Long poolMaxLifetimeSeconds;
        private Long poolMaxIdleTimeSeconds;

        private Builder(final String connectionString) {
            this.connectionString = connectionString;
        }

        public Builder withPoolMaxOpen(final Integer value) {
            this.poolMaxOpen = value;
            return this;
        }

        public Builder withPoolMaxIdle(final Integer value) {
            this.poolMaxIdle = value;
            return this;
        }

        public Builder withPoolMaxLifetime(final Long seconds) {
            this.poolMaxLifetimeSeconds = seconds;
            return this;
        }

        public Builder withPoolMaxIdleTime(final Long seconds) {
            this.poolMaxIdleTimeSeconds = seconds;
            return this;
        }

        public JdbcMetastoreImpl build() {
            return new JdbcMetastoreImpl(this);
        }
    }

    private static String normalizeConnectionString(final String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.startsWith("jdbc:") ? value.substring("jdbc:".length()) : value;
    }

    private static String tryExtractConnectionString(final DataSource dataSource) {
        return invokeString(dataSource, "getJdbcUrl", "getJdbcURL", "getUrl", "getURL")
                .map(JdbcMetastoreImpl::normalizeConnectionString)
                .orElse(null);
    }

    private static Integer tryExtractMaxOpen(final DataSource dataSource) {
        return invokeInteger(dataSource, "getMaximumPoolSize", "getMaxTotal", "getMaxActive")
                .orElse(null);
    }

    private static Integer tryExtractMaxIdle(final DataSource dataSource) {
        return invokeInteger(dataSource, "getMaxIdle", "getMinimumIdle").orElse(null);
    }

    private static Long tryExtractMaxLifetimeMillis(final DataSource dataSource) {
        return invokeLong(dataSource, "getMaxLifetime", "getMaxConnLifetimeMillis").orElse(null);
    }

    private static Long tryExtractMaxIdleTimeMillis(final DataSource dataSource) {
        return invokeLong(dataSource, "getIdleTimeout", "getMinEvictableIdleTimeMillis").orElse(null);
    }

    private static Long toSecondsCeil(final Long millis) {
        if (millis == null) {
            return null;
        }
        if (millis <= 0L) {
            return 0L;
        }
        return (millis + 999L) / 1000L;
    }

    private static Optional<String> invokeString(final Object target, final String... methodNames) {
        for (String methodName : methodNames) {
            Optional<Object> value = invokeNoArg(target, methodName);
            if (value.isPresent() && value.get() instanceof String) {
                String stringValue = (String) value.get();
                if (!stringValue.isBlank()) {
                    return Optional.of(stringValue);
                }
            }
        }
        return Optional.empty();
    }

    private static Optional<Integer> invokeInteger(final Object target, final String... methodNames) {
        for (String methodName : methodNames) {
            Optional<Object> value = invokeNoArg(target, methodName);
            if (value.isPresent() && value.get() instanceof Number) {
                return Optional.of(((Number) value.get()).intValue());
            }
        }
        return Optional.empty();
    }

    private static Optional<Long> invokeLong(final Object target, final String... methodNames) {
        for (String methodName : methodNames) {
            Optional<Object> value = invokeNoArg(target, methodName);
            if (value.isPresent() && value.get() instanceof Number) {
                return Optional.of(((Number) value.get()).longValue());
            }
        }
        return Optional.empty();
    }

    private static Optional<Object> invokeNoArg(final Object target, final String methodName) {
        try {
            Method method = target.getClass().getMethod(methodName);
            return Optional.ofNullable(method.invoke(target));
        } catch (ReflectiveOperationException e) {
            return Optional.empty();
        }
    }
}
