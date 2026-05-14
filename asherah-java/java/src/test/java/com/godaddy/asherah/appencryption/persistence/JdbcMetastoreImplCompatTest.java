package com.godaddy.asherah.appencryption.persistence;

import com.godaddy.asherah.jni.AsherahConfig;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;

import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.logging.Logger;
import javax.sql.DataSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

class JdbcMetastoreImplCompatTest {

    @Test
    void explicitBuilderSettingsFlowToNativeConfig() {
        JdbcMetastoreImpl metastore = JdbcMetastoreImpl.newBuilder("jdbc:mysql://localhost:3306/test")
                .withPoolMaxOpen(20)
                .withPoolMaxIdle(8)
                .withPoolMaxLifetime(1800L)
                .withPoolMaxIdleTime(300L)
                .build();

        AsherahConfig.Builder cfgBuilder = AsherahConfig.builder()
                .serviceName("svc")
                .productId("prod");
        metastore.applyConfig(cfgBuilder);
        AsherahConfig cfg = cfgBuilder.build();

        JSONObject json = new JSONObject(cfg.toJson());
        assertEquals("rdbms", json.getString("Metastore"));
        assertEquals("mysql://localhost:3306/test", json.getString("ConnectionString"));
        assertEquals(20, json.getInt("PoolMaxOpen"));
        assertEquals(8, json.getInt("PoolMaxIdle"));
        assertEquals(1800L, json.getLong("PoolMaxLifetime"));
        assertEquals(300L, json.getLong("PoolMaxIdleTime"));
    }

    @Test
    void dataSourceBuilderExtractsUrlAndPoolHints() {
        StubPoolDataSource dataSource =
                new StubPoolDataSource("jdbc:postgresql://db.example:5432/app", 30, 10, 3_500L, 1_001L);

        JdbcMetastoreImpl metastore = JdbcMetastoreImpl.newBuilder(dataSource).build();

        AsherahConfig.Builder cfgBuilder = AsherahConfig.builder()
                .serviceName("svc")
                .productId("prod");
        metastore.applyConfig(cfgBuilder);
        AsherahConfig cfg = cfgBuilder.build();

        JSONObject json = new JSONObject(cfg.toJson());
        assertEquals("rdbms", json.getString("Metastore"));
        assertEquals("postgresql://db.example:5432/app", json.getString("ConnectionString"));
        assertEquals(30, json.getInt("PoolMaxOpen"));
        assertEquals(10, json.getInt("PoolMaxIdle"));
        // Rounded up from milliseconds for second-based native config fields.
        assertEquals(4L, json.getLong("PoolMaxLifetime"));
        assertEquals(2L, json.getLong("PoolMaxIdleTime"));
    }

    private static final class StubPoolDataSource implements DataSource {
        private final String jdbcUrl;
        private final int maximumPoolSize;
        private final int minimumIdle;
        private final long maxLifetime;
        private final long idleTimeout;

        private StubPoolDataSource(
                final String jdbcUrl,
                final int maximumPoolSize,
                final int minimumIdle,
                final long maxLifetime,
                final long idleTimeout
        ) {
            this.jdbcUrl = jdbcUrl;
            this.maximumPoolSize = maximumPoolSize;
            this.minimumIdle = minimumIdle;
            this.maxLifetime = maxLifetime;
            this.idleTimeout = idleTimeout;
        }

        // Reflection targets in JdbcMetastoreImpl.newBuilder(DataSource)
        public String getJdbcUrl() {
            return jdbcUrl;
        }

        public int getMaximumPoolSize() {
            return maximumPoolSize;
        }

        public int getMinimumIdle() {
            return minimumIdle;
        }

        public long getMaxLifetime() {
            return maxLifetime;
        }

        public long getIdleTimeout() {
            return idleTimeout;
        }

        @Override
        public Connection getConnection() throws SQLException {
            throw new SQLFeatureNotSupportedException();
        }

        @Override
        public Connection getConnection(final String username, final String password) throws SQLException {
            throw new SQLFeatureNotSupportedException();
        }

        @Override
        public PrintWriter getLogWriter() {
            return null;
        }

        @Override
        public void setLogWriter(final PrintWriter out) {
        }

        @Override
        public void setLoginTimeout(final int seconds) {
        }

        @Override
        public int getLoginTimeout() {
            return 0;
        }

        @Override
        public Logger getParentLogger() throws SQLFeatureNotSupportedException {
            throw new SQLFeatureNotSupportedException();
        }

        @Override
        public <T> T unwrap(final Class<T> iface) throws SQLException {
            throw new SQLFeatureNotSupportedException();
        }

        @Override
        public boolean isWrapperFor(final Class<?> iface) {
            return false;
        }
    }
}
