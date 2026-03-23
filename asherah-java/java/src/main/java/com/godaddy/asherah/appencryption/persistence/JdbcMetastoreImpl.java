package com.godaddy.asherah.appencryption.persistence;

import com.godaddy.asherah.jni.AsherahConfig;
import org.json.JSONObject;

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

    private JdbcMetastoreImpl(final Builder builder) {
        this.connectionString = builder.connectionString;
    }

    public void applyConfig(final AsherahConfig.Builder builder) {
        builder.metastore("rdbms");
        if (connectionString != null) {
            builder.connectionString(connectionString);
        }
    }

    public static Builder newBuilder(final String connectionString) {
        return new Builder(connectionString);
    }

    /**
     * Overload accepting a DataSource for canonical API compat.
     * Extracts the connection URL if possible; otherwise the connection
     * string must be set via the CONNECTION_STRING environment variable.
     */
    public static Builder newBuilder(final DataSource dataSource) {
        // DataSource doesn't expose a standard URL getter.
        // Users must set CONNECTION_STRING env var or use the String overload.
        return new Builder(null);
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

        private Builder(final String connectionString) {
            this.connectionString = connectionString;
        }

        public JdbcMetastoreImpl build() {
            return new JdbcMetastoreImpl(this);
        }
    }
}
