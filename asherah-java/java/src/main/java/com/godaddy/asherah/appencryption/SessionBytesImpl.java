package com.godaddy.asherah.appencryption;

import com.godaddy.asherah.jni.AsherahSession;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;

/**
 * Session implementation for byte[] payloads.
 * Wraps the native AsherahSession. Compatible with the canonical godaddy/asherah SDK.
 *
 * @param <D> the data row record type (byte[] or JSONObject)
 */
class SessionBytesImpl<D> implements Session<byte[], D> {

    private final AsherahSession inner;
    private final boolean drrIsJson;

    SessionBytesImpl(final AsherahSession inner, final boolean drrIsJson) {
        this.inner = inner;
        this.drrIsJson = drrIsJson;
    }

    @Override
    @SuppressWarnings("unchecked")
    public D encrypt(final byte[] payload) {
        final String drrJson = inner.encryptToJson(payload);
        if (drrIsJson) {
            return (D) new JSONObject(drrJson);
        }
        return (D) drrJson.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public byte[] decrypt(final D dataRowRecord) {
        final String drrJson;
        if (dataRowRecord instanceof JSONObject) {
            drrJson = ((JSONObject) dataRowRecord).toString();
        } else {
            drrJson = new String((byte[]) dataRowRecord, StandardCharsets.UTF_8);
        }
        return inner.decryptFromJson(drrJson);
    }

    @Override
    public void close() {
        inner.close();
    }
}
