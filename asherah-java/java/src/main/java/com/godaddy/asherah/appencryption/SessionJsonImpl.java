package com.godaddy.asherah.appencryption;

import com.godaddy.asherah.jni.AsherahSession;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;

/**
 * Session implementation for JSONObject payloads with byte[] data row records.
 * Wraps the native AsherahSession. Compatible with the canonical godaddy/asherah SDK.
 *
 * @param <D> the data row record type (byte[] or JSONObject)
 */
class SessionJsonImpl<D> implements Session<JSONObject, D> {

    private final AsherahSession inner;
    private final boolean drrIsJson;

    SessionJsonImpl(final AsherahSession inner, final boolean drrIsJson) {
        this.inner = inner;
        this.drrIsJson = drrIsJson;
    }

    @Override
    @SuppressWarnings("unchecked")
    public D encrypt(final JSONObject payload) {
        final byte[] data = payload.toString().getBytes(StandardCharsets.UTF_8);
        final String drrJson = inner.encryptToJson(data);
        if (drrIsJson) {
            return (D) new JSONObject(drrJson);
        }
        return (D) drrJson.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public JSONObject decrypt(final D dataRowRecord) {
        final String drrJson;
        if (dataRowRecord instanceof JSONObject) {
            drrJson = ((JSONObject) dataRowRecord).toString();
        } else {
            drrJson = new String((byte[]) dataRowRecord, StandardCharsets.UTF_8);
        }
        final byte[] plaintext = inner.decryptFromJson(drrJson);
        return new JSONObject(new String(plaintext, StandardCharsets.UTF_8));
    }

    @Override
    public void close() {
        inner.close();
    }
}
