package com.godaddy.asherah.jni;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.function.Consumer;

import org.json.JSONObject;
import org.junit.jupiter.api.Test;

/**
 * JSON serialization contract for {@link AsherahConfig} (no native JNI). Unset
 * optional string fields are omitted from the payload, matching {@link JsonUtil}.
 */
class AsherahConfigTest {

  private static AsherahConfig minimal(final Consumer<AsherahConfig.Builder> configure) {
    final AsherahConfig.Builder b =
        AsherahConfig.builder()
            .serviceName("svc")
            .productId("prod")
            .metastore("memory")
            .kms("static");
    if (configure != null) {
      configure.accept(b);
    }
    return b.build();
  }

  @Test
  void toJson_omitsAwsProfileNameWhenUnset() {
    final String json = minimal(null).toJson();
    final JSONObject o = new JSONObject(json);
    assertFalse(o.has("AwsProfileName"));
  }

  @Test
  void toJson_includesAwsProfileNameWhenSet() {
    final String json = minimal(b -> b.awsProfileName("test-profile")).toJson();
    final JSONObject o = new JSONObject(json);
    assertTrue(o.has("AwsProfileName"));
    assertEquals("test-profile", o.getString("AwsProfileName"));
  }

  @Test
  void toJson_omitsAwsProfileNameWhenClearedWithNull() {
    final String json =
        minimal(
                b -> {
                  b.awsProfileName("staging");
                  b.awsProfileName(null);
                })
            .toJson();
    final JSONObject o = new JSONObject(json);
    assertFalse(o.has("AwsProfileName"));
  }

  @Test
  void toJson_omitsConnectionStringWhenUnset() {
    final String json = minimal(null).toJson();
    final JSONObject o = new JSONObject(json);
    assertFalse(o.has("ConnectionString"));
  }

  @Test
  void toJson_includesConnectionStringWhenSet() {
    final String json = minimal(b -> b.connectionString("jdbc:test")).toJson();
    final JSONObject o = new JSONObject(json);
    assertTrue(o.has("ConnectionString"));
    assertEquals("jdbc:test", o.getString("ConnectionString"));
  }

  @Test
  void toJson_omitsConnectionStringWhenClearedWithNull() {
    final String json =
        minimal(
                b -> {
                  b.connectionString("jdbc:test");
                  b.connectionString(null);
                })
            .toJson();
    final JSONObject o = new JSONObject(json);
    assertFalse(o.has("ConnectionString"));
  }

  @Test
  void toJson_omitsDynamoDbEndpointWhenUnset() {
    final String json = minimal(null).toJson();
    final JSONObject o = new JSONObject(json);
    assertFalse(o.has("DynamoDbEndpoint"));
  }

  @Test
  void toJson_includesDynamoDbEndpointWhenSet() {
    final String json = minimal(b -> b.dynamoDbEndpoint("http://localhost:8000")).toJson();
    final JSONObject o = new JSONObject(json);
    assertTrue(o.has("DynamoDbEndpoint"));
    assertEquals("http://localhost:8000", o.getString("DynamoDbEndpoint"));
  }

  @Test
  void toJson_omitsDynamoDbEndpointWhenClearedWithNull() {
    final String json =
        minimal(
                b -> {
                  b.dynamoDbEndpoint("http://localhost:8000");
                  b.dynamoDbEndpoint(null);
                })
            .toJson();
    final JSONObject o = new JSONObject(json);
    assertFalse(o.has("DynamoDbEndpoint"));
  }

  @Test
  void toJson_omitsPreferredRegionWhenUnset() {
    final String json = minimal(null).toJson();
    final JSONObject o = new JSONObject(json);
    assertFalse(o.has("PreferredRegion"));
  }

  @Test
  void toJson_includesPreferredRegionWhenSet() {
    final String json = minimal(b -> b.preferredRegion("us-west-2")).toJson();
    final JSONObject o = new JSONObject(json);
    assertTrue(o.has("PreferredRegion"));
    assertEquals("us-west-2", o.getString("PreferredRegion"));
  }

  @Test
  void toJson_omitsPreferredRegionWhenClearedWithNull() {
    final String json =
        minimal(
                b -> {
                  b.preferredRegion("us-west-2");
                  b.preferredRegion(null);
                })
            .toJson();
    final JSONObject o = new JSONObject(json);
    assertFalse(o.has("PreferredRegion"));
  }

  @Test
  void toJson_omitsStaticMasterKeyHexWhenUnset() {
    final String json = minimal(null).toJson();
    final JSONObject o = new JSONObject(json);
    assertFalse(o.has("StaticMasterKeyHex"));
  }

  @Test
  void toJson_includesStaticMasterKeyHexWhenSet() {
    final String json =
        minimal(b -> b.staticMasterKeyHex("00112233445566778899aabbccddeeff")).toJson();
    final JSONObject o = new JSONObject(json);
    assertTrue(o.has("StaticMasterKeyHex"));
    assertEquals("00112233445566778899aabbccddeeff", o.getString("StaticMasterKeyHex"));
  }

  @Test
  void toJson_omitsStaticMasterKeyHexWhenClearedWithNull() {
    final String json =
        minimal(
                b -> {
                  b.staticMasterKeyHex("00112233445566778899aabbccddeeff");
                  b.staticMasterKeyHex(null);
                })
            .toJson();
    final JSONObject o = new JSONObject(json);
    assertFalse(o.has("StaticMasterKeyHex"));
  }
}
