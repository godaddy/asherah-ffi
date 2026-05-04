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
}
