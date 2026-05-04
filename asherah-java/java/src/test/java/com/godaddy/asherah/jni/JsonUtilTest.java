package com.godaddy.asherah.jni;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.Map;

import org.json.JSONObject;
import org.junit.jupiter.api.Test;

class JsonUtilTest {

  @Test
  void toJson_omitsNullEntries() {
    final Map<String, Object> values = new LinkedHashMap<>();
    values.put("Set", "v");
    values.put("Unset", null);
    final JSONObject o = new JSONObject(JsonUtil.toJson(values));
    assertTrue(o.has("Set"));
    assertFalse(o.has("Unset"));
  }

  @Test
  void toJson_emitsAllValueShapes() {
    final Map<String, Object> values = new LinkedHashMap<>();
    values.put("Str", "hello");
    values.put("Int", 42);
    values.put("Bool", true);
    final Map<String, Object> nested = new LinkedHashMap<>();
    nested.put("Inner", "x");
    values.put("Map", nested);
    final JSONObject o = new JSONObject(JsonUtil.toJson(values));
    assertEquals("hello", o.getString("Str"));
    assertEquals(42, o.getInt("Int"));
    assertTrue(o.getBoolean("Bool"));
    assertEquals("x", o.getJSONObject("Map").getString("Inner"));
  }

  @Test
  void toJson_escapesControlAndQuoteChars() {
    final Map<String, Object> values = new LinkedHashMap<>();
    values.put("K", "a\"b\\c\nd\tef");
    final JSONObject o = new JSONObject(JsonUtil.toJson(values));
    assertEquals("a\"b\\c\nd\tef", o.getString("K"));
  }
}
