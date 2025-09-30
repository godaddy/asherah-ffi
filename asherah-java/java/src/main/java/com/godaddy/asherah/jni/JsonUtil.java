package com.godaddy.asherah.jni;

import java.util.Iterator;
import java.util.Map;

final class JsonUtil {
  private JsonUtil() {}

  static String toJson(final Map<String, ?> values) {
    final StringBuilder sb = new StringBuilder();
    sb.append('{');
    final Iterator<? extends Map.Entry<String, ?>> iter = values.entrySet().iterator();
    boolean first = true;
    while (iter.hasNext()) {
      final Map.Entry<String, ?> entry = iter.next();
      if (!first) {
        sb.append(',');
      }
      first = false;
      appendEscapedString(sb, entry.getKey());
      sb.append(':');
      appendValue(sb, entry.getValue());
    }
    sb.append('}');
    return sb.toString();
  }

  static void appendValue(final StringBuilder sb, final Object value) {
    if (value == null) {
      sb.append("null");
    } else if (value instanceof String) {
      appendEscapedString(sb, (String) value);
    } else if (value instanceof Number || value instanceof Boolean) {
      sb.append(value.toString());
    } else if (value instanceof Map) {
      @SuppressWarnings("unchecked")
      final Map<String, ?> nested = (Map<String, ?>) value;
      sb.append(toJson(nested));
    } else {
      appendEscapedString(sb, value.toString());
    }
  }

  private static void appendEscapedString(final StringBuilder sb, final String value) {
    sb.append('"');
    for (int i = 0; i < value.length(); i++) {
      final char c = value.charAt(i);
      switch (c) {
        case '\\':
        case '"':
          sb.append('\\').append(c);
          break;
        case '\b':
          sb.append("\\b");
          break;
        case '\f':
          sb.append("\\f");
          break;
        case '\n':
          sb.append("\\n");
          break;
        case '\r':
          sb.append("\\r");
          break;
        case '\t':
          sb.append("\\t");
          break;
        default:
          if (c < 0x20) {
            sb.append(String.format("\\u%04x", (int) c));
          } else {
            sb.append(c);
          }
      }
    }
    sb.append('"');
  }
}
