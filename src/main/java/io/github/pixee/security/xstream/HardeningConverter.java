package io.github.pixee.security.xstream;

import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;

/**
 * This type can be used to protect {@link com.thoughtworks.xstream.XStream} serialization and
 * deserialization operations from attack. It can be added via {@link
 * com.thoughtworks.xstream.XStream#registerConverter(Converter)} alongside other converters as a
 * safeguard to help prevent exploitation.
 *
 * <p>Ideally users should specify allowed types, but this is difficult in practice as the object
 * graphs users work with could become extensive and difficult to maintain over time. And, not
 * managing such an object graph ahead of time is sort of the point of libraries like XStream.
 *
 * <p>It's worth noting that newer versions of XStream (&gt;= 1.4.7) have simpler APIs to prevent
 * unwanted types, so it only makes sense to use this {@link Converter} strategy in &lt; 1.4.7
 * installations. In later versions, there are methods like denyTypes(Class) and denyTypes(String)
 * that will be more readable.
 *
 * <p>https://www.contrastsecurity.com/security-influencers/serialization-must-die-act-2-xstream
 * https://www.jenkins.io/security/advisory/2022-02-09/
 *
 * <p>Providing generalized and robust protections is difficult because there may be types on the
 * classpath that offer side effects that are not yet known to the public. However, looking at the
 * history of exploitation, we can make a strong protection that will at least require the discovery
 * of new "gadget" types.
 */
public final class HardeningConverter implements Converter {

  private final Set<Class<?>> dangerousTypes;
  private final List<Predicate<Class<?>>> dangerousTypeCheckers;

  public HardeningConverter() {
    this(defaultDangerousTypes, defaultDangerousTypeCheckers);
  }

  public HardeningConverter(
      final Set<Class<?>> dangerousTypes, final List<Predicate<Class<?>>> dangerousTypeCheckers) {
    this.dangerousTypes = dangerousTypes;
    this.dangerousTypeCheckers = dangerousTypeCheckers;
  }

  /**
   * Prevent conversions of dangerous types.
   *
   * @param type the type being deserialized or serialized
   * @return true, if the type is malicious -- false otherwise
   */
  @Override
  public boolean canConvert(final Class type) {
    if (dangerousTypes.contains(type)) {
      return true;
    }

    for (Predicate<Class<?>> dangerousTypeChecker : dangerousTypeCheckers) {
      if (dangerousTypeChecker.test(type)) {
        return true;
      }
    }

    return false;
  }

  /** {@inheritDoc} */
  @Override
  public Object unmarshal(
      final HierarchicalStreamReader reader, final UnmarshallingContext context) {
    throw new SecurityException("unsupported type due to security reasons");
  }

  /** {@inheritDoc} */
  @Override
  public void marshal(
      final Object source,
      final HierarchicalStreamWriter writer,
      final com.thoughtworks.xstream.converters.MarshallingContext context) {
    throw new SecurityException("unsupported type due to security reasons");
  }

  private static final Set<Class<?>> defaultDangerousTypes =
      Collections.unmodifiableSet(
          new HashSet<>(
              Arrays.asList(java.beans.EventHandler.class, java.lang.ProcessBuilder.class)));

  private static final List<Predicate<Class<?>>> defaultDangerousTypeCheckers =
      Collections.singletonList(Proxy::isProxyClass);

  /**
   * A {@link HardeningConverter} instance with default restrictions. Equivalent to creating a new
   * instance without any constructor parameters.
   */
  public static final HardeningConverter DEFAULT = new HardeningConverter();
}
