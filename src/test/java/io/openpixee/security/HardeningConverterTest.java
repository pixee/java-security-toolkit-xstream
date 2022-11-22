package io.openpixee.security;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.converters.ConversionException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.function.Predicate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

final class HardeningConverterTest {

  private XStream xstream;

  @BeforeEach
  void setup() {
    xstream = new XStream();
  }

  @Test
  void it_allows_normal_operations() {
    xstream.registerConverter(new HardeningConverter());
    String foo = (String) xstream.fromXML("<string>foo</string>");
    assertThat(foo, equalTo("foo"));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "<owner class=\"java.lang.ProcessBuilder\">\n"
            + "              <command>\n"
            + "                <string>open</string>\n"
            + "                <string>/Applications/Calculator.app</string>\n"
            + "              </command>\n"
            + "              <redirectErrorStream>false</redirectErrorStream>\n"
            + "            </owner>",
      })
  void it_prevents_attack_type_conversion(final String xml) {
    ProcessBuilder pb = (ProcessBuilder) xstream.fromXML(xml);
    assertThat(pb, is(notNullValue()));

    xstream.registerConverter(new HardeningConverter());

    assertThrows(ConversionException.class, () -> xstream.fromXML(xml));
  }

  @Test
  void it_uses_overriden_types_when_provided() {
    xstream.registerConverter(
        new HardeningConverter(
            new HashSet<>(Collections.singletonList(String.class)), Collections.emptyList()));
    assertThrows(ConversionException.class, () -> xstream.fromXML("<string>foo</string>"));

    URL url = (URL) xstream.fromXML("<url>https://cloud9</url>");
    assertThat(url.getHost(), equalTo("cloud9"));
  }

  @Test
  void it_uses_type_checking_predicate_when_provided() throws MalformedURLException {

    // confirm that we can deserialize a simple string
    xstream.fromXML("<string>foo</string>");

    String mapXml = xstream.toXML(new HashMap<>());
    String runtimeXml = xstream.toXML(Runtime.getRuntime());
    String urlXml = xstream.toXML(new URL("http://cloud9"));

    final Predicate<Class<?>> blocksEverythingPredicate = aClass -> true;

    xstream.registerConverter(
        new HardeningConverter(
            Collections.emptySet(), Collections.singletonList(blocksEverythingPredicate)));
    assertThrows(ConversionException.class, () -> xstream.fromXML("<string>foo</string>"));
    assertThrows(ConversionException.class, () -> xstream.fromXML(mapXml));
    assertThrows(ConversionException.class, () -> xstream.fromXML(runtimeXml));
    assertThrows(ConversionException.class, () -> xstream.fromXML(urlXml));
  }
}
