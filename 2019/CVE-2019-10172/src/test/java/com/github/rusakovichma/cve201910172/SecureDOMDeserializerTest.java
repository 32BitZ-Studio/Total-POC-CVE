package com.github.rusakovichma.cve201910172;

import com.github.rusakovichma.cve201910172.model.Person;
import com.github.rusakovichma.cve201910172.util.ResourceUtils;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

import static org.junit.Assert.*;

public class SecureDOMDeserializerTest {

    @Test(expected = IllegalArgumentException.class)
    public void deserializeMitigateXXETest() throws Exception {
        SecureDOMDeserializer deserializer = new SecureDOMDeserializer();
        Person person = deserializer._deserialize(IOUtils.toString(ResourceUtils.getPoc2(), "UTF-8"), null);
    }
}