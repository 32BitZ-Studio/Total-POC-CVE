package com.github.rusakovichma.cve201910172;

import com.github.rusakovichma.cve201910172.model.Person;
import com.github.rusakovichma.cve201910172.util.ResourceUtils;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

import static org.junit.Assert.*;

public class VulnerableDOMDeserializerTest {

    private static final String VULN_OUTPUT = "# use glob syntax.\n" +
            "syntax: glob\n" +
            "*.class\n" +
            "*~\n" +
            "*.bak\n" +
            "*.off\n" +
            "*.old\n" +
            ".DS_Store\n" +
            "\n" +
            "# building\n" +
            "target\n" +
            "/build\n" +
            "/dist\n" +
            "\n" +
            "# Eclipse\n" +
            ".classpath\n" +
            ".project\n" +
            ".settings\n" +
            "\n" +
            "# IDEA\n" +
            ".idea\n" +
            "*.iml\n" +
            "*.ipr\n" +
            "*.iws\n" +
            "/target\n" +
            "/eclipse/";

    @Test
    public void deserializeXXEAttack() throws Exception {
        VulnerableDOMDeserializer deserializer = new VulnerableDOMDeserializer();
        Person person = deserializer._deserialize(IOUtils.toString(ResourceUtils.getPoc2(), "UTF-8"), null);
        assertTrue(person.name.contains(VULN_OUTPUT));
    }
}