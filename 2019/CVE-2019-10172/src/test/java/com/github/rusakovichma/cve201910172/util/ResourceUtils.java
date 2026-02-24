package com.github.rusakovichma.cve201910172.util;

import java.io.InputStream;

public class ResourceUtils {
    public static InputStream getPoc1() {
        return ResourceUtils.class.getClassLoader().getResourceAsStream("poc1.xml");
    }

    public static InputStream getPoc2() {
        return ResourceUtils.class.getClassLoader().getResourceAsStream("poc2.xml");
    }

    public static InputStream getPoc3() {
        return ResourceUtils.class.getClassLoader().getResourceAsStream("poc3.xsl");
    }
}
