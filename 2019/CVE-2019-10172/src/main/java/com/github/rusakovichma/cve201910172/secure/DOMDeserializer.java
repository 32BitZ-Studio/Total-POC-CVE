package com.github.rusakovichma.cve201910172.secure;

import java.io.StringReader;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.codehaus.jackson.map.DeserializationContext;
import org.codehaus.jackson.map.deser.std.FromStringDeserializer;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

public abstract class DOMDeserializer<T> extends FromStringDeserializer<T> {
    final static DocumentBuilderFactory _parserFactory;

    static {
        _parserFactory = DocumentBuilderFactory.newInstance();
        // yup, only cave men do XML without recognizing namespaces...
        _parserFactory.setNamespaceAware(true);
        _parserFactory.setExpandEntityReferences(false);
        try {
            _parserFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        } catch (ParserConfigurationException pce) {
            System.err.println("[DOMDeserializer] Problem setting SECURE_PROCESSING_FEATURE: " + pce.toString());
        }
    }

    protected DOMDeserializer(Class<T> cls) {
        super(cls);
    }

    @Override
    public abstract T _deserialize(String value, DeserializationContext ctxt);

    protected final Document parse(String value) throws IllegalArgumentException {
        try {
            return _parserFactory.newDocumentBuilder().parse(new InputSource(new StringReader(value)));
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse JSON String as XML: " + e.getMessage(), e);
        }
    }

    /*
    /**********************************************************
    /* Concrete deserializers
    /**********************************************************
     */

    public static class NodeDeserializer extends org.codehaus.jackson.map.ext.DOMDeserializer<Node> {
        public NodeDeserializer() {
            super(Node.class);
        }

        @Override
        public Node _deserialize(String value, DeserializationContext ctxt) throws IllegalArgumentException {
            return parse(value);
        }
    }

    public static class DocumentDeserializer extends org.codehaus.jackson.map.ext.DOMDeserializer<Document> {
        public DocumentDeserializer() {
            super(Document.class);
        }

        @Override
        public Document _deserialize(String value, DeserializationContext ctxt) throws IllegalArgumentException {
            return parse(value);
        }
    }
}
