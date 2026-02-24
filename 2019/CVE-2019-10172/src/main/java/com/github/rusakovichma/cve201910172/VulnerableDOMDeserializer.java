package com.github.rusakovichma.cve201910172;

import com.github.rusakovichma.cve201910172.model.Person;
import org.codehaus.jackson.map.DeserializationContext;
import org.codehaus.jackson.map.ext.DOMDeserializer;
import org.w3c.dom.Document;

public class VulnerableDOMDeserializer extends DOMDeserializer<Person> {

    public VulnerableDOMDeserializer() {
        super(Person.class);
    }

    public Person _deserialize(String value, DeserializationContext ctxt) {
        Document doc = this.parse(value);
        Person person = new Person();
        person.age = Integer.valueOf(doc.getElementsByTagName("age").item(0).getTextContent());
        person.name = doc.getElementsByTagName("name").item(0).getTextContent();
        return person;
    }
}
