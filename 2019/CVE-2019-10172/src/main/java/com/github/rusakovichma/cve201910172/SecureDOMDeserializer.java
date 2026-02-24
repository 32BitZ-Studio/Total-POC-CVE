package com.github.rusakovichma.cve201910172;

import com.github.rusakovichma.cve201910172.model.Person;
import com.github.rusakovichma.cve201910172.secure.DOMDeserializer;
import org.codehaus.jackson.map.DeserializationContext;
import org.w3c.dom.Document;

public class SecureDOMDeserializer extends DOMDeserializer<Person> {

    public SecureDOMDeserializer() {
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
