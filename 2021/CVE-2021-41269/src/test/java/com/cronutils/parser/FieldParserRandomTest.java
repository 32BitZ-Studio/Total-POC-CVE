package com.cronutils.parser;

import org.junit.jupiter.api.Disabled;
import com.cronutils.model.field.constraint.FieldConstraints;
import com.cronutils.model.field.expression.FieldExpression;
import com.cronutils.model.field.expression.RandomExpression;
import com.cronutils.model.field.value.SpecialChar;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

@Disabled
class FieldParserRandomTest {
    private FieldParser parser;
    private FieldConstraints constraints;

    @BeforeEach
    void setUp() {
        constraints = mock(FieldConstraints.class);
        parser = new FieldParser(constraints);
    }

    @Test
    void testParseSimpleRandom() {
        FieldExpression expression = parser.parse("~");
        assertTrue(expression instanceof RandomExpression);
        RandomExpression random = (RandomExpression) expression;
        assertNull(random.getFrom());
        assertNull(random.getTo());
        assertNull(random.getStep());
    }

    @Test
    void testParseRandomWithRange() {
        FieldExpression expression = parser.parse("10~20");
        assertTrue(expression instanceof RandomExpression);
        RandomExpression random = (RandomExpression) expression;
        assertEquals(10, random.getFrom());
        assertEquals(20, random.getTo());
        assertNull(random.getStep());
    }

    @Test
    void testParseRandomWithPartialRange() {
        FieldExpression expression = parser.parse("~20");
        assertTrue(expression instanceof RandomExpression);
        RandomExpression random = (RandomExpression) expression;
        assertNull(random.getFrom());
        assertEquals(20, random.getTo());
        assertNull(random.getStep());

        expression = parser.parse("10~");
        assertTrue(expression instanceof RandomExpression);
        random = (RandomExpression) expression;
        assertEquals(10, random.getFrom());
        assertNull(random.getTo());
        assertNull(random.getStep());
    }

    @Test
    void testParseRandomWithStep() {
        FieldExpression expression = parser.parse("~/30");
        assertTrue(expression instanceof RandomExpression);
        RandomExpression random = (RandomExpression) expression;
        assertNull(random.getFrom());
        assertNull(random.getTo());
        assertEquals(30, random.getStep());

        expression = parser.parse("10~20/30");
        assertTrue(expression instanceof RandomExpression);
        random = (RandomExpression) expression;
        assertEquals(10, random.getFrom());
        assertEquals(20, random.getTo());
        assertEquals(30, random.getStep());
    }

    @Test
    void testInvalidRandomExpressions() {
        assertThrows(IllegalArgumentException.class, () -> parser.parse("~/"));
        assertThrows(IllegalArgumentException.class, () -> parser.parse("~//30"));
        assertThrows(IllegalArgumentException.class, () -> parser.parse("10~20/"));
        assertThrows(IllegalArgumentException.class, () -> parser.parse("a~20"));
        assertThrows(IllegalArgumentException.class, () -> parser.parse("10~b"));
        assertThrows(IllegalArgumentException.class, () -> parser.parse("10~20/c"));
    }
}
