package com.cronutils.model.field.expression;

import com.cronutils.model.field.value.IntegerFieldValue;
import com.cronutils.utils.RandomUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class RandomExpressionTest {
    @Mock
    private RandomUtils randomUtils;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testSimpleRandom() {
        when(randomUtils.nextInt(0, 60)).thenReturn(30);
        RandomExpression expression = new RandomExpression(randomUtils);
        IntegerFieldValue value = expression.getRandomValue(0, 59);
        assertEquals(30, value.getValue());
        verify(randomUtils).nextInt(0, 60);
    }

    @Test
    void testRandomWithRange() {
        when(randomUtils.nextInt(10, 21)).thenReturn(15);
        RandomExpression expression = new RandomExpression(10, 20, null, randomUtils);
        IntegerFieldValue value = expression.getRandomValue(0, 59);
        assertEquals(15, value.getValue());
        verify(randomUtils).nextInt(10, 21);
    }

    @Test
    void testRandomWithStep() {
        when(randomUtils.nextInt(30)).thenReturn(15);
        RandomExpression expression = new RandomExpression(null, null, 30, randomUtils);
        IntegerFieldValue value = expression.getRandomValue(0, 59);
        assertEquals(15, value.getValue());
        verify(randomUtils).nextInt(30);
    }

    @Test
    void testRandomWithRangeAndStep() {
        when(randomUtils.nextInt(30)).thenReturn(25);
        RandomExpression expression = new RandomExpression(10, 50, 30, randomUtils);
        IntegerFieldValue value = expression.getRandomValue(0, 59);
        assertEquals(35, value.getValue()); // 10 + 25
        verify(randomUtils).nextInt(30);
    }

    @Test
    void testToString() {
        assertEquals("~", new RandomExpression(randomUtils).toString());
        assertEquals("10~20", new RandomExpression(10, 20, null, randomUtils).toString());
        assertEquals("~20", new RandomExpression(null, 20, null, randomUtils).toString());
        assertEquals("10~", new RandomExpression(10, null, null, randomUtils).toString());
        assertEquals("~/30", new RandomExpression(null, null, 30, randomUtils).toString());
        assertEquals("10~20/30", new RandomExpression(10, 20, 30, randomUtils).toString());
    }
}
