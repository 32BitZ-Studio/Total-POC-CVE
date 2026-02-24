package com.cronutils.model.time;

import com.cronutils.model.Cron;
import com.cronutils.model.CronType;
import com.cronutils.model.definition.CronDefinition;
import com.cronutils.model.definition.CronDefinitionBuilder;
import com.cronutils.parser.CronParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CrossMinuteExecutionTest {

    @Test
    public void testCrossMinuteExecution() {
        CronDefinition definition = CronDefinitionBuilder.instanceDefinitionFor(CronType.QUARTZ);
        CronParser parser = new CronParser(definition);
        Cron cron = parser.parse("*/8 * * * * ?");
        ExecutionTime executionTime = ExecutionTime.forCron(cron);

        // Test case 1: When next execution should be in the same minute
        ZonedDateTime time1 = ZonedDateTime.of(2024, 9, 12, 10, 46, 40, 0, ZoneOffset.UTC);
        ZonedDateTime expected1 = ZonedDateTime.of(2024, 9, 12, 10, 46, 48, 0, ZoneOffset.UTC);
        assertEquals(expected1, executionTime.nextExecution(time1).get());

        // Test case 2: When next execution should be in the next minute
        ZonedDateTime time2 = ZonedDateTime.of(2024, 9, 12, 10, 46, 57, 0, ZoneOffset.UTC);
        ZonedDateTime expected2 = ZonedDateTime.of(2024, 9, 12, 10, 47, 0, 0, ZoneOffset.UTC);
        assertEquals(expected2, executionTime.nextExecution(time2).get());

        // Test case 3: When at exact execution time
        ZonedDateTime time3 = ZonedDateTime.of(2024, 9, 12, 10, 46, 48, 0, ZoneOffset.UTC);
        ZonedDateTime expected3 = ZonedDateTime.of(2024, 9, 12, 10, 46, 56, 0, ZoneOffset.UTC);
        assertEquals(expected3, executionTime.nextExecution(time3).get());
    }

    @Test
    public void testCrossMinuteExecutionWithDifferentIntervals() {
        CronDefinition definition = CronDefinitionBuilder.instanceDefinitionFor(CronType.QUARTZ);
        CronParser parser = new CronParser(definition);
        
        // Test with 15-second intervals
        Cron cron1 = parser.parse("0/15 * * * * ?");
        ExecutionTime executionTime1 = ExecutionTime.forCron(cron1);
        ZonedDateTime time1 = ZonedDateTime.of(2024, 9, 12, 10, 46, 55, 0, ZoneOffset.UTC);
        ZonedDateTime expected1 = ZonedDateTime.of(2024, 9, 12, 10, 47, 0, 0, ZoneOffset.UTC);
        assertEquals(expected1, executionTime1.nextExecution(time1).get());

        // Test with 30-second intervals
        Cron cron2 = parser.parse("0/30 * * * * ?");
        ExecutionTime executionTime2 = ExecutionTime.forCron(cron2);
        ZonedDateTime time2 = ZonedDateTime.of(2024, 9, 12, 10, 46, 35, 0, ZoneOffset.UTC);
        ZonedDateTime expected2 = ZonedDateTime.of(2024, 9, 12, 10, 47, 0, 0, ZoneOffset.UTC);
        assertEquals(expected2, executionTime2.nextExecution(time2).get());
    }
}
