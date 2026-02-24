package com.cronutils.model.time;

import com.cronutils.model.CronType;
import com.cronutils.model.definition.CronDefinitionBuilder;
import com.cronutils.parser.CronParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

import static java.time.format.DateTimeFormatter.ISO_INSTANT;

public class LastExecutionWithDifferentMonthLengthsTest {

    @Test
    void shouldFindCorrectLastExecTimeWhenDaysOfMonthsAreDifferent() {
        final var parser = new CronParser(CronDefinitionBuilder.instanceDefinitionFor(CronType.QUARTZ));
        // last run is in a month with 31 days
        final var execTime = ExecutionTime.forCron(parser.parse("0 30 23 * * ? 2022"));

        final var lastExec = execTime.lastExecution(
            Instant.parse("2023-11-24T12:00:00Z").atZone(ZoneId.of("UTC")));
        
        assertTrue(lastExec.isPresent(), "Should find a last execution");
        assertEquals(
            "2022-12-31T23:30:00Z",
            ISO_INSTANT.format(lastExec.get().toInstant()),
            "Last execution should be the last possible time in 2022"
        );

        final var nextExec = execTime.nextExecution(lastExec.get());
        assertTrue(nextExec.isEmpty(), "Should not find next execution as cron ended in 2022");
    }

    @Test
    void shouldHandleLastDayOfMonthTransitions() {
        final var parser = new CronParser(CronDefinitionBuilder.instanceDefinitionFor(CronType.QUARTZ));
        // Run at 23:30 on the last day of every month in 2022
        final var execTime = ExecutionTime.forCron(parser.parse("0 30 23 L * ? 2022"));

        // Check from a month with 30 days (November)
        final var novemberCheck = execTime.lastExecution(
            Instant.parse("2023-11-24T12:00:00Z").atZone(ZoneId.of("UTC")));
        
        assertTrue(novemberCheck.isPresent(), "Should find a last execution from November");
        assertEquals(
            "2022-12-31T23:30:00Z",
            ISO_INSTANT.format(novemberCheck.get().toInstant()),
            "Last execution should be December 31, 2022"
        );

        // Check from a month with 31 days (October)
        final var octoberCheck = execTime.lastExecution(
            Instant.parse("2023-10-24T12:00:00Z").atZone(ZoneId.of("UTC")));
        
        assertTrue(octoberCheck.isPresent(), "Should find a last execution from October");
        assertEquals(
            "2022-12-31T23:30:00Z",
            ISO_INSTANT.format(octoberCheck.get().toInstant()),
            "Last execution should be December 31, 2022"
        );
    }

    @Test
    void shouldHandleSpecificDayAcrossMonths() {
        final var parser = new CronParser(CronDefinitionBuilder.instanceDefinitionFor(CronType.QUARTZ));
        // Run at 23:30 on the 31st of every month in 2022
        final var execTime = ExecutionTime.forCron(parser.parse("0 30 23 31 * ? 2022"));

        // Test cases for different months
        Stream.of(
            Arguments.of("2023-11-24T12:00:00Z", "2022-12-31T23:30:00Z"),
            Arguments.of("2023-10-24T12:00:00Z", "2022-12-31T23:30:00Z"),
            Arguments.of("2023-09-24T12:00:00Z", "2022-12-31T23:30:00Z")
        ).forEach(args -> {
            final var checkTime = Instant.parse((String) args.get()[0]).atZone(ZoneId.of("UTC"));
            final var expectedLastExec = (String) args.get()[1];
            
            final var lastExec = execTime.lastExecution(checkTime);
            assertTrue(lastExec.isPresent(), "Should find last execution when checking from " + checkTime);
            assertEquals(
                expectedLastExec,
                ISO_INSTANT.format(lastExec.get().toInstant()),
                "Last execution should be correct when checking from " + checkTime
            );
            
            final var nextExec = execTime.nextExecution(lastExec.get());
            assertTrue(nextExec.isEmpty(), "Should not find next execution after " + lastExec.get());
        });
    }
}
