package com.cronutils.model;

import com.cronutils.model.definition.CronDefinition;
import com.cronutils.model.definition.CronDefinitionBuilder;
import com.cronutils.parser.CronParser;
import com.cronutils.model.CronType;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Disabled; // Will use if a test needs specific time mocking not available

import java.time.ZonedDateTime;
import java.time.ZoneId; // For ZonedDateTime construction

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

public class SingleCronTest {

    private CronParser cronParser;

    @BeforeEach
    public void setUp() {
        // Using QUARTZ definition for 7 fields (includes year)
        CronDefinition cronDefinition = CronDefinitionBuilder.instanceDefinitionFor(CronType.QUARTZ);
        cronParser = new CronParser(cronDefinition);
    }

    @Test
    public void testOverlapFromIssueDescription() {
        // cron1 = "0 0 10 1/1 ? *" (every day at 10am) - This is not a QUARTZ expression (6 fields)
        // cron2 = "0 0 10 ? * MON *" (every Monday at 10am) - QUARTZ
        // Let's make cron1 QUARTZ compatible: "0 0 10 1/1 * ? *"
        Cron cron1 = cronParser.parse("0 0 10 1/1 * ? *"); // Every day at 10 AM
        Cron cron2 = cronParser.parse("0 0 10 ? * MON *"); // Every Monday at 10 AM
        assertTrue(cron1.overlap(cron2), "Cron1 (every day at 10am) should overlap with Cron2 (every Monday at 10am)");
        assertTrue(cron2.overlap(cron1), "Overlap should be symmetric");
    }

    @Test
    public void testNonOverlappingExpressions() {
        Cron cron1 = cronParser.parse("0 0 10 ? * MON *"); // Every Monday at 10 AM
        Cron cron2 = cronParser.parse("0 0 12 ? * TUE *"); // Every Tuesday at 12 PM
        assertFalse(cron1.overlap(cron2), "Cron1 (Monday 10am) should not overlap with Cron2 (Tuesday 12pm)");
        assertFalse(cron2.overlap(cron1), "Overlap should be symmetric");
    }

    @Test
    public void testAlwaysOverlappingExpressions() {
        Cron cron1 = cronParser.parse("* * * * * ? *");    // Every second
        Cron cron2 = cronParser.parse("0 * * * * ? *");    // Every minute at second 0
        assertTrue(cron1.overlap(cron2), "Cron1 (every second) should overlap with Cron2 (every minute at second 0)");
        assertTrue(cron2.overlap(cron1), "Overlap should be symmetric");
    }

    @Test
    public void testOverlapOnSpecificDate() {
        // Ensure test year has Dec 25th as a Friday. 2026 is such a year.
        // cron1: Dec 25th, 2026 at 12 PM
        Cron cron1 = cronParser.parse("0 0 12 25 12 ? 2026");
        // cron2: Every Friday in December 2026 at 12 PM
        Cron cron2 = cronParser.parse("0 0 12 ? 12 FRI 2026");
        assertTrue(cron1.overlap(cron2), "Cron1 (Dec 25th 2026 12pm) should overlap with Cron2 (Fridays in Dec 2026 at 12pm) as Dec 25, 2026 is a Friday.");
        assertTrue(cron2.overlap(cron1), "Overlap should be symmetric");

        // Test with a year where Dec 25 is NOT a Friday. 2025 is such a year (Thursday).
        Cron cron3 = cronParser.parse("0 0 12 25 12 ? 2025"); // Dec 25th, 2025 at 12 PM
        Cron cron4 = cronParser.parse("0 0 12 ? 12 FRI 2025"); // Every Friday in December 2025 at 12 PM
        assertFalse(cron3.overlap(cron4), "Cron3 (Dec 25th 2025 12pm) should NOT overlap with Cron4 (Fridays in Dec 2025 at 12pm) as Dec 25, 2025 is a Thursday.");
        assertFalse(cron4.overlap(cron3), "Overlap should be symmetric");
    }
    
    @Test
    public void testSlightlyDifferentExpressionsThatShouldOverlap() {
        // Every 5 minutes vs Every 10 minutes
        Cron cron1 = cronParser.parse("0 0/5 * * * ? *");
        Cron cron2 = cronParser.parse("0 0/10 * * * ? *");
        assertTrue(cron1.overlap(cron2), "Every 5 minutes should overlap with every 10 minutes.");
        assertTrue(cron2.overlap(cron1), "Overlap should be symmetric");
    }

    @Test
    public void testNonOverlappingSameDayDifferentHours() {
        Cron cron1 = cronParser.parse("0 0 10 ? * MON *"); // Monday 10:00 AM
        Cron cron2 = cronParser.parse("0 0 11 ? * MON *"); // Monday 11:00 AM
        assertFalse(cron1.overlap(cron2), "Monday 10am should not overlap with Monday 11am.");
        assertFalse(cron2.overlap(cron1), "Overlap should be symmetric");
    }
    
    @Test
    public void testOverlappingHourlyAndDaily() {
        // Every hour vs Every day at a specific hour
        Cron cron1 = cronParser.parse("0 0 * * * ? *"); // Every hour at minute 0
        Cron cron2 = cronParser.parse("0 0 12 * * ? *"); // Every day at 12:00 PM
        assertTrue(cron1.overlap(cron2), "Every hour should overlap with every day at 12 PM.");
        assertTrue(cron2.overlap(cron1), "Overlap should be symmetric");
    }

    // It might be good to have a test case where the year is not specified in one
    // and specified in another, if the cron definition allows optional years.
    // For QUARTZ, year is a field. If not specified, it might default or be an error.
    // The CronParser with QUARTZ definition expects 7 fields usually.
    // Let's try a case where one has a wildcard year and another a specific year.
    @Test
    public void testOverlapWithWildcardYearAndSpecificYear() {
        // cron1: Every Jan 1st 10 AM, any year
        Cron cron1 = cronParser.parse("0 0 10 1 1 ? *");
        // cron2: Jan 1st, 2027 at 10 AM
        Cron cron2 = cronParser.parse("0 0 10 1 1 ? 2027");
        assertTrue(cron1.overlap(cron2), "Jan 1st any year should overlap with Jan 1st 2027.");
        assertTrue(cron2.overlap(cron1), "Overlap should be symmetric");

        // cron3: Every Jan 1st 10 AM, any year
        Cron cron3 = cronParser.parse("0 0 10 1 1 ? *");
        // cron4: Feb 1st, 2027 at 10 AM
        Cron cron4 = cronParser.parse("0 0 10 1 2 ? 2027");
        assertFalse(cron3.overlap(cron4), "Jan 1st any year should NOT overlap with Feb 1st 2027.");
        assertFalse(cron4.overlap(cron3), "Overlap should be symmetric");
    }

    // Test for expressions that will never overlap because of year constraints
    @Test
    public void testNonOverlapDueToYear() {
        Cron cron1 = cronParser.parse("0 0 12 1 1 ? 2025"); // Jan 1st, 2025 12:00 PM
        Cron cron2 = cronParser.parse("0 0 12 1 1 ? 2026"); // Jan 1st, 2026 12:00 PM
        assertFalse(cron1.overlap(cron2), "Expressions for different years should not overlap.");
        assertFalse(cron2.overlap(cron1), "Overlap should be symmetric");
    }
}
