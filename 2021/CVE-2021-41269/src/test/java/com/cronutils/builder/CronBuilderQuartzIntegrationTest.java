package com.cronutils.builder;

import org.junit.jupiter.api.Test;

import com.cronutils.model.Cron;
import com.cronutils.model.CronType;
import com.cronutils.model.definition.CronDefinition;
import com.cronutils.model.definition.CronDefinitionBuilder;

import static com.cronutils.model.field.expression.FieldExpressionFactory.*;
import static org.junit.jupiter.api.Assertions.*;

public class CronBuilderQuartzIntegrationTest {

    @Test
    void shouldAllowBothDoWAndDoMWhenAlways() {
        CronDefinition quartzDefinition = CronDefinitionBuilder.instanceDefinitionFor(CronType.QUARTZ);
        CronBuilder cronBuilder = CronBuilder.cron(quartzDefinition)
                .withSecond(on(0))
                .withMinute(on(1))
                .withHour(on(13))
                .withDoM(always())
                .withMonth(always())
                .withDoW(questionMark())
                .withYear(always());
        Cron cron = cronBuilder.instance();

        assertDoesNotThrow(() -> {
            // This should not throw a validation error
            cron.validate();
        });

        assertEquals("0 1 13 * * ? *", cron.asString());
    }

    @Test
    void shouldAllowDoMWithQuestionMarkDoW() {
        CronDefinition quartzDefinition = CronDefinitionBuilder.instanceDefinitionFor(CronType.QUARTZ);
        CronBuilder cronBuilder = CronBuilder.cron(quartzDefinition)
                .withSecond(on(0))
                .withMinute(on(1))
                .withHour(on(13))
                .withDoM(on(1))
                .withMonth(always())
                .withDoW(questionMark())
                .withYear(always());
        Cron cron = cronBuilder.instance();

        assertDoesNotThrow(() -> {
            // This should not throw a validation error
            cron.validate();
        });

        assertEquals("0 1 13 1 * ? *", cron.asString());
    }

    @Test
    void shouldAllowDoWWithQuestionMarkDoM() {
        CronDefinition quartzDefinition = CronDefinitionBuilder.instanceDefinitionFor(CronType.QUARTZ);
        CronBuilder cronBuilder = CronBuilder.cron(quartzDefinition)
                .withSecond(on(0))
                .withMinute(on(1))
                .withHour(on(13))
                .withDoM(questionMark())
                .withMonth(always())
                .withDoW(on(1))
                .withYear(always());
        Cron cron = cronBuilder.instance();

        assertDoesNotThrow(() -> {
            // This should not throw a validation error
            cron.validate();
        });

        assertEquals("0 1 13 ? * 1 *", cron.asString());
    }
}
