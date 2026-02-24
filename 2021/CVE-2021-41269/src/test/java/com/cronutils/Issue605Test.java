package com.cronutils;

import com.cronutils.mapper.CronMapper;
import com.cronutils.model.Cron;
import com.cronutils.model.CronType;
import com.cronutils.model.definition.CronDefinition;
import com.cronutils.model.definition.CronDefinitionBuilder;
import com.cronutils.parser.CronParser;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static com.cronutils.model.CronType.QUARTZ;
import static com.cronutils.model.CronType.SPRING;
import static org.junit.jupiter.api.Assertions.assertEquals;

class Issue605Test {

    static Stream<Arguments> cronExpressions() {
        return Stream.of(
                Arguments.of(QUARTZ, CronMapper.fromQuartzToCron4j(), "0 0 * * 4#1"),
                Arguments.of(QUARTZ, CronMapper.fromQuartzToSpring(), "0 0 0 ? * 4#1"),
                Arguments.of(QUARTZ, CronMapper.fromQuartzToUnix(), "0 0 * * 4#1"),
                Arguments.of(SPRING, CronMapper.fromSpringToQuartz(), "0 0 0 ? * 6#1 *")
        );
    }

    @ParameterizedTest
    @MethodSource("cronExpressions")
    void testDayOfWeekMappingSpring(CronType cronType, CronMapper mapper, String expectedExpression) {
        Cron sourceCron = getCron(cronType, "0 0 0 ? * 5#1");
        Cron destinationCron = mapper.map(sourceCron);
        assertEquals(expectedExpression, destinationCron.asString());
    }

    private Cron getCron(CronType cronType, @SuppressWarnings("SameParameterValue") final String quartzExpression) {
        final CronDefinition cronDefinition = CronDefinitionBuilder.instanceDefinitionFor(cronType);
        final CronParser parser = new CronParser(cronDefinition);
        return parser.parse(quartzExpression);
    }

}
