package com.cronutils.model.field.expression;

import com.cronutils.model.field.expression.visitor.FieldExpressionVisitor;
import com.cronutils.model.field.value.IntegerFieldValue;
import com.cronutils.utils.RandomUtils;

/**
 * Represents a random value expression in a cron field, using the '~' character.
 * This is specific to OpenBSD cron expressions.
 */
public class RandomExpression extends FieldExpression {
    private static final long serialVersionUID = 8876876234273662919L;
    
    private final Integer from;
    private final Integer to;
    private final Integer step;
    private final RandomUtils randomUtils;

    public RandomExpression(Integer from, Integer to, Integer step, RandomUtils randomUtils) {
        this.from = from;
        this.to = to;
        this.step = step;
        this.randomUtils = randomUtils;
    }

    public RandomExpression(RandomUtils randomUtils) {
        this(null, null, null, randomUtils);
    }

    /**
     * Get random value within the range considering step if specified
     * @param min minimum value allowed for the field
     * @param max maximum value allowed for the field
     * @return random value as IntegerFieldValue
     */
    public IntegerFieldValue getRandomValue(int min, int max) {
        int actualFrom = from != null ? from : min;
        int actualTo = to != null ? to : max;
        
        if (step != null) {
            // For step values, we need to generate a random offset less than the step size
            int randomOffset = randomUtils.nextInt(step);
            // Then we need to ensure the value falls within our range
            int value = actualFrom + randomOffset;
            while (value > actualTo) {
                value -= step;
            }
            return new IntegerFieldValue(value);
        } else {
            return new IntegerFieldValue(randomUtils.nextInt(actualFrom, actualTo + 1));
        }
    }

    public Integer getFrom() {
        return from;
    }

    public Integer getTo() {
        return to;
    }

    public Integer getStep() {
        return step;
    }

    @Override
    public FieldExpression accept(FieldExpressionVisitor visitor) {
        return visitor.visit(this);
    }

    @Override
    public String asString() {
        StringBuilder builder = new StringBuilder();
        if (from != null || to != null) {
            if (from != null) {
                builder.append(from);
            }
            builder.append("~");
            if (to != null) {
                builder.append(to);
            }
        } else {
            builder.append("~");
        }
        if (step != null) {
            builder.append("/").append(step);
        }
        return builder.toString();
    }

    @Override
    public String toString() {
        return asString();
    }
}
