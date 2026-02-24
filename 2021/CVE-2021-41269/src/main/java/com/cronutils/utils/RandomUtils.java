package com.cronutils.utils;

import java.util.Random;

/**
 * Utility class for random number generation in cron expressions.
 * This is used primarily for OpenBSD-style random intervals using the '~' character.
 */
public class RandomUtils {
    private final Random random;

    public RandomUtils() {
        this(new Random());
    }

    public RandomUtils(Random random) {
        this.random = random;
    }

    /**
     * Generate a random integer between 0 (inclusive) and bound (exclusive)
     * @param bound the upper bound (exclusive)
     * @return random integer
     */
    public int nextInt(int bound) {
        return random.nextInt(bound);
    }

    /**
     * Generate a random integer between min (inclusive) and max (exclusive)
     * @param min minimum value (inclusive)
     * @param max maximum value (exclusive)
     * @return random integer
     */
    public int nextInt(int min, int max) {
        return random.nextInt(min, max);
    }
}
