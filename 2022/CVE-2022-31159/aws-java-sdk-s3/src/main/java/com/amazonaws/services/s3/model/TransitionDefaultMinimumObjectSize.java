/*
 * Copyright 2010-2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
package com.amazonaws.services.s3.model;

/**
 * Indicates whether the lifecycle configuration allows objects smaller than 128 KB to be transitioned.
 */
public enum TransitionDefaultMinimumObjectSize {
    VARIES_BY_STORAGE_CLASS("varies_by_storage_class"),
    ALL_STORAGE_CLASSES_128K("all_storage_classes_128K");

    private String value;

    TransitionDefaultMinimumObjectSize(String value) {
        this.value = value;
    }

    public String toString() {
        return this.value;
    }

    public static TransitionDefaultMinimumObjectSize parseTransitionDefaultMinimumObjectSize(String str) {
        for (TransitionDefaultMinimumObjectSize transitionDefaultMinimumObjectSize : TransitionDefaultMinimumObjectSize.values()) {
            if (transitionDefaultMinimumObjectSize.value.equals(str)) {
                return transitionDefaultMinimumObjectSize;
            }
        }
        return null;
    }
}
