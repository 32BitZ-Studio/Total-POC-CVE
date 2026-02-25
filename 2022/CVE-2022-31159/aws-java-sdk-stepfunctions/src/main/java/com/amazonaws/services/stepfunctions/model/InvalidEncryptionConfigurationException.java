/*
 * Copyright 2020-2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with
 * the License. A copy of the License is located at
 * 
 * http://aws.amazon.com/apache2.0
 * 
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
 * and limitations under the License.
 */
package com.amazonaws.services.stepfunctions.model;

import javax.annotation.Generated;

/**
 * <p>
 * Received when <code>encryptionConfiguration</code> is specified but various conditions exist which make the
 * configuration invalid. For example, if <code>type</code> is set to <code>CUSTOMER_MANAGED_KMS_KEY</code>, but
 * <code>kmsKeyId</code> is null, or <code>kmsDataKeyReusePeriodSeconds</code> is not between 60 and 900, or the KMS key
 * is not symmetric or inactive.
 * </p>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class InvalidEncryptionConfigurationException extends com.amazonaws.services.stepfunctions.model.AWSStepFunctionsException {
    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new InvalidEncryptionConfigurationException with the specified error message.
     *
     * @param message
     *        Describes the error encountered.
     */
    public InvalidEncryptionConfigurationException(String message) {
        super(message);
    }

}
