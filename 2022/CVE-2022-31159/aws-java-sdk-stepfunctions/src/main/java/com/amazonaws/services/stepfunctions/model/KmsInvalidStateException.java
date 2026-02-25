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
 * The KMS key is not in valid state, for example: Disabled or Deleted.
 * </p>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class KmsInvalidStateException extends com.amazonaws.services.stepfunctions.model.AWSStepFunctionsException {
    private static final long serialVersionUID = 1L;

    /**
     * <p>
     * Current status of the KMS; key. For example: <code>DISABLED</code>, <code>PENDING_DELETION</code>,
     * <code>PENDING_IMPORT</code>, <code>UNAVAILABLE</code>, <code>CREATING</code>.
     * </p>
     */
    private String kmsKeyState;

    /**
     * Constructs a new KmsInvalidStateException with the specified error message.
     *
     * @param message
     *        Describes the error encountered.
     */
    public KmsInvalidStateException(String message) {
        super(message);
    }

    /**
     * <p>
     * Current status of the KMS; key. For example: <code>DISABLED</code>, <code>PENDING_DELETION</code>,
     * <code>PENDING_IMPORT</code>, <code>UNAVAILABLE</code>, <code>CREATING</code>.
     * </p>
     * 
     * @param kmsKeyState
     *        Current status of the KMS; key. For example: <code>DISABLED</code>, <code>PENDING_DELETION</code>,
     *        <code>PENDING_IMPORT</code>, <code>UNAVAILABLE</code>, <code>CREATING</code>.
     * @see KmsKeyState
     */

    @com.fasterxml.jackson.annotation.JsonProperty("kmsKeyState")
    public void setKmsKeyState(String kmsKeyState) {
        this.kmsKeyState = kmsKeyState;
    }

    /**
     * <p>
     * Current status of the KMS; key. For example: <code>DISABLED</code>, <code>PENDING_DELETION</code>,
     * <code>PENDING_IMPORT</code>, <code>UNAVAILABLE</code>, <code>CREATING</code>.
     * </p>
     * 
     * @return Current status of the KMS; key. For example: <code>DISABLED</code>, <code>PENDING_DELETION</code>,
     *         <code>PENDING_IMPORT</code>, <code>UNAVAILABLE</code>, <code>CREATING</code>.
     * @see KmsKeyState
     */

    @com.fasterxml.jackson.annotation.JsonProperty("kmsKeyState")
    public String getKmsKeyState() {
        return this.kmsKeyState;
    }

    /**
     * <p>
     * Current status of the KMS; key. For example: <code>DISABLED</code>, <code>PENDING_DELETION</code>,
     * <code>PENDING_IMPORT</code>, <code>UNAVAILABLE</code>, <code>CREATING</code>.
     * </p>
     * 
     * @param kmsKeyState
     *        Current status of the KMS; key. For example: <code>DISABLED</code>, <code>PENDING_DELETION</code>,
     *        <code>PENDING_IMPORT</code>, <code>UNAVAILABLE</code>, <code>CREATING</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see KmsKeyState
     */

    public KmsInvalidStateException withKmsKeyState(String kmsKeyState) {
        setKmsKeyState(kmsKeyState);
        return this;
    }

    /**
     * <p>
     * Current status of the KMS; key. For example: <code>DISABLED</code>, <code>PENDING_DELETION</code>,
     * <code>PENDING_IMPORT</code>, <code>UNAVAILABLE</code>, <code>CREATING</code>.
     * </p>
     * 
     * @param kmsKeyState
     *        Current status of the KMS; key. For example: <code>DISABLED</code>, <code>PENDING_DELETION</code>,
     *        <code>PENDING_IMPORT</code>, <code>UNAVAILABLE</code>, <code>CREATING</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see KmsKeyState
     */

    public KmsInvalidStateException withKmsKeyState(KmsKeyState kmsKeyState) {
        this.kmsKeyState = kmsKeyState.toString();
        return this;
    }

}
