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
package com.amazonaws.services.qapps.model;

import javax.annotation.Generated;

/**
 * <p>
 * The requested operation could not be completed because too many requests were sent at once. Wait a bit and try again
 * later.
 * </p>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ThrottlingException extends com.amazonaws.services.qapps.model.AWSQAppsException {
    private static final long serialVersionUID = 1L;

    /**
     * <p>
     * The code for the service where the quota was exceeded
     * </p>
     */
    private String serviceCode;
    /**
     * <p>
     * The code of the quota that was exceeded
     * </p>
     */
    private String quotaCode;
    /**
     * <p>
     * The number of seconds to wait before retrying the operation
     * </p>
     */
    private Integer retryAfterSeconds;

    /**
     * Constructs a new ThrottlingException with the specified error message.
     *
     * @param message
     *        Describes the error encountered.
     */
    public ThrottlingException(String message) {
        super(message);
    }

    /**
     * <p>
     * The code for the service where the quota was exceeded
     * </p>
     * 
     * @param serviceCode
     *        The code for the service where the quota was exceeded
     */

    @com.fasterxml.jackson.annotation.JsonProperty("serviceCode")
    public void setServiceCode(String serviceCode) {
        this.serviceCode = serviceCode;
    }

    /**
     * <p>
     * The code for the service where the quota was exceeded
     * </p>
     * 
     * @return The code for the service where the quota was exceeded
     */

    @com.fasterxml.jackson.annotation.JsonProperty("serviceCode")
    public String getServiceCode() {
        return this.serviceCode;
    }

    /**
     * <p>
     * The code for the service where the quota was exceeded
     * </p>
     * 
     * @param serviceCode
     *        The code for the service where the quota was exceeded
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ThrottlingException withServiceCode(String serviceCode) {
        setServiceCode(serviceCode);
        return this;
    }

    /**
     * <p>
     * The code of the quota that was exceeded
     * </p>
     * 
     * @param quotaCode
     *        The code of the quota that was exceeded
     */

    @com.fasterxml.jackson.annotation.JsonProperty("quotaCode")
    public void setQuotaCode(String quotaCode) {
        this.quotaCode = quotaCode;
    }

    /**
     * <p>
     * The code of the quota that was exceeded
     * </p>
     * 
     * @return The code of the quota that was exceeded
     */

    @com.fasterxml.jackson.annotation.JsonProperty("quotaCode")
    public String getQuotaCode() {
        return this.quotaCode;
    }

    /**
     * <p>
     * The code of the quota that was exceeded
     * </p>
     * 
     * @param quotaCode
     *        The code of the quota that was exceeded
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ThrottlingException withQuotaCode(String quotaCode) {
        setQuotaCode(quotaCode);
        return this;
    }

    /**
     * <p>
     * The number of seconds to wait before retrying the operation
     * </p>
     * 
     * @param retryAfterSeconds
     *        The number of seconds to wait before retrying the operation
     */

    @com.fasterxml.jackson.annotation.JsonProperty("Retry-After")
    public void setRetryAfterSeconds(Integer retryAfterSeconds) {
        this.retryAfterSeconds = retryAfterSeconds;
    }

    /**
     * <p>
     * The number of seconds to wait before retrying the operation
     * </p>
     * 
     * @return The number of seconds to wait before retrying the operation
     */

    @com.fasterxml.jackson.annotation.JsonProperty("Retry-After")
    public Integer getRetryAfterSeconds() {
        return this.retryAfterSeconds;
    }

    /**
     * <p>
     * The number of seconds to wait before retrying the operation
     * </p>
     * 
     * @param retryAfterSeconds
     *        The number of seconds to wait before retrying the operation
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ThrottlingException withRetryAfterSeconds(Integer retryAfterSeconds) {
        setRetryAfterSeconds(retryAfterSeconds);
        return this;
    }

}
