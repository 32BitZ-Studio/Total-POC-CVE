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
 * The requested operation could not be completed because it would exceed the service's quota or limit.
 * </p>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ServiceQuotaExceededException extends com.amazonaws.services.qapps.model.AWSQAppsException {
    private static final long serialVersionUID = 1L;

    /**
     * <p>
     * The unique identifier of the resource
     * </p>
     */
    private String resourceId;
    /**
     * <p>
     * The type of the resource
     * </p>
     */
    private String resourceType;
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
     * Constructs a new ServiceQuotaExceededException with the specified error message.
     *
     * @param message
     *        Describes the error encountered.
     */
    public ServiceQuotaExceededException(String message) {
        super(message);
    }

    /**
     * <p>
     * The unique identifier of the resource
     * </p>
     * 
     * @param resourceId
     *        The unique identifier of the resource
     */

    @com.fasterxml.jackson.annotation.JsonProperty("resourceId")
    public void setResourceId(String resourceId) {
        this.resourceId = resourceId;
    }

    /**
     * <p>
     * The unique identifier of the resource
     * </p>
     * 
     * @return The unique identifier of the resource
     */

    @com.fasterxml.jackson.annotation.JsonProperty("resourceId")
    public String getResourceId() {
        return this.resourceId;
    }

    /**
     * <p>
     * The unique identifier of the resource
     * </p>
     * 
     * @param resourceId
     *        The unique identifier of the resource
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ServiceQuotaExceededException withResourceId(String resourceId) {
        setResourceId(resourceId);
        return this;
    }

    /**
     * <p>
     * The type of the resource
     * </p>
     * 
     * @param resourceType
     *        The type of the resource
     */

    @com.fasterxml.jackson.annotation.JsonProperty("resourceType")
    public void setResourceType(String resourceType) {
        this.resourceType = resourceType;
    }

    /**
     * <p>
     * The type of the resource
     * </p>
     * 
     * @return The type of the resource
     */

    @com.fasterxml.jackson.annotation.JsonProperty("resourceType")
    public String getResourceType() {
        return this.resourceType;
    }

    /**
     * <p>
     * The type of the resource
     * </p>
     * 
     * @param resourceType
     *        The type of the resource
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ServiceQuotaExceededException withResourceType(String resourceType) {
        setResourceType(resourceType);
        return this;
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

    public ServiceQuotaExceededException withServiceCode(String serviceCode) {
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

    public ServiceQuotaExceededException withQuotaCode(String quotaCode) {
        setQuotaCode(quotaCode);
        return this;
    }

}
