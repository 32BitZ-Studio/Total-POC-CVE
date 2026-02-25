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
package com.amazonaws.services.pcaconnectorscep.model;

import javax.annotation.Generated;

/**
 * <p>
 * The request would cause a service quota to be exceeded.
 * </p>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ServiceQuotaExceededException extends com.amazonaws.services.pcaconnectorscep.model.AWSPcaConnectorScepException {
    private static final long serialVersionUID = 1L;

    /**
     * <p>
     * The resource type, which can be either <code>Connector</code> or <code>Challenge</code>.
     * </p>
     */
    private String resourceType;
    /**
     * <p>
     * Identifies the originating service.
     * </p>
     */
    private String serviceCode;
    /**
     * <p>
     * The quota identifier.
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
     * The resource type, which can be either <code>Connector</code> or <code>Challenge</code>.
     * </p>
     * 
     * @param resourceType
     *        The resource type, which can be either <code>Connector</code> or <code>Challenge</code>.
     */

    @com.fasterxml.jackson.annotation.JsonProperty("ResourceType")
    public void setResourceType(String resourceType) {
        this.resourceType = resourceType;
    }

    /**
     * <p>
     * The resource type, which can be either <code>Connector</code> or <code>Challenge</code>.
     * </p>
     * 
     * @return The resource type, which can be either <code>Connector</code> or <code>Challenge</code>.
     */

    @com.fasterxml.jackson.annotation.JsonProperty("ResourceType")
    public String getResourceType() {
        return this.resourceType;
    }

    /**
     * <p>
     * The resource type, which can be either <code>Connector</code> or <code>Challenge</code>.
     * </p>
     * 
     * @param resourceType
     *        The resource type, which can be either <code>Connector</code> or <code>Challenge</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ServiceQuotaExceededException withResourceType(String resourceType) {
        setResourceType(resourceType);
        return this;
    }

    /**
     * <p>
     * Identifies the originating service.
     * </p>
     * 
     * @param serviceCode
     *        Identifies the originating service.
     */

    @com.fasterxml.jackson.annotation.JsonProperty("ServiceCode")
    public void setServiceCode(String serviceCode) {
        this.serviceCode = serviceCode;
    }

    /**
     * <p>
     * Identifies the originating service.
     * </p>
     * 
     * @return Identifies the originating service.
     */

    @com.fasterxml.jackson.annotation.JsonProperty("ServiceCode")
    public String getServiceCode() {
        return this.serviceCode;
    }

    /**
     * <p>
     * Identifies the originating service.
     * </p>
     * 
     * @param serviceCode
     *        Identifies the originating service.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ServiceQuotaExceededException withServiceCode(String serviceCode) {
        setServiceCode(serviceCode);
        return this;
    }

    /**
     * <p>
     * The quota identifier.
     * </p>
     * 
     * @param quotaCode
     *        The quota identifier.
     */

    @com.fasterxml.jackson.annotation.JsonProperty("QuotaCode")
    public void setQuotaCode(String quotaCode) {
        this.quotaCode = quotaCode;
    }

    /**
     * <p>
     * The quota identifier.
     * </p>
     * 
     * @return The quota identifier.
     */

    @com.fasterxml.jackson.annotation.JsonProperty("QuotaCode")
    public String getQuotaCode() {
        return this.quotaCode;
    }

    /**
     * <p>
     * The quota identifier.
     * </p>
     * 
     * @param quotaCode
     *        The quota identifier.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ServiceQuotaExceededException withQuotaCode(String quotaCode) {
        setQuotaCode(quotaCode);
        return this;
    }

}
