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
package com.amazonaws.services.workspaces.model;

import java.io.Serializable;
import javax.annotation.Generated;

import com.amazonaws.AmazonWebServiceRequest;

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/workspaces-2015-04-08/ModifyStreamingProperties"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ModifyStreamingPropertiesRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The identifier of the resource.
     * </p>
     */
    private String resourceId;
    /**
     * <p>
     * The streaming properties to configure.
     * </p>
     */
    private StreamingProperties streamingProperties;

    /**
     * <p>
     * The identifier of the resource.
     * </p>
     * 
     * @param resourceId
     *        The identifier of the resource.
     */

    public void setResourceId(String resourceId) {
        this.resourceId = resourceId;
    }

    /**
     * <p>
     * The identifier of the resource.
     * </p>
     * 
     * @return The identifier of the resource.
     */

    public String getResourceId() {
        return this.resourceId;
    }

    /**
     * <p>
     * The identifier of the resource.
     * </p>
     * 
     * @param resourceId
     *        The identifier of the resource.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ModifyStreamingPropertiesRequest withResourceId(String resourceId) {
        setResourceId(resourceId);
        return this;
    }

    /**
     * <p>
     * The streaming properties to configure.
     * </p>
     * 
     * @param streamingProperties
     *        The streaming properties to configure.
     */

    public void setStreamingProperties(StreamingProperties streamingProperties) {
        this.streamingProperties = streamingProperties;
    }

    /**
     * <p>
     * The streaming properties to configure.
     * </p>
     * 
     * @return The streaming properties to configure.
     */

    public StreamingProperties getStreamingProperties() {
        return this.streamingProperties;
    }

    /**
     * <p>
     * The streaming properties to configure.
     * </p>
     * 
     * @param streamingProperties
     *        The streaming properties to configure.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ModifyStreamingPropertiesRequest withStreamingProperties(StreamingProperties streamingProperties) {
        setStreamingProperties(streamingProperties);
        return this;
    }

    /**
     * Returns a string representation of this object. This is useful for testing and debugging. Sensitive data will be
     * redacted from this string using a placeholder value.
     *
     * @return A string representation of this object.
     *
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        if (getResourceId() != null)
            sb.append("ResourceId: ").append(getResourceId()).append(",");
        if (getStreamingProperties() != null)
            sb.append("StreamingProperties: ").append(getStreamingProperties());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ModifyStreamingPropertiesRequest == false)
            return false;
        ModifyStreamingPropertiesRequest other = (ModifyStreamingPropertiesRequest) obj;
        if (other.getResourceId() == null ^ this.getResourceId() == null)
            return false;
        if (other.getResourceId() != null && other.getResourceId().equals(this.getResourceId()) == false)
            return false;
        if (other.getStreamingProperties() == null ^ this.getStreamingProperties() == null)
            return false;
        if (other.getStreamingProperties() != null && other.getStreamingProperties().equals(this.getStreamingProperties()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getResourceId() == null) ? 0 : getResourceId().hashCode());
        hashCode = prime * hashCode + ((getStreamingProperties() == null) ? 0 : getStreamingProperties().hashCode());
        return hashCode;
    }

    @Override
    public ModifyStreamingPropertiesRequest clone() {
        return (ModifyStreamingPropertiesRequest) super.clone();
    }

}
