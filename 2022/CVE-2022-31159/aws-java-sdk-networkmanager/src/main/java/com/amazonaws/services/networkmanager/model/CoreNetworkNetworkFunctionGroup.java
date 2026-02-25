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
package com.amazonaws.services.networkmanager.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * Describes a network function group.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/networkmanager-2019-07-05/CoreNetworkNetworkFunctionGroup"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class CoreNetworkNetworkFunctionGroup implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The name of the network function group.
     * </p>
     */
    private String name;
    /**
     * <p>
     * The core network edge locations.
     * </p>
     */
    private java.util.List<String> edgeLocations;
    /**
     * <p>
     * The segments associated with the network function group.
     * </p>
     */
    private ServiceInsertionSegments segments;

    /**
     * <p>
     * The name of the network function group.
     * </p>
     * 
     * @param name
     *        The name of the network function group.
     */

    public void setName(String name) {
        this.name = name;
    }

    /**
     * <p>
     * The name of the network function group.
     * </p>
     * 
     * @return The name of the network function group.
     */

    public String getName() {
        return this.name;
    }

    /**
     * <p>
     * The name of the network function group.
     * </p>
     * 
     * @param name
     *        The name of the network function group.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CoreNetworkNetworkFunctionGroup withName(String name) {
        setName(name);
        return this;
    }

    /**
     * <p>
     * The core network edge locations.
     * </p>
     * 
     * @return The core network edge locations.
     */

    public java.util.List<String> getEdgeLocations() {
        return edgeLocations;
    }

    /**
     * <p>
     * The core network edge locations.
     * </p>
     * 
     * @param edgeLocations
     *        The core network edge locations.
     */

    public void setEdgeLocations(java.util.Collection<String> edgeLocations) {
        if (edgeLocations == null) {
            this.edgeLocations = null;
            return;
        }

        this.edgeLocations = new java.util.ArrayList<String>(edgeLocations);
    }

    /**
     * <p>
     * The core network edge locations.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setEdgeLocations(java.util.Collection)} or {@link #withEdgeLocations(java.util.Collection)} if you want
     * to override the existing values.
     * </p>
     * 
     * @param edgeLocations
     *        The core network edge locations.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CoreNetworkNetworkFunctionGroup withEdgeLocations(String... edgeLocations) {
        if (this.edgeLocations == null) {
            setEdgeLocations(new java.util.ArrayList<String>(edgeLocations.length));
        }
        for (String ele : edgeLocations) {
            this.edgeLocations.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The core network edge locations.
     * </p>
     * 
     * @param edgeLocations
     *        The core network edge locations.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CoreNetworkNetworkFunctionGroup withEdgeLocations(java.util.Collection<String> edgeLocations) {
        setEdgeLocations(edgeLocations);
        return this;
    }

    /**
     * <p>
     * The segments associated with the network function group.
     * </p>
     * 
     * @param segments
     *        The segments associated with the network function group.
     */

    public void setSegments(ServiceInsertionSegments segments) {
        this.segments = segments;
    }

    /**
     * <p>
     * The segments associated with the network function group.
     * </p>
     * 
     * @return The segments associated with the network function group.
     */

    public ServiceInsertionSegments getSegments() {
        return this.segments;
    }

    /**
     * <p>
     * The segments associated with the network function group.
     * </p>
     * 
     * @param segments
     *        The segments associated with the network function group.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CoreNetworkNetworkFunctionGroup withSegments(ServiceInsertionSegments segments) {
        setSegments(segments);
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
        if (getName() != null)
            sb.append("Name: ").append(getName()).append(",");
        if (getEdgeLocations() != null)
            sb.append("EdgeLocations: ").append(getEdgeLocations()).append(",");
        if (getSegments() != null)
            sb.append("Segments: ").append(getSegments());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof CoreNetworkNetworkFunctionGroup == false)
            return false;
        CoreNetworkNetworkFunctionGroup other = (CoreNetworkNetworkFunctionGroup) obj;
        if (other.getName() == null ^ this.getName() == null)
            return false;
        if (other.getName() != null && other.getName().equals(this.getName()) == false)
            return false;
        if (other.getEdgeLocations() == null ^ this.getEdgeLocations() == null)
            return false;
        if (other.getEdgeLocations() != null && other.getEdgeLocations().equals(this.getEdgeLocations()) == false)
            return false;
        if (other.getSegments() == null ^ this.getSegments() == null)
            return false;
        if (other.getSegments() != null && other.getSegments().equals(this.getSegments()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getName() == null) ? 0 : getName().hashCode());
        hashCode = prime * hashCode + ((getEdgeLocations() == null) ? 0 : getEdgeLocations().hashCode());
        hashCode = prime * hashCode + ((getSegments() == null) ? 0 : getSegments().hashCode());
        return hashCode;
    }

    @Override
    public CoreNetworkNetworkFunctionGroup clone() {
        try {
            return (CoreNetworkNetworkFunctionGroup) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.networkmanager.model.transform.CoreNetworkNetworkFunctionGroupMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
