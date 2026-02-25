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
 * Describes the edge that's used for the override.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/networkmanager-2019-07-05/EdgeOverride" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class EdgeOverride implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The list of edge locations.
     * </p>
     */
    private java.util.List<java.util.List<String>> edgeSets;
    /**
     * <p>
     * The edge that should be used when overriding the current edge order.
     * </p>
     */
    private String useEdge;

    /**
     * <p>
     * The list of edge locations.
     * </p>
     * 
     * @return The list of edge locations.
     */

    public java.util.List<java.util.List<String>> getEdgeSets() {
        return edgeSets;
    }

    /**
     * <p>
     * The list of edge locations.
     * </p>
     * 
     * @param edgeSets
     *        The list of edge locations.
     */

    public void setEdgeSets(java.util.Collection<java.util.List<String>> edgeSets) {
        if (edgeSets == null) {
            this.edgeSets = null;
            return;
        }

        this.edgeSets = new java.util.ArrayList<java.util.List<String>>(edgeSets);
    }

    /**
     * <p>
     * The list of edge locations.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setEdgeSets(java.util.Collection)} or {@link #withEdgeSets(java.util.Collection)} if you want to override
     * the existing values.
     * </p>
     * 
     * @param edgeSets
     *        The list of edge locations.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public EdgeOverride withEdgeSets(java.util.List<String>... edgeSets) {
        if (this.edgeSets == null) {
            setEdgeSets(new java.util.ArrayList<java.util.List<String>>(edgeSets.length));
        }
        for (java.util.List<String> ele : edgeSets) {
            this.edgeSets.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The list of edge locations.
     * </p>
     * 
     * @param edgeSets
     *        The list of edge locations.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public EdgeOverride withEdgeSets(java.util.Collection<java.util.List<String>> edgeSets) {
        setEdgeSets(edgeSets);
        return this;
    }

    /**
     * <p>
     * The edge that should be used when overriding the current edge order.
     * </p>
     * 
     * @param useEdge
     *        The edge that should be used when overriding the current edge order.
     */

    public void setUseEdge(String useEdge) {
        this.useEdge = useEdge;
    }

    /**
     * <p>
     * The edge that should be used when overriding the current edge order.
     * </p>
     * 
     * @return The edge that should be used when overriding the current edge order.
     */

    public String getUseEdge() {
        return this.useEdge;
    }

    /**
     * <p>
     * The edge that should be used when overriding the current edge order.
     * </p>
     * 
     * @param useEdge
     *        The edge that should be used when overriding the current edge order.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public EdgeOverride withUseEdge(String useEdge) {
        setUseEdge(useEdge);
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
        if (getEdgeSets() != null)
            sb.append("EdgeSets: ").append(getEdgeSets()).append(",");
        if (getUseEdge() != null)
            sb.append("UseEdge: ").append(getUseEdge());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof EdgeOverride == false)
            return false;
        EdgeOverride other = (EdgeOverride) obj;
        if (other.getEdgeSets() == null ^ this.getEdgeSets() == null)
            return false;
        if (other.getEdgeSets() != null && other.getEdgeSets().equals(this.getEdgeSets()) == false)
            return false;
        if (other.getUseEdge() == null ^ this.getUseEdge() == null)
            return false;
        if (other.getUseEdge() != null && other.getUseEdge().equals(this.getUseEdge()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getEdgeSets() == null) ? 0 : getEdgeSets().hashCode());
        hashCode = prime * hashCode + ((getUseEdge() == null) ? 0 : getUseEdge().hashCode());
        return hashCode;
    }

    @Override
    public EdgeOverride clone() {
        try {
            return (EdgeOverride) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.networkmanager.model.transform.EdgeOverrideMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
