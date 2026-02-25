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
 * The list of network function groups and edge overrides for the service insertion action. Used for both the
 * <code>send-to</code> and <code>send-via</code> actions.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/networkmanager-2019-07-05/Via" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class Via implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The list of network function groups associated with the service insertion action.
     * </p>
     */
    private java.util.List<NetworkFunctionGroup> networkFunctionGroups;
    /**
     * <p>
     * Describes any edge overrides. An edge override is a specific edge to be used for traffic.
     * </p>
     */
    private java.util.List<EdgeOverride> withEdgeOverrides;

    /**
     * <p>
     * The list of network function groups associated with the service insertion action.
     * </p>
     * 
     * @return The list of network function groups associated with the service insertion action.
     */

    public java.util.List<NetworkFunctionGroup> getNetworkFunctionGroups() {
        return networkFunctionGroups;
    }

    /**
     * <p>
     * The list of network function groups associated with the service insertion action.
     * </p>
     * 
     * @param networkFunctionGroups
     *        The list of network function groups associated with the service insertion action.
     */

    public void setNetworkFunctionGroups(java.util.Collection<NetworkFunctionGroup> networkFunctionGroups) {
        if (networkFunctionGroups == null) {
            this.networkFunctionGroups = null;
            return;
        }

        this.networkFunctionGroups = new java.util.ArrayList<NetworkFunctionGroup>(networkFunctionGroups);
    }

    /**
     * <p>
     * The list of network function groups associated with the service insertion action.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setNetworkFunctionGroups(java.util.Collection)} or
     * {@link #withNetworkFunctionGroups(java.util.Collection)} if you want to override the existing values.
     * </p>
     * 
     * @param networkFunctionGroups
     *        The list of network function groups associated with the service insertion action.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Via withNetworkFunctionGroups(NetworkFunctionGroup... networkFunctionGroups) {
        if (this.networkFunctionGroups == null) {
            setNetworkFunctionGroups(new java.util.ArrayList<NetworkFunctionGroup>(networkFunctionGroups.length));
        }
        for (NetworkFunctionGroup ele : networkFunctionGroups) {
            this.networkFunctionGroups.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The list of network function groups associated with the service insertion action.
     * </p>
     * 
     * @param networkFunctionGroups
     *        The list of network function groups associated with the service insertion action.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Via withNetworkFunctionGroups(java.util.Collection<NetworkFunctionGroup> networkFunctionGroups) {
        setNetworkFunctionGroups(networkFunctionGroups);
        return this;
    }

    /**
     * <p>
     * Describes any edge overrides. An edge override is a specific edge to be used for traffic.
     * </p>
     * 
     * @return Describes any edge overrides. An edge override is a specific edge to be used for traffic.
     */

    public java.util.List<EdgeOverride> getWithEdgeOverrides() {
        return withEdgeOverrides;
    }

    /**
     * <p>
     * Describes any edge overrides. An edge override is a specific edge to be used for traffic.
     * </p>
     * 
     * @param withEdgeOverrides
     *        Describes any edge overrides. An edge override is a specific edge to be used for traffic.
     */

    public void setWithEdgeOverrides(java.util.Collection<EdgeOverride> withEdgeOverrides) {
        if (withEdgeOverrides == null) {
            this.withEdgeOverrides = null;
            return;
        }

        this.withEdgeOverrides = new java.util.ArrayList<EdgeOverride>(withEdgeOverrides);
    }

    /**
     * <p>
     * Describes any edge overrides. An edge override is a specific edge to be used for traffic.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setWithEdgeOverrides(java.util.Collection)} or {@link #withWithEdgeOverrides(java.util.Collection)} if
     * you want to override the existing values.
     * </p>
     * 
     * @param withEdgeOverrides
     *        Describes any edge overrides. An edge override is a specific edge to be used for traffic.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Via withWithEdgeOverrides(EdgeOverride... withEdgeOverrides) {
        if (this.withEdgeOverrides == null) {
            setWithEdgeOverrides(new java.util.ArrayList<EdgeOverride>(withEdgeOverrides.length));
        }
        for (EdgeOverride ele : withEdgeOverrides) {
            this.withEdgeOverrides.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * Describes any edge overrides. An edge override is a specific edge to be used for traffic.
     * </p>
     * 
     * @param withEdgeOverrides
     *        Describes any edge overrides. An edge override is a specific edge to be used for traffic.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Via withWithEdgeOverrides(java.util.Collection<EdgeOverride> withEdgeOverrides) {
        setWithEdgeOverrides(withEdgeOverrides);
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
        if (getNetworkFunctionGroups() != null)
            sb.append("NetworkFunctionGroups: ").append(getNetworkFunctionGroups()).append(",");
        if (getWithEdgeOverrides() != null)
            sb.append("WithEdgeOverrides: ").append(getWithEdgeOverrides());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof Via == false)
            return false;
        Via other = (Via) obj;
        if (other.getNetworkFunctionGroups() == null ^ this.getNetworkFunctionGroups() == null)
            return false;
        if (other.getNetworkFunctionGroups() != null && other.getNetworkFunctionGroups().equals(this.getNetworkFunctionGroups()) == false)
            return false;
        if (other.getWithEdgeOverrides() == null ^ this.getWithEdgeOverrides() == null)
            return false;
        if (other.getWithEdgeOverrides() != null && other.getWithEdgeOverrides().equals(this.getWithEdgeOverrides()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getNetworkFunctionGroups() == null) ? 0 : getNetworkFunctionGroups().hashCode());
        hashCode = prime * hashCode + ((getWithEdgeOverrides() == null) ? 0 : getWithEdgeOverrides().hashCode());
        return hashCode;
    }

    @Override
    public Via clone() {
        try {
            return (Via) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.networkmanager.model.transform.ViaMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
