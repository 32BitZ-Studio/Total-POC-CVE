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
 * Describes a core network
 * </p>
 * 
 * @see <a
 *      href="http://docs.aws.amazon.com/goto/WebAPI/networkmanager-2019-07-05/CoreNetworkNetworkFunctionGroupIdentifier"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class CoreNetworkNetworkFunctionGroupIdentifier implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The ID of the core network.
     * </p>
     */
    private String coreNetworkId;
    /**
     * <p>
     * The network function group name.
     * </p>
     */
    private String networkFunctionGroupName;
    /**
     * <p>
     * The location for the core network edge.
     * </p>
     */
    private String edgeLocation;

    /**
     * <p>
     * The ID of the core network.
     * </p>
     * 
     * @param coreNetworkId
     *        The ID of the core network.
     */

    public void setCoreNetworkId(String coreNetworkId) {
        this.coreNetworkId = coreNetworkId;
    }

    /**
     * <p>
     * The ID of the core network.
     * </p>
     * 
     * @return The ID of the core network.
     */

    public String getCoreNetworkId() {
        return this.coreNetworkId;
    }

    /**
     * <p>
     * The ID of the core network.
     * </p>
     * 
     * @param coreNetworkId
     *        The ID of the core network.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CoreNetworkNetworkFunctionGroupIdentifier withCoreNetworkId(String coreNetworkId) {
        setCoreNetworkId(coreNetworkId);
        return this;
    }

    /**
     * <p>
     * The network function group name.
     * </p>
     * 
     * @param networkFunctionGroupName
     *        The network function group name.
     */

    public void setNetworkFunctionGroupName(String networkFunctionGroupName) {
        this.networkFunctionGroupName = networkFunctionGroupName;
    }

    /**
     * <p>
     * The network function group name.
     * </p>
     * 
     * @return The network function group name.
     */

    public String getNetworkFunctionGroupName() {
        return this.networkFunctionGroupName;
    }

    /**
     * <p>
     * The network function group name.
     * </p>
     * 
     * @param networkFunctionGroupName
     *        The network function group name.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CoreNetworkNetworkFunctionGroupIdentifier withNetworkFunctionGroupName(String networkFunctionGroupName) {
        setNetworkFunctionGroupName(networkFunctionGroupName);
        return this;
    }

    /**
     * <p>
     * The location for the core network edge.
     * </p>
     * 
     * @param edgeLocation
     *        The location for the core network edge.
     */

    public void setEdgeLocation(String edgeLocation) {
        this.edgeLocation = edgeLocation;
    }

    /**
     * <p>
     * The location for the core network edge.
     * </p>
     * 
     * @return The location for the core network edge.
     */

    public String getEdgeLocation() {
        return this.edgeLocation;
    }

    /**
     * <p>
     * The location for the core network edge.
     * </p>
     * 
     * @param edgeLocation
     *        The location for the core network edge.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CoreNetworkNetworkFunctionGroupIdentifier withEdgeLocation(String edgeLocation) {
        setEdgeLocation(edgeLocation);
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
        if (getCoreNetworkId() != null)
            sb.append("CoreNetworkId: ").append(getCoreNetworkId()).append(",");
        if (getNetworkFunctionGroupName() != null)
            sb.append("NetworkFunctionGroupName: ").append(getNetworkFunctionGroupName()).append(",");
        if (getEdgeLocation() != null)
            sb.append("EdgeLocation: ").append(getEdgeLocation());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof CoreNetworkNetworkFunctionGroupIdentifier == false)
            return false;
        CoreNetworkNetworkFunctionGroupIdentifier other = (CoreNetworkNetworkFunctionGroupIdentifier) obj;
        if (other.getCoreNetworkId() == null ^ this.getCoreNetworkId() == null)
            return false;
        if (other.getCoreNetworkId() != null && other.getCoreNetworkId().equals(this.getCoreNetworkId()) == false)
            return false;
        if (other.getNetworkFunctionGroupName() == null ^ this.getNetworkFunctionGroupName() == null)
            return false;
        if (other.getNetworkFunctionGroupName() != null && other.getNetworkFunctionGroupName().equals(this.getNetworkFunctionGroupName()) == false)
            return false;
        if (other.getEdgeLocation() == null ^ this.getEdgeLocation() == null)
            return false;
        if (other.getEdgeLocation() != null && other.getEdgeLocation().equals(this.getEdgeLocation()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getCoreNetworkId() == null) ? 0 : getCoreNetworkId().hashCode());
        hashCode = prime * hashCode + ((getNetworkFunctionGroupName() == null) ? 0 : getNetworkFunctionGroupName().hashCode());
        hashCode = prime * hashCode + ((getEdgeLocation() == null) ? 0 : getEdgeLocation().hashCode());
        return hashCode;
    }

    @Override
    public CoreNetworkNetworkFunctionGroupIdentifier clone() {
        try {
            return (CoreNetworkNetworkFunctionGroupIdentifier) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.networkmanager.model.transform.CoreNetworkNetworkFunctionGroupIdentifierMarshaller.getInstance().marshall(this,
                protocolMarshaller);
    }
}
