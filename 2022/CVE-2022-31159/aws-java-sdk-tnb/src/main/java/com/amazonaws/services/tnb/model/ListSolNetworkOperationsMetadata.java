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
package com.amazonaws.services.tnb.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * Metadata related to a network operation.
 * </p>
 * <p>
 * A network operation is any operation that is done to your network, such as network instance instantiation or
 * termination.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/tnb-2008-10-21/ListSolNetworkOperationsMetadata"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ListSolNetworkOperationsMetadata implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The date that the resource was created.
     * </p>
     */
    private java.util.Date createdAt;
    /**
     * <p>
     * The date that the resource was last modified.
     * </p>
     */
    private java.util.Date lastModified;
    /**
     * <p>
     * The network service descriptor id used for the operation.
     * </p>
     * <p>
     * Only present if the updateType is <code>UPDATE_NS</code>.
     * </p>
     */
    private String nsdInfoId;
    /**
     * <p>
     * The network function id used for the operation.
     * </p>
     * <p>
     * Only present if the updateType is <code>MODIFY_VNF_INFO</code>.
     * </p>
     */
    private String vnfInstanceId;

    /**
     * <p>
     * The date that the resource was created.
     * </p>
     * 
     * @param createdAt
     *        The date that the resource was created.
     */

    public void setCreatedAt(java.util.Date createdAt) {
        this.createdAt = createdAt;
    }

    /**
     * <p>
     * The date that the resource was created.
     * </p>
     * 
     * @return The date that the resource was created.
     */

    public java.util.Date getCreatedAt() {
        return this.createdAt;
    }

    /**
     * <p>
     * The date that the resource was created.
     * </p>
     * 
     * @param createdAt
     *        The date that the resource was created.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListSolNetworkOperationsMetadata withCreatedAt(java.util.Date createdAt) {
        setCreatedAt(createdAt);
        return this;
    }

    /**
     * <p>
     * The date that the resource was last modified.
     * </p>
     * 
     * @param lastModified
     *        The date that the resource was last modified.
     */

    public void setLastModified(java.util.Date lastModified) {
        this.lastModified = lastModified;
    }

    /**
     * <p>
     * The date that the resource was last modified.
     * </p>
     * 
     * @return The date that the resource was last modified.
     */

    public java.util.Date getLastModified() {
        return this.lastModified;
    }

    /**
     * <p>
     * The date that the resource was last modified.
     * </p>
     * 
     * @param lastModified
     *        The date that the resource was last modified.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListSolNetworkOperationsMetadata withLastModified(java.util.Date lastModified) {
        setLastModified(lastModified);
        return this;
    }

    /**
     * <p>
     * The network service descriptor id used for the operation.
     * </p>
     * <p>
     * Only present if the updateType is <code>UPDATE_NS</code>.
     * </p>
     * 
     * @param nsdInfoId
     *        The network service descriptor id used for the operation.</p>
     *        <p>
     *        Only present if the updateType is <code>UPDATE_NS</code>.
     */

    public void setNsdInfoId(String nsdInfoId) {
        this.nsdInfoId = nsdInfoId;
    }

    /**
     * <p>
     * The network service descriptor id used for the operation.
     * </p>
     * <p>
     * Only present if the updateType is <code>UPDATE_NS</code>.
     * </p>
     * 
     * @return The network service descriptor id used for the operation.</p>
     *         <p>
     *         Only present if the updateType is <code>UPDATE_NS</code>.
     */

    public String getNsdInfoId() {
        return this.nsdInfoId;
    }

    /**
     * <p>
     * The network service descriptor id used for the operation.
     * </p>
     * <p>
     * Only present if the updateType is <code>UPDATE_NS</code>.
     * </p>
     * 
     * @param nsdInfoId
     *        The network service descriptor id used for the operation.</p>
     *        <p>
     *        Only present if the updateType is <code>UPDATE_NS</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListSolNetworkOperationsMetadata withNsdInfoId(String nsdInfoId) {
        setNsdInfoId(nsdInfoId);
        return this;
    }

    /**
     * <p>
     * The network function id used for the operation.
     * </p>
     * <p>
     * Only present if the updateType is <code>MODIFY_VNF_INFO</code>.
     * </p>
     * 
     * @param vnfInstanceId
     *        The network function id used for the operation.</p>
     *        <p>
     *        Only present if the updateType is <code>MODIFY_VNF_INFO</code>.
     */

    public void setVnfInstanceId(String vnfInstanceId) {
        this.vnfInstanceId = vnfInstanceId;
    }

    /**
     * <p>
     * The network function id used for the operation.
     * </p>
     * <p>
     * Only present if the updateType is <code>MODIFY_VNF_INFO</code>.
     * </p>
     * 
     * @return The network function id used for the operation.</p>
     *         <p>
     *         Only present if the updateType is <code>MODIFY_VNF_INFO</code>.
     */

    public String getVnfInstanceId() {
        return this.vnfInstanceId;
    }

    /**
     * <p>
     * The network function id used for the operation.
     * </p>
     * <p>
     * Only present if the updateType is <code>MODIFY_VNF_INFO</code>.
     * </p>
     * 
     * @param vnfInstanceId
     *        The network function id used for the operation.</p>
     *        <p>
     *        Only present if the updateType is <code>MODIFY_VNF_INFO</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListSolNetworkOperationsMetadata withVnfInstanceId(String vnfInstanceId) {
        setVnfInstanceId(vnfInstanceId);
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
        if (getCreatedAt() != null)
            sb.append("CreatedAt: ").append(getCreatedAt()).append(",");
        if (getLastModified() != null)
            sb.append("LastModified: ").append(getLastModified()).append(",");
        if (getNsdInfoId() != null)
            sb.append("NsdInfoId: ").append(getNsdInfoId()).append(",");
        if (getVnfInstanceId() != null)
            sb.append("VnfInstanceId: ").append(getVnfInstanceId());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ListSolNetworkOperationsMetadata == false)
            return false;
        ListSolNetworkOperationsMetadata other = (ListSolNetworkOperationsMetadata) obj;
        if (other.getCreatedAt() == null ^ this.getCreatedAt() == null)
            return false;
        if (other.getCreatedAt() != null && other.getCreatedAt().equals(this.getCreatedAt()) == false)
            return false;
        if (other.getLastModified() == null ^ this.getLastModified() == null)
            return false;
        if (other.getLastModified() != null && other.getLastModified().equals(this.getLastModified()) == false)
            return false;
        if (other.getNsdInfoId() == null ^ this.getNsdInfoId() == null)
            return false;
        if (other.getNsdInfoId() != null && other.getNsdInfoId().equals(this.getNsdInfoId()) == false)
            return false;
        if (other.getVnfInstanceId() == null ^ this.getVnfInstanceId() == null)
            return false;
        if (other.getVnfInstanceId() != null && other.getVnfInstanceId().equals(this.getVnfInstanceId()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getCreatedAt() == null) ? 0 : getCreatedAt().hashCode());
        hashCode = prime * hashCode + ((getLastModified() == null) ? 0 : getLastModified().hashCode());
        hashCode = prime * hashCode + ((getNsdInfoId() == null) ? 0 : getNsdInfoId().hashCode());
        hashCode = prime * hashCode + ((getVnfInstanceId() == null) ? 0 : getVnfInstanceId().hashCode());
        return hashCode;
    }

    @Override
    public ListSolNetworkOperationsMetadata clone() {
        try {
            return (ListSolNetworkOperationsMetadata) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.tnb.model.transform.ListSolNetworkOperationsMetadataMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
