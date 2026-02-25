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
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * Describes the storage connector.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/workspaces-2015-04-08/StorageConnector" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class StorageConnector implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The type of connector used to save user files.
     * </p>
     */
    private String connectorType;
    /**
     * <p>
     * Indicates if the storage connetor is enabled or disabled.
     * </p>
     */
    private String status;

    /**
     * <p>
     * The type of connector used to save user files.
     * </p>
     * 
     * @param connectorType
     *        The type of connector used to save user files.
     * @see StorageConnectorTypeEnum
     */

    public void setConnectorType(String connectorType) {
        this.connectorType = connectorType;
    }

    /**
     * <p>
     * The type of connector used to save user files.
     * </p>
     * 
     * @return The type of connector used to save user files.
     * @see StorageConnectorTypeEnum
     */

    public String getConnectorType() {
        return this.connectorType;
    }

    /**
     * <p>
     * The type of connector used to save user files.
     * </p>
     * 
     * @param connectorType
     *        The type of connector used to save user files.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see StorageConnectorTypeEnum
     */

    public StorageConnector withConnectorType(String connectorType) {
        setConnectorType(connectorType);
        return this;
    }

    /**
     * <p>
     * The type of connector used to save user files.
     * </p>
     * 
     * @param connectorType
     *        The type of connector used to save user files.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see StorageConnectorTypeEnum
     */

    public StorageConnector withConnectorType(StorageConnectorTypeEnum connectorType) {
        this.connectorType = connectorType.toString();
        return this;
    }

    /**
     * <p>
     * Indicates if the storage connetor is enabled or disabled.
     * </p>
     * 
     * @param status
     *        Indicates if the storage connetor is enabled or disabled.
     * @see StorageConnectorStatusEnum
     */

    public void setStatus(String status) {
        this.status = status;
    }

    /**
     * <p>
     * Indicates if the storage connetor is enabled or disabled.
     * </p>
     * 
     * @return Indicates if the storage connetor is enabled or disabled.
     * @see StorageConnectorStatusEnum
     */

    public String getStatus() {
        return this.status;
    }

    /**
     * <p>
     * Indicates if the storage connetor is enabled or disabled.
     * </p>
     * 
     * @param status
     *        Indicates if the storage connetor is enabled or disabled.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see StorageConnectorStatusEnum
     */

    public StorageConnector withStatus(String status) {
        setStatus(status);
        return this;
    }

    /**
     * <p>
     * Indicates if the storage connetor is enabled or disabled.
     * </p>
     * 
     * @param status
     *        Indicates if the storage connetor is enabled or disabled.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see StorageConnectorStatusEnum
     */

    public StorageConnector withStatus(StorageConnectorStatusEnum status) {
        this.status = status.toString();
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
        if (getConnectorType() != null)
            sb.append("ConnectorType: ").append(getConnectorType()).append(",");
        if (getStatus() != null)
            sb.append("Status: ").append(getStatus());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof StorageConnector == false)
            return false;
        StorageConnector other = (StorageConnector) obj;
        if (other.getConnectorType() == null ^ this.getConnectorType() == null)
            return false;
        if (other.getConnectorType() != null && other.getConnectorType().equals(this.getConnectorType()) == false)
            return false;
        if (other.getStatus() == null ^ this.getStatus() == null)
            return false;
        if (other.getStatus() != null && other.getStatus().equals(this.getStatus()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getConnectorType() == null) ? 0 : getConnectorType().hashCode());
        hashCode = prime * hashCode + ((getStatus() == null) ? 0 : getStatus().hashCode());
        return hashCode;
    }

    @Override
    public StorageConnector clone() {
        try {
            return (StorageConnector) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.workspaces.model.transform.StorageConnectorMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
