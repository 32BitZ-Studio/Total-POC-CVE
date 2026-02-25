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

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * For Connector for SCEP for general-purpose. An object containing information about the specified connector's SCEP
 * challenge passwords.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/Challenge" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class Challenge implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the challenge.
     * </p>
     */
    private String arn;
    /**
     * <p>
     * The Amazon Resource Name (ARN) of the connector.
     * </p>
     */
    private String connectorArn;
    /**
     * <p>
     * The date and time that the challenge was created.
     * </p>
     */
    private java.util.Date createdAt;
    /**
     * <p>
     * The date and time that the challenge was updated.
     * </p>
     */
    private java.util.Date updatedAt;
    /**
     * <p>
     * The SCEP challenge password, in UUID format.
     * </p>
     */
    private String password;

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the challenge.
     * </p>
     * 
     * @param arn
     *        The Amazon Resource Name (ARN) of the challenge.
     */

    public void setArn(String arn) {
        this.arn = arn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the challenge.
     * </p>
     * 
     * @return The Amazon Resource Name (ARN) of the challenge.
     */

    public String getArn() {
        return this.arn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the challenge.
     * </p>
     * 
     * @param arn
     *        The Amazon Resource Name (ARN) of the challenge.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Challenge withArn(String arn) {
        setArn(arn);
        return this;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the connector.
     * </p>
     * 
     * @param connectorArn
     *        The Amazon Resource Name (ARN) of the connector.
     */

    public void setConnectorArn(String connectorArn) {
        this.connectorArn = connectorArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the connector.
     * </p>
     * 
     * @return The Amazon Resource Name (ARN) of the connector.
     */

    public String getConnectorArn() {
        return this.connectorArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the connector.
     * </p>
     * 
     * @param connectorArn
     *        The Amazon Resource Name (ARN) of the connector.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Challenge withConnectorArn(String connectorArn) {
        setConnectorArn(connectorArn);
        return this;
    }

    /**
     * <p>
     * The date and time that the challenge was created.
     * </p>
     * 
     * @param createdAt
     *        The date and time that the challenge was created.
     */

    public void setCreatedAt(java.util.Date createdAt) {
        this.createdAt = createdAt;
    }

    /**
     * <p>
     * The date and time that the challenge was created.
     * </p>
     * 
     * @return The date and time that the challenge was created.
     */

    public java.util.Date getCreatedAt() {
        return this.createdAt;
    }

    /**
     * <p>
     * The date and time that the challenge was created.
     * </p>
     * 
     * @param createdAt
     *        The date and time that the challenge was created.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Challenge withCreatedAt(java.util.Date createdAt) {
        setCreatedAt(createdAt);
        return this;
    }

    /**
     * <p>
     * The date and time that the challenge was updated.
     * </p>
     * 
     * @param updatedAt
     *        The date and time that the challenge was updated.
     */

    public void setUpdatedAt(java.util.Date updatedAt) {
        this.updatedAt = updatedAt;
    }

    /**
     * <p>
     * The date and time that the challenge was updated.
     * </p>
     * 
     * @return The date and time that the challenge was updated.
     */

    public java.util.Date getUpdatedAt() {
        return this.updatedAt;
    }

    /**
     * <p>
     * The date and time that the challenge was updated.
     * </p>
     * 
     * @param updatedAt
     *        The date and time that the challenge was updated.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Challenge withUpdatedAt(java.util.Date updatedAt) {
        setUpdatedAt(updatedAt);
        return this;
    }

    /**
     * <p>
     * The SCEP challenge password, in UUID format.
     * </p>
     * 
     * @param password
     *        The SCEP challenge password, in UUID format.
     */

    public void setPassword(String password) {
        this.password = password;
    }

    /**
     * <p>
     * The SCEP challenge password, in UUID format.
     * </p>
     * 
     * @return The SCEP challenge password, in UUID format.
     */

    public String getPassword() {
        return this.password;
    }

    /**
     * <p>
     * The SCEP challenge password, in UUID format.
     * </p>
     * 
     * @param password
     *        The SCEP challenge password, in UUID format.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Challenge withPassword(String password) {
        setPassword(password);
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
        if (getArn() != null)
            sb.append("Arn: ").append(getArn()).append(",");
        if (getConnectorArn() != null)
            sb.append("ConnectorArn: ").append(getConnectorArn()).append(",");
        if (getCreatedAt() != null)
            sb.append("CreatedAt: ").append(getCreatedAt()).append(",");
        if (getUpdatedAt() != null)
            sb.append("UpdatedAt: ").append(getUpdatedAt()).append(",");
        if (getPassword() != null)
            sb.append("Password: ").append("***Sensitive Data Redacted***");
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof Challenge == false)
            return false;
        Challenge other = (Challenge) obj;
        if (other.getArn() == null ^ this.getArn() == null)
            return false;
        if (other.getArn() != null && other.getArn().equals(this.getArn()) == false)
            return false;
        if (other.getConnectorArn() == null ^ this.getConnectorArn() == null)
            return false;
        if (other.getConnectorArn() != null && other.getConnectorArn().equals(this.getConnectorArn()) == false)
            return false;
        if (other.getCreatedAt() == null ^ this.getCreatedAt() == null)
            return false;
        if (other.getCreatedAt() != null && other.getCreatedAt().equals(this.getCreatedAt()) == false)
            return false;
        if (other.getUpdatedAt() == null ^ this.getUpdatedAt() == null)
            return false;
        if (other.getUpdatedAt() != null && other.getUpdatedAt().equals(this.getUpdatedAt()) == false)
            return false;
        if (other.getPassword() == null ^ this.getPassword() == null)
            return false;
        if (other.getPassword() != null && other.getPassword().equals(this.getPassword()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getArn() == null) ? 0 : getArn().hashCode());
        hashCode = prime * hashCode + ((getConnectorArn() == null) ? 0 : getConnectorArn().hashCode());
        hashCode = prime * hashCode + ((getCreatedAt() == null) ? 0 : getCreatedAt().hashCode());
        hashCode = prime * hashCode + ((getUpdatedAt() == null) ? 0 : getUpdatedAt().hashCode());
        hashCode = prime * hashCode + ((getPassword() == null) ? 0 : getPassword().hashCode());
        return hashCode;
    }

    @Override
    public Challenge clone() {
        try {
            return (Challenge) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.pcaconnectorscep.model.transform.ChallengeMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
