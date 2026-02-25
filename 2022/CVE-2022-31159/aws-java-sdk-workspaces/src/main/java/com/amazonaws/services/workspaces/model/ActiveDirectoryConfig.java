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
 * Information about the Active Directory config.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/workspaces-2015-04-08/ActiveDirectoryConfig" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ActiveDirectoryConfig implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The name of the domain.
     * </p>
     */
    private String domainName;
    /**
     * <p>
     * Indicates the secret ARN on the service account.
     * </p>
     */
    private String serviceAccountSecretArn;

    /**
     * <p>
     * The name of the domain.
     * </p>
     * 
     * @param domainName
     *        The name of the domain.
     */

    public void setDomainName(String domainName) {
        this.domainName = domainName;
    }

    /**
     * <p>
     * The name of the domain.
     * </p>
     * 
     * @return The name of the domain.
     */

    public String getDomainName() {
        return this.domainName;
    }

    /**
     * <p>
     * The name of the domain.
     * </p>
     * 
     * @param domainName
     *        The name of the domain.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ActiveDirectoryConfig withDomainName(String domainName) {
        setDomainName(domainName);
        return this;
    }

    /**
     * <p>
     * Indicates the secret ARN on the service account.
     * </p>
     * 
     * @param serviceAccountSecretArn
     *        Indicates the secret ARN on the service account.
     */

    public void setServiceAccountSecretArn(String serviceAccountSecretArn) {
        this.serviceAccountSecretArn = serviceAccountSecretArn;
    }

    /**
     * <p>
     * Indicates the secret ARN on the service account.
     * </p>
     * 
     * @return Indicates the secret ARN on the service account.
     */

    public String getServiceAccountSecretArn() {
        return this.serviceAccountSecretArn;
    }

    /**
     * <p>
     * Indicates the secret ARN on the service account.
     * </p>
     * 
     * @param serviceAccountSecretArn
     *        Indicates the secret ARN on the service account.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ActiveDirectoryConfig withServiceAccountSecretArn(String serviceAccountSecretArn) {
        setServiceAccountSecretArn(serviceAccountSecretArn);
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
        if (getDomainName() != null)
            sb.append("DomainName: ").append(getDomainName()).append(",");
        if (getServiceAccountSecretArn() != null)
            sb.append("ServiceAccountSecretArn: ").append(getServiceAccountSecretArn());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ActiveDirectoryConfig == false)
            return false;
        ActiveDirectoryConfig other = (ActiveDirectoryConfig) obj;
        if (other.getDomainName() == null ^ this.getDomainName() == null)
            return false;
        if (other.getDomainName() != null && other.getDomainName().equals(this.getDomainName()) == false)
            return false;
        if (other.getServiceAccountSecretArn() == null ^ this.getServiceAccountSecretArn() == null)
            return false;
        if (other.getServiceAccountSecretArn() != null && other.getServiceAccountSecretArn().equals(this.getServiceAccountSecretArn()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getDomainName() == null) ? 0 : getDomainName().hashCode());
        hashCode = prime * hashCode + ((getServiceAccountSecretArn() == null) ? 0 : getServiceAccountSecretArn().hashCode());
        return hashCode;
    }

    @Override
    public ActiveDirectoryConfig clone() {
        try {
            return (ActiveDirectoryConfig) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.workspaces.model.transform.ActiveDirectoryConfigMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
