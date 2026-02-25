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
 * Contains configuration details for use with Microsoft Intune. For information about using Connector for SCEP for
 * Microsoft Intune, see <a
 * href="https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlconnector-for-scep-intune.html">Using
 * Connector for SCEP for Microsoft Intune</a>.
 * </p>
 * <p>
 * When you use Connector for SCEP for Microsoft Intune, certain functionalities are enabled by accessing Microsoft
 * Intune through the Microsoft API. Your use of the Connector for SCEP and accompanying Amazon Web Services services
 * doesn't remove your need to have a valid license for your use of the Microsoft Intune service. You should also review
 * the <a href="https://learn.microsoft.com/en-us/mem/intune/apps/app-protection-policy">Microsoft Intune® App
 * Protection Policies</a>.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/IntuneConfiguration"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class IntuneConfiguration implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The directory (tenant) ID from your Microsoft Entra ID app registration.
     * </p>
     */
    private String azureApplicationId;
    /**
     * <p>
     * The primary domain from your Microsoft Entra ID app registration.
     * </p>
     */
    private String domain;

    /**
     * <p>
     * The directory (tenant) ID from your Microsoft Entra ID app registration.
     * </p>
     * 
     * @param azureApplicationId
     *        The directory (tenant) ID from your Microsoft Entra ID app registration.
     */

    public void setAzureApplicationId(String azureApplicationId) {
        this.azureApplicationId = azureApplicationId;
    }

    /**
     * <p>
     * The directory (tenant) ID from your Microsoft Entra ID app registration.
     * </p>
     * 
     * @return The directory (tenant) ID from your Microsoft Entra ID app registration.
     */

    public String getAzureApplicationId() {
        return this.azureApplicationId;
    }

    /**
     * <p>
     * The directory (tenant) ID from your Microsoft Entra ID app registration.
     * </p>
     * 
     * @param azureApplicationId
     *        The directory (tenant) ID from your Microsoft Entra ID app registration.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public IntuneConfiguration withAzureApplicationId(String azureApplicationId) {
        setAzureApplicationId(azureApplicationId);
        return this;
    }

    /**
     * <p>
     * The primary domain from your Microsoft Entra ID app registration.
     * </p>
     * 
     * @param domain
     *        The primary domain from your Microsoft Entra ID app registration.
     */

    public void setDomain(String domain) {
        this.domain = domain;
    }

    /**
     * <p>
     * The primary domain from your Microsoft Entra ID app registration.
     * </p>
     * 
     * @return The primary domain from your Microsoft Entra ID app registration.
     */

    public String getDomain() {
        return this.domain;
    }

    /**
     * <p>
     * The primary domain from your Microsoft Entra ID app registration.
     * </p>
     * 
     * @param domain
     *        The primary domain from your Microsoft Entra ID app registration.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public IntuneConfiguration withDomain(String domain) {
        setDomain(domain);
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
        if (getAzureApplicationId() != null)
            sb.append("AzureApplicationId: ").append(getAzureApplicationId()).append(",");
        if (getDomain() != null)
            sb.append("Domain: ").append(getDomain());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof IntuneConfiguration == false)
            return false;
        IntuneConfiguration other = (IntuneConfiguration) obj;
        if (other.getAzureApplicationId() == null ^ this.getAzureApplicationId() == null)
            return false;
        if (other.getAzureApplicationId() != null && other.getAzureApplicationId().equals(this.getAzureApplicationId()) == false)
            return false;
        if (other.getDomain() == null ^ this.getDomain() == null)
            return false;
        if (other.getDomain() != null && other.getDomain().equals(this.getDomain()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getAzureApplicationId() == null) ? 0 : getAzureApplicationId().hashCode());
        hashCode = prime * hashCode + ((getDomain() == null) ? 0 : getDomain().hashCode());
        return hashCode;
    }

    @Override
    public IntuneConfiguration clone() {
        try {
            return (IntuneConfiguration) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.pcaconnectorscep.model.transform.IntuneConfigurationMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
