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
 * Connector for SCEP is a service that links Amazon Web Services Private Certificate Authority to your SCEP-enabled
 * devices. The connector brokers the exchange of certificates from Amazon Web Services Private CA to your SCEP-enabled
 * devices and mobile device management systems. The connector is a complex type that contains the connector's
 * configuration settings.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/Connector" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class Connector implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the connector.
     * </p>
     */
    private String arn;
    /**
     * <p>
     * The Amazon Resource Name (ARN) of the certificate authority associated with the connector.
     * </p>
     */
    private String certificateAuthorityArn;
    /**
     * <p>
     * The connector type.
     * </p>
     */
    private String type;
    /**
     * <p>
     * Contains settings relevant to the mobile device management system that you chose for the connector. If you didn't
     * configure <code>MobileDeviceManagement</code>, then the connector is for general-purpose use and this object is
     * empty.
     * </p>
     */
    private MobileDeviceManagement mobileDeviceManagement;
    /**
     * <p>
     * Contains OpenID Connect (OIDC) parameters for use with Connector for SCEP for Microsoft Intune. For more
     * information about using Connector for SCEP for Microsoft Intune, see <a
     * href="https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlconnector-for-scep-intune.html"
     * >Using Connector for SCEP for Microsoft Intune</a>.
     * </p>
     */
    private OpenIdConfiguration openIdConfiguration;
    /**
     * <p>
     * The connector's status.
     * </p>
     */
    private String status;
    /**
     * <p>
     * Information about why connector creation failed, if status is <code>FAILED</code>.
     * </p>
     */
    private String statusReason;
    /**
     * <p>
     * The connector's HTTPS public SCEP URL.
     * </p>
     */
    private String endpoint;
    /**
     * <p>
     * The date and time that the connector was created.
     * </p>
     */
    private java.util.Date createdAt;
    /**
     * <p>
     * The date and time that the connector was updated.
     * </p>
     */
    private java.util.Date updatedAt;

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the connector.
     * </p>
     * 
     * @param arn
     *        The Amazon Resource Name (ARN) of the connector.
     */

    public void setArn(String arn) {
        this.arn = arn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the connector.
     * </p>
     * 
     * @return The Amazon Resource Name (ARN) of the connector.
     */

    public String getArn() {
        return this.arn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the connector.
     * </p>
     * 
     * @param arn
     *        The Amazon Resource Name (ARN) of the connector.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Connector withArn(String arn) {
        setArn(arn);
        return this;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the certificate authority associated with the connector.
     * </p>
     * 
     * @param certificateAuthorityArn
     *        The Amazon Resource Name (ARN) of the certificate authority associated with the connector.
     */

    public void setCertificateAuthorityArn(String certificateAuthorityArn) {
        this.certificateAuthorityArn = certificateAuthorityArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the certificate authority associated with the connector.
     * </p>
     * 
     * @return The Amazon Resource Name (ARN) of the certificate authority associated with the connector.
     */

    public String getCertificateAuthorityArn() {
        return this.certificateAuthorityArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the certificate authority associated with the connector.
     * </p>
     * 
     * @param certificateAuthorityArn
     *        The Amazon Resource Name (ARN) of the certificate authority associated with the connector.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Connector withCertificateAuthorityArn(String certificateAuthorityArn) {
        setCertificateAuthorityArn(certificateAuthorityArn);
        return this;
    }

    /**
     * <p>
     * The connector type.
     * </p>
     * 
     * @param type
     *        The connector type.
     * @see ConnectorType
     */

    public void setType(String type) {
        this.type = type;
    }

    /**
     * <p>
     * The connector type.
     * </p>
     * 
     * @return The connector type.
     * @see ConnectorType
     */

    public String getType() {
        return this.type;
    }

    /**
     * <p>
     * The connector type.
     * </p>
     * 
     * @param type
     *        The connector type.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ConnectorType
     */

    public Connector withType(String type) {
        setType(type);
        return this;
    }

    /**
     * <p>
     * The connector type.
     * </p>
     * 
     * @param type
     *        The connector type.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ConnectorType
     */

    public Connector withType(ConnectorType type) {
        this.type = type.toString();
        return this;
    }

    /**
     * <p>
     * Contains settings relevant to the mobile device management system that you chose for the connector. If you didn't
     * configure <code>MobileDeviceManagement</code>, then the connector is for general-purpose use and this object is
     * empty.
     * </p>
     * 
     * @param mobileDeviceManagement
     *        Contains settings relevant to the mobile device management system that you chose for the connector. If you
     *        didn't configure <code>MobileDeviceManagement</code>, then the connector is for general-purpose use and
     *        this object is empty.
     */

    public void setMobileDeviceManagement(MobileDeviceManagement mobileDeviceManagement) {
        this.mobileDeviceManagement = mobileDeviceManagement;
    }

    /**
     * <p>
     * Contains settings relevant to the mobile device management system that you chose for the connector. If you didn't
     * configure <code>MobileDeviceManagement</code>, then the connector is for general-purpose use and this object is
     * empty.
     * </p>
     * 
     * @return Contains settings relevant to the mobile device management system that you chose for the connector. If
     *         you didn't configure <code>MobileDeviceManagement</code>, then the connector is for general-purpose use
     *         and this object is empty.
     */

    public MobileDeviceManagement getMobileDeviceManagement() {
        return this.mobileDeviceManagement;
    }

    /**
     * <p>
     * Contains settings relevant to the mobile device management system that you chose for the connector. If you didn't
     * configure <code>MobileDeviceManagement</code>, then the connector is for general-purpose use and this object is
     * empty.
     * </p>
     * 
     * @param mobileDeviceManagement
     *        Contains settings relevant to the mobile device management system that you chose for the connector. If you
     *        didn't configure <code>MobileDeviceManagement</code>, then the connector is for general-purpose use and
     *        this object is empty.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Connector withMobileDeviceManagement(MobileDeviceManagement mobileDeviceManagement) {
        setMobileDeviceManagement(mobileDeviceManagement);
        return this;
    }

    /**
     * <p>
     * Contains OpenID Connect (OIDC) parameters for use with Connector for SCEP for Microsoft Intune. For more
     * information about using Connector for SCEP for Microsoft Intune, see <a
     * href="https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlconnector-for-scep-intune.html"
     * >Using Connector for SCEP for Microsoft Intune</a>.
     * </p>
     * 
     * @param openIdConfiguration
     *        Contains OpenID Connect (OIDC) parameters for use with Connector for SCEP for Microsoft Intune. For more
     *        information about using Connector for SCEP for Microsoft Intune, see <a href=
     *        "https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlconnector-for-scep-intune.html"
     *        >Using Connector for SCEP for Microsoft Intune</a>.
     */

    public void setOpenIdConfiguration(OpenIdConfiguration openIdConfiguration) {
        this.openIdConfiguration = openIdConfiguration;
    }

    /**
     * <p>
     * Contains OpenID Connect (OIDC) parameters for use with Connector for SCEP for Microsoft Intune. For more
     * information about using Connector for SCEP for Microsoft Intune, see <a
     * href="https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlconnector-for-scep-intune.html"
     * >Using Connector for SCEP for Microsoft Intune</a>.
     * </p>
     * 
     * @return Contains OpenID Connect (OIDC) parameters for use with Connector for SCEP for Microsoft Intune. For more
     *         information about using Connector for SCEP for Microsoft Intune, see <a href=
     *         "https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlconnector-for-scep-intune.html"
     *         >Using Connector for SCEP for Microsoft Intune</a>.
     */

    public OpenIdConfiguration getOpenIdConfiguration() {
        return this.openIdConfiguration;
    }

    /**
     * <p>
     * Contains OpenID Connect (OIDC) parameters for use with Connector for SCEP for Microsoft Intune. For more
     * information about using Connector for SCEP for Microsoft Intune, see <a
     * href="https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlconnector-for-scep-intune.html"
     * >Using Connector for SCEP for Microsoft Intune</a>.
     * </p>
     * 
     * @param openIdConfiguration
     *        Contains OpenID Connect (OIDC) parameters for use with Connector for SCEP for Microsoft Intune. For more
     *        information about using Connector for SCEP for Microsoft Intune, see <a href=
     *        "https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlconnector-for-scep-intune.html"
     *        >Using Connector for SCEP for Microsoft Intune</a>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Connector withOpenIdConfiguration(OpenIdConfiguration openIdConfiguration) {
        setOpenIdConfiguration(openIdConfiguration);
        return this;
    }

    /**
     * <p>
     * The connector's status.
     * </p>
     * 
     * @param status
     *        The connector's status.
     * @see ConnectorStatus
     */

    public void setStatus(String status) {
        this.status = status;
    }

    /**
     * <p>
     * The connector's status.
     * </p>
     * 
     * @return The connector's status.
     * @see ConnectorStatus
     */

    public String getStatus() {
        return this.status;
    }

    /**
     * <p>
     * The connector's status.
     * </p>
     * 
     * @param status
     *        The connector's status.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ConnectorStatus
     */

    public Connector withStatus(String status) {
        setStatus(status);
        return this;
    }

    /**
     * <p>
     * The connector's status.
     * </p>
     * 
     * @param status
     *        The connector's status.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ConnectorStatus
     */

    public Connector withStatus(ConnectorStatus status) {
        this.status = status.toString();
        return this;
    }

    /**
     * <p>
     * Information about why connector creation failed, if status is <code>FAILED</code>.
     * </p>
     * 
     * @param statusReason
     *        Information about why connector creation failed, if status is <code>FAILED</code>.
     * @see ConnectorStatusReason
     */

    public void setStatusReason(String statusReason) {
        this.statusReason = statusReason;
    }

    /**
     * <p>
     * Information about why connector creation failed, if status is <code>FAILED</code>.
     * </p>
     * 
     * @return Information about why connector creation failed, if status is <code>FAILED</code>.
     * @see ConnectorStatusReason
     */

    public String getStatusReason() {
        return this.statusReason;
    }

    /**
     * <p>
     * Information about why connector creation failed, if status is <code>FAILED</code>.
     * </p>
     * 
     * @param statusReason
     *        Information about why connector creation failed, if status is <code>FAILED</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ConnectorStatusReason
     */

    public Connector withStatusReason(String statusReason) {
        setStatusReason(statusReason);
        return this;
    }

    /**
     * <p>
     * Information about why connector creation failed, if status is <code>FAILED</code>.
     * </p>
     * 
     * @param statusReason
     *        Information about why connector creation failed, if status is <code>FAILED</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ConnectorStatusReason
     */

    public Connector withStatusReason(ConnectorStatusReason statusReason) {
        this.statusReason = statusReason.toString();
        return this;
    }

    /**
     * <p>
     * The connector's HTTPS public SCEP URL.
     * </p>
     * 
     * @param endpoint
     *        The connector's HTTPS public SCEP URL.
     */

    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
    }

    /**
     * <p>
     * The connector's HTTPS public SCEP URL.
     * </p>
     * 
     * @return The connector's HTTPS public SCEP URL.
     */

    public String getEndpoint() {
        return this.endpoint;
    }

    /**
     * <p>
     * The connector's HTTPS public SCEP URL.
     * </p>
     * 
     * @param endpoint
     *        The connector's HTTPS public SCEP URL.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Connector withEndpoint(String endpoint) {
        setEndpoint(endpoint);
        return this;
    }

    /**
     * <p>
     * The date and time that the connector was created.
     * </p>
     * 
     * @param createdAt
     *        The date and time that the connector was created.
     */

    public void setCreatedAt(java.util.Date createdAt) {
        this.createdAt = createdAt;
    }

    /**
     * <p>
     * The date and time that the connector was created.
     * </p>
     * 
     * @return The date and time that the connector was created.
     */

    public java.util.Date getCreatedAt() {
        return this.createdAt;
    }

    /**
     * <p>
     * The date and time that the connector was created.
     * </p>
     * 
     * @param createdAt
     *        The date and time that the connector was created.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Connector withCreatedAt(java.util.Date createdAt) {
        setCreatedAt(createdAt);
        return this;
    }

    /**
     * <p>
     * The date and time that the connector was updated.
     * </p>
     * 
     * @param updatedAt
     *        The date and time that the connector was updated.
     */

    public void setUpdatedAt(java.util.Date updatedAt) {
        this.updatedAt = updatedAt;
    }

    /**
     * <p>
     * The date and time that the connector was updated.
     * </p>
     * 
     * @return The date and time that the connector was updated.
     */

    public java.util.Date getUpdatedAt() {
        return this.updatedAt;
    }

    /**
     * <p>
     * The date and time that the connector was updated.
     * </p>
     * 
     * @param updatedAt
     *        The date and time that the connector was updated.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Connector withUpdatedAt(java.util.Date updatedAt) {
        setUpdatedAt(updatedAt);
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
        if (getCertificateAuthorityArn() != null)
            sb.append("CertificateAuthorityArn: ").append(getCertificateAuthorityArn()).append(",");
        if (getType() != null)
            sb.append("Type: ").append(getType()).append(",");
        if (getMobileDeviceManagement() != null)
            sb.append("MobileDeviceManagement: ").append(getMobileDeviceManagement()).append(",");
        if (getOpenIdConfiguration() != null)
            sb.append("OpenIdConfiguration: ").append(getOpenIdConfiguration()).append(",");
        if (getStatus() != null)
            sb.append("Status: ").append(getStatus()).append(",");
        if (getStatusReason() != null)
            sb.append("StatusReason: ").append(getStatusReason()).append(",");
        if (getEndpoint() != null)
            sb.append("Endpoint: ").append(getEndpoint()).append(",");
        if (getCreatedAt() != null)
            sb.append("CreatedAt: ").append(getCreatedAt()).append(",");
        if (getUpdatedAt() != null)
            sb.append("UpdatedAt: ").append(getUpdatedAt());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof Connector == false)
            return false;
        Connector other = (Connector) obj;
        if (other.getArn() == null ^ this.getArn() == null)
            return false;
        if (other.getArn() != null && other.getArn().equals(this.getArn()) == false)
            return false;
        if (other.getCertificateAuthorityArn() == null ^ this.getCertificateAuthorityArn() == null)
            return false;
        if (other.getCertificateAuthorityArn() != null && other.getCertificateAuthorityArn().equals(this.getCertificateAuthorityArn()) == false)
            return false;
        if (other.getType() == null ^ this.getType() == null)
            return false;
        if (other.getType() != null && other.getType().equals(this.getType()) == false)
            return false;
        if (other.getMobileDeviceManagement() == null ^ this.getMobileDeviceManagement() == null)
            return false;
        if (other.getMobileDeviceManagement() != null && other.getMobileDeviceManagement().equals(this.getMobileDeviceManagement()) == false)
            return false;
        if (other.getOpenIdConfiguration() == null ^ this.getOpenIdConfiguration() == null)
            return false;
        if (other.getOpenIdConfiguration() != null && other.getOpenIdConfiguration().equals(this.getOpenIdConfiguration()) == false)
            return false;
        if (other.getStatus() == null ^ this.getStatus() == null)
            return false;
        if (other.getStatus() != null && other.getStatus().equals(this.getStatus()) == false)
            return false;
        if (other.getStatusReason() == null ^ this.getStatusReason() == null)
            return false;
        if (other.getStatusReason() != null && other.getStatusReason().equals(this.getStatusReason()) == false)
            return false;
        if (other.getEndpoint() == null ^ this.getEndpoint() == null)
            return false;
        if (other.getEndpoint() != null && other.getEndpoint().equals(this.getEndpoint()) == false)
            return false;
        if (other.getCreatedAt() == null ^ this.getCreatedAt() == null)
            return false;
        if (other.getCreatedAt() != null && other.getCreatedAt().equals(this.getCreatedAt()) == false)
            return false;
        if (other.getUpdatedAt() == null ^ this.getUpdatedAt() == null)
            return false;
        if (other.getUpdatedAt() != null && other.getUpdatedAt().equals(this.getUpdatedAt()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getArn() == null) ? 0 : getArn().hashCode());
        hashCode = prime * hashCode + ((getCertificateAuthorityArn() == null) ? 0 : getCertificateAuthorityArn().hashCode());
        hashCode = prime * hashCode + ((getType() == null) ? 0 : getType().hashCode());
        hashCode = prime * hashCode + ((getMobileDeviceManagement() == null) ? 0 : getMobileDeviceManagement().hashCode());
        hashCode = prime * hashCode + ((getOpenIdConfiguration() == null) ? 0 : getOpenIdConfiguration().hashCode());
        hashCode = prime * hashCode + ((getStatus() == null) ? 0 : getStatus().hashCode());
        hashCode = prime * hashCode + ((getStatusReason() == null) ? 0 : getStatusReason().hashCode());
        hashCode = prime * hashCode + ((getEndpoint() == null) ? 0 : getEndpoint().hashCode());
        hashCode = prime * hashCode + ((getCreatedAt() == null) ? 0 : getCreatedAt().hashCode());
        hashCode = prime * hashCode + ((getUpdatedAt() == null) ? 0 : getUpdatedAt().hashCode());
        return hashCode;
    }

    @Override
    public Connector clone() {
        try {
            return (Connector) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.pcaconnectorscep.model.transform.ConnectorMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
