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

import com.amazonaws.AmazonWebServiceRequest;

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/CreateConnector" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class CreateConnectorRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the Amazon Web Services Private Certificate Authority certificate authority to
     * use with this connector. Due to security vulnerabilities present in the SCEP protocol, we recommend using a
     * private CA that's dedicated for use with the connector.
     * </p>
     * <p>
     * To retrieve the private CAs associated with your account, you can call <a
     * href="https://docs.aws.amazon.com/privateca/latest/APIReference/API_ListCertificateAuthorities.html"
     * >ListCertificateAuthorities</a> using the Amazon Web Services Private CA API.
     * </p>
     */
    private String certificateAuthorityArn;
    /**
     * <p>
     * If you don't supply a value, by default Connector for SCEP creates a connector for general-purpose use. A
     * general-purpose connector is designed to work with clients or endpoints that support the SCEP protocol, except
     * Connector for SCEP for Microsoft Intune. With connectors for general-purpose use, you manage SCEP challenge
     * passwords using Connector for SCEP. For information about considerations and limitations with using Connector for
     * SCEP, see <a href=
     * "https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlc4scep-considerations-limitations.html"
     * >Considerations and Limitations</a>.
     * </p>
     * <p>
     * If you provide an <code>IntuneConfiguration</code>, Connector for SCEP creates a connector for use with Microsoft
     * Intune, and you manage the challenge passwords using Microsoft Intune. For more information, see <a
     * href="https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlconnector-for-scep-intune.html"
     * >Using Connector for SCEP for Microsoft Intune</a>.
     * </p>
     */
    private MobileDeviceManagement mobileDeviceManagement;
    /**
     * <p>
     * Custom string that can be used to distinguish between calls to the <a
     * href="https://docs.aws.amazon.com/C4SCEP_API/pca-connector-scep/latest/APIReference/API_CreateChallenge.html"
     * >CreateChallenge</a> action. Client tokens for <code>CreateChallenge</code> time out after five minutes.
     * Therefore, if you call <code>CreateChallenge</code> multiple times with the same client token within five
     * minutes, Connector for SCEP recognizes that you are requesting only one challenge and will only respond with one.
     * If you change the client token for each call, Connector for SCEP recognizes that you are requesting multiple
     * challenge passwords.
     * </p>
     */
    private String clientToken;
    /**
     * <p>
     * The key-value pairs to associate with the resource.
     * </p>
     */
    private java.util.Map<String, String> tags;

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the Amazon Web Services Private Certificate Authority certificate authority to
     * use with this connector. Due to security vulnerabilities present in the SCEP protocol, we recommend using a
     * private CA that's dedicated for use with the connector.
     * </p>
     * <p>
     * To retrieve the private CAs associated with your account, you can call <a
     * href="https://docs.aws.amazon.com/privateca/latest/APIReference/API_ListCertificateAuthorities.html"
     * >ListCertificateAuthorities</a> using the Amazon Web Services Private CA API.
     * </p>
     * 
     * @param certificateAuthorityArn
     *        The Amazon Resource Name (ARN) of the Amazon Web Services Private Certificate Authority certificate
     *        authority to use with this connector. Due to security vulnerabilities present in the SCEP protocol, we
     *        recommend using a private CA that's dedicated for use with the connector.</p>
     *        <p>
     *        To retrieve the private CAs associated with your account, you can call <a
     *        href="https://docs.aws.amazon.com/privateca/latest/APIReference/API_ListCertificateAuthorities.html"
     *        >ListCertificateAuthorities</a> using the Amazon Web Services Private CA API.
     */

    public void setCertificateAuthorityArn(String certificateAuthorityArn) {
        this.certificateAuthorityArn = certificateAuthorityArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the Amazon Web Services Private Certificate Authority certificate authority to
     * use with this connector. Due to security vulnerabilities present in the SCEP protocol, we recommend using a
     * private CA that's dedicated for use with the connector.
     * </p>
     * <p>
     * To retrieve the private CAs associated with your account, you can call <a
     * href="https://docs.aws.amazon.com/privateca/latest/APIReference/API_ListCertificateAuthorities.html"
     * >ListCertificateAuthorities</a> using the Amazon Web Services Private CA API.
     * </p>
     * 
     * @return The Amazon Resource Name (ARN) of the Amazon Web Services Private Certificate Authority certificate
     *         authority to use with this connector. Due to security vulnerabilities present in the SCEP protocol, we
     *         recommend using a private CA that's dedicated for use with the connector.</p>
     *         <p>
     *         To retrieve the private CAs associated with your account, you can call <a
     *         href="https://docs.aws.amazon.com/privateca/latest/APIReference/API_ListCertificateAuthorities.html"
     *         >ListCertificateAuthorities</a> using the Amazon Web Services Private CA API.
     */

    public String getCertificateAuthorityArn() {
        return this.certificateAuthorityArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the Amazon Web Services Private Certificate Authority certificate authority to
     * use with this connector. Due to security vulnerabilities present in the SCEP protocol, we recommend using a
     * private CA that's dedicated for use with the connector.
     * </p>
     * <p>
     * To retrieve the private CAs associated with your account, you can call <a
     * href="https://docs.aws.amazon.com/privateca/latest/APIReference/API_ListCertificateAuthorities.html"
     * >ListCertificateAuthorities</a> using the Amazon Web Services Private CA API.
     * </p>
     * 
     * @param certificateAuthorityArn
     *        The Amazon Resource Name (ARN) of the Amazon Web Services Private Certificate Authority certificate
     *        authority to use with this connector. Due to security vulnerabilities present in the SCEP protocol, we
     *        recommend using a private CA that's dedicated for use with the connector.</p>
     *        <p>
     *        To retrieve the private CAs associated with your account, you can call <a
     *        href="https://docs.aws.amazon.com/privateca/latest/APIReference/API_ListCertificateAuthorities.html"
     *        >ListCertificateAuthorities</a> using the Amazon Web Services Private CA API.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateConnectorRequest withCertificateAuthorityArn(String certificateAuthorityArn) {
        setCertificateAuthorityArn(certificateAuthorityArn);
        return this;
    }

    /**
     * <p>
     * If you don't supply a value, by default Connector for SCEP creates a connector for general-purpose use. A
     * general-purpose connector is designed to work with clients or endpoints that support the SCEP protocol, except
     * Connector for SCEP for Microsoft Intune. With connectors for general-purpose use, you manage SCEP challenge
     * passwords using Connector for SCEP. For information about considerations and limitations with using Connector for
     * SCEP, see <a href=
     * "https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlc4scep-considerations-limitations.html"
     * >Considerations and Limitations</a>.
     * </p>
     * <p>
     * If you provide an <code>IntuneConfiguration</code>, Connector for SCEP creates a connector for use with Microsoft
     * Intune, and you manage the challenge passwords using Microsoft Intune. For more information, see <a
     * href="https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlconnector-for-scep-intune.html"
     * >Using Connector for SCEP for Microsoft Intune</a>.
     * </p>
     * 
     * @param mobileDeviceManagement
     *        If you don't supply a value, by default Connector for SCEP creates a connector for general-purpose use. A
     *        general-purpose connector is designed to work with clients or endpoints that support the SCEP protocol,
     *        except Connector for SCEP for Microsoft Intune. With connectors for general-purpose use, you manage SCEP
     *        challenge passwords using Connector for SCEP. For information about considerations and limitations with
     *        using Connector for SCEP, see <a href=
     *        "https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlc4scep-considerations-limitations.html"
     *        >Considerations and Limitations</a>.</p>
     *        <p>
     *        If you provide an <code>IntuneConfiguration</code>, Connector for SCEP creates a connector for use with
     *        Microsoft Intune, and you manage the challenge passwords using Microsoft Intune. For more information, see
     *        <a href=
     *        "https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlconnector-for-scep-intune.html"
     *        >Using Connector for SCEP for Microsoft Intune</a>.
     */

    public void setMobileDeviceManagement(MobileDeviceManagement mobileDeviceManagement) {
        this.mobileDeviceManagement = mobileDeviceManagement;
    }

    /**
     * <p>
     * If you don't supply a value, by default Connector for SCEP creates a connector for general-purpose use. A
     * general-purpose connector is designed to work with clients or endpoints that support the SCEP protocol, except
     * Connector for SCEP for Microsoft Intune. With connectors for general-purpose use, you manage SCEP challenge
     * passwords using Connector for SCEP. For information about considerations and limitations with using Connector for
     * SCEP, see <a href=
     * "https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlc4scep-considerations-limitations.html"
     * >Considerations and Limitations</a>.
     * </p>
     * <p>
     * If you provide an <code>IntuneConfiguration</code>, Connector for SCEP creates a connector for use with Microsoft
     * Intune, and you manage the challenge passwords using Microsoft Intune. For more information, see <a
     * href="https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlconnector-for-scep-intune.html"
     * >Using Connector for SCEP for Microsoft Intune</a>.
     * </p>
     * 
     * @return If you don't supply a value, by default Connector for SCEP creates a connector for general-purpose use. A
     *         general-purpose connector is designed to work with clients or endpoints that support the SCEP protocol,
     *         except Connector for SCEP for Microsoft Intune. With connectors for general-purpose use, you manage SCEP
     *         challenge passwords using Connector for SCEP. For information about considerations and limitations with
     *         using Connector for SCEP, see <a href=
     *         "https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlc4scep-considerations-limitations.html"
     *         >Considerations and Limitations</a>.</p>
     *         <p>
     *         If you provide an <code>IntuneConfiguration</code>, Connector for SCEP creates a connector for use with
     *         Microsoft Intune, and you manage the challenge passwords using Microsoft Intune. For more information,
     *         see <a href=
     *         "https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlconnector-for-scep-intune.html"
     *         >Using Connector for SCEP for Microsoft Intune</a>.
     */

    public MobileDeviceManagement getMobileDeviceManagement() {
        return this.mobileDeviceManagement;
    }

    /**
     * <p>
     * If you don't supply a value, by default Connector for SCEP creates a connector for general-purpose use. A
     * general-purpose connector is designed to work with clients or endpoints that support the SCEP protocol, except
     * Connector for SCEP for Microsoft Intune. With connectors for general-purpose use, you manage SCEP challenge
     * passwords using Connector for SCEP. For information about considerations and limitations with using Connector for
     * SCEP, see <a href=
     * "https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlc4scep-considerations-limitations.html"
     * >Considerations and Limitations</a>.
     * </p>
     * <p>
     * If you provide an <code>IntuneConfiguration</code>, Connector for SCEP creates a connector for use with Microsoft
     * Intune, and you manage the challenge passwords using Microsoft Intune. For more information, see <a
     * href="https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlconnector-for-scep-intune.html"
     * >Using Connector for SCEP for Microsoft Intune</a>.
     * </p>
     * 
     * @param mobileDeviceManagement
     *        If you don't supply a value, by default Connector for SCEP creates a connector for general-purpose use. A
     *        general-purpose connector is designed to work with clients or endpoints that support the SCEP protocol,
     *        except Connector for SCEP for Microsoft Intune. With connectors for general-purpose use, you manage SCEP
     *        challenge passwords using Connector for SCEP. For information about considerations and limitations with
     *        using Connector for SCEP, see <a href=
     *        "https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlc4scep-considerations-limitations.html"
     *        >Considerations and Limitations</a>.</p>
     *        <p>
     *        If you provide an <code>IntuneConfiguration</code>, Connector for SCEP creates a connector for use with
     *        Microsoft Intune, and you manage the challenge passwords using Microsoft Intune. For more information, see
     *        <a href=
     *        "https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlconnector-for-scep-intune.html"
     *        >Using Connector for SCEP for Microsoft Intune</a>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateConnectorRequest withMobileDeviceManagement(MobileDeviceManagement mobileDeviceManagement) {
        setMobileDeviceManagement(mobileDeviceManagement);
        return this;
    }

    /**
     * <p>
     * Custom string that can be used to distinguish between calls to the <a
     * href="https://docs.aws.amazon.com/C4SCEP_API/pca-connector-scep/latest/APIReference/API_CreateChallenge.html"
     * >CreateChallenge</a> action. Client tokens for <code>CreateChallenge</code> time out after five minutes.
     * Therefore, if you call <code>CreateChallenge</code> multiple times with the same client token within five
     * minutes, Connector for SCEP recognizes that you are requesting only one challenge and will only respond with one.
     * If you change the client token for each call, Connector for SCEP recognizes that you are requesting multiple
     * challenge passwords.
     * </p>
     * 
     * @param clientToken
     *        Custom string that can be used to distinguish between calls to the <a href=
     *        "https://docs.aws.amazon.com/C4SCEP_API/pca-connector-scep/latest/APIReference/API_CreateChallenge.html"
     *        >CreateChallenge</a> action. Client tokens for <code>CreateChallenge</code> time out after five minutes.
     *        Therefore, if you call <code>CreateChallenge</code> multiple times with the same client token within five
     *        minutes, Connector for SCEP recognizes that you are requesting only one challenge and will only respond
     *        with one. If you change the client token for each call, Connector for SCEP recognizes that you are
     *        requesting multiple challenge passwords.
     */

    public void setClientToken(String clientToken) {
        this.clientToken = clientToken;
    }

    /**
     * <p>
     * Custom string that can be used to distinguish between calls to the <a
     * href="https://docs.aws.amazon.com/C4SCEP_API/pca-connector-scep/latest/APIReference/API_CreateChallenge.html"
     * >CreateChallenge</a> action. Client tokens for <code>CreateChallenge</code> time out after five minutes.
     * Therefore, if you call <code>CreateChallenge</code> multiple times with the same client token within five
     * minutes, Connector for SCEP recognizes that you are requesting only one challenge and will only respond with one.
     * If you change the client token for each call, Connector for SCEP recognizes that you are requesting multiple
     * challenge passwords.
     * </p>
     * 
     * @return Custom string that can be used to distinguish between calls to the <a
     *         href="https://docs.aws.amazon.com/C4SCEP_API/pca-connector-scep/latest/APIReference/API_CreateChallenge.html"
     *         >CreateChallenge</a> action. Client tokens for <code>CreateChallenge</code> time out after five minutes.
     *         Therefore, if you call <code>CreateChallenge</code> multiple times with the same client token within five
     *         minutes, Connector for SCEP recognizes that you are requesting only one challenge and will only respond
     *         with one. If you change the client token for each call, Connector for SCEP recognizes that you are
     *         requesting multiple challenge passwords.
     */

    public String getClientToken() {
        return this.clientToken;
    }

    /**
     * <p>
     * Custom string that can be used to distinguish between calls to the <a
     * href="https://docs.aws.amazon.com/C4SCEP_API/pca-connector-scep/latest/APIReference/API_CreateChallenge.html"
     * >CreateChallenge</a> action. Client tokens for <code>CreateChallenge</code> time out after five minutes.
     * Therefore, if you call <code>CreateChallenge</code> multiple times with the same client token within five
     * minutes, Connector for SCEP recognizes that you are requesting only one challenge and will only respond with one.
     * If you change the client token for each call, Connector for SCEP recognizes that you are requesting multiple
     * challenge passwords.
     * </p>
     * 
     * @param clientToken
     *        Custom string that can be used to distinguish between calls to the <a href=
     *        "https://docs.aws.amazon.com/C4SCEP_API/pca-connector-scep/latest/APIReference/API_CreateChallenge.html"
     *        >CreateChallenge</a> action. Client tokens for <code>CreateChallenge</code> time out after five minutes.
     *        Therefore, if you call <code>CreateChallenge</code> multiple times with the same client token within five
     *        minutes, Connector for SCEP recognizes that you are requesting only one challenge and will only respond
     *        with one. If you change the client token for each call, Connector for SCEP recognizes that you are
     *        requesting multiple challenge passwords.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateConnectorRequest withClientToken(String clientToken) {
        setClientToken(clientToken);
        return this;
    }

    /**
     * <p>
     * The key-value pairs to associate with the resource.
     * </p>
     * 
     * @return The key-value pairs to associate with the resource.
     */

    public java.util.Map<String, String> getTags() {
        return tags;
    }

    /**
     * <p>
     * The key-value pairs to associate with the resource.
     * </p>
     * 
     * @param tags
     *        The key-value pairs to associate with the resource.
     */

    public void setTags(java.util.Map<String, String> tags) {
        this.tags = tags;
    }

    /**
     * <p>
     * The key-value pairs to associate with the resource.
     * </p>
     * 
     * @param tags
     *        The key-value pairs to associate with the resource.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateConnectorRequest withTags(java.util.Map<String, String> tags) {
        setTags(tags);
        return this;
    }

    /**
     * Add a single Tags entry
     *
     * @see CreateConnectorRequest#withTags
     * @returns a reference to this object so that method calls can be chained together.
     */

    public CreateConnectorRequest addTagsEntry(String key, String value) {
        if (null == this.tags) {
            this.tags = new java.util.HashMap<String, String>();
        }
        if (this.tags.containsKey(key))
            throw new IllegalArgumentException("Duplicated keys (" + key.toString() + ") are provided.");
        this.tags.put(key, value);
        return this;
    }

    /**
     * Removes all the entries added into Tags.
     *
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateConnectorRequest clearTagsEntries() {
        this.tags = null;
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
        if (getCertificateAuthorityArn() != null)
            sb.append("CertificateAuthorityArn: ").append(getCertificateAuthorityArn()).append(",");
        if (getMobileDeviceManagement() != null)
            sb.append("MobileDeviceManagement: ").append(getMobileDeviceManagement()).append(",");
        if (getClientToken() != null)
            sb.append("ClientToken: ").append(getClientToken()).append(",");
        if (getTags() != null)
            sb.append("Tags: ").append(getTags());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof CreateConnectorRequest == false)
            return false;
        CreateConnectorRequest other = (CreateConnectorRequest) obj;
        if (other.getCertificateAuthorityArn() == null ^ this.getCertificateAuthorityArn() == null)
            return false;
        if (other.getCertificateAuthorityArn() != null && other.getCertificateAuthorityArn().equals(this.getCertificateAuthorityArn()) == false)
            return false;
        if (other.getMobileDeviceManagement() == null ^ this.getMobileDeviceManagement() == null)
            return false;
        if (other.getMobileDeviceManagement() != null && other.getMobileDeviceManagement().equals(this.getMobileDeviceManagement()) == false)
            return false;
        if (other.getClientToken() == null ^ this.getClientToken() == null)
            return false;
        if (other.getClientToken() != null && other.getClientToken().equals(this.getClientToken()) == false)
            return false;
        if (other.getTags() == null ^ this.getTags() == null)
            return false;
        if (other.getTags() != null && other.getTags().equals(this.getTags()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getCertificateAuthorityArn() == null) ? 0 : getCertificateAuthorityArn().hashCode());
        hashCode = prime * hashCode + ((getMobileDeviceManagement() == null) ? 0 : getMobileDeviceManagement().hashCode());
        hashCode = prime * hashCode + ((getClientToken() == null) ? 0 : getClientToken().hashCode());
        hashCode = prime * hashCode + ((getTags() == null) ? 0 : getTags().hashCode());
        return hashCode;
    }

    @Override
    public CreateConnectorRequest clone() {
        return (CreateConnectorRequest) super.clone();
    }

}
