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
package com.amazonaws.services.macie2.model;

import java.io.Serializable;
import javax.annotation.Generated;

import com.amazonaws.AmazonWebServiceRequest;

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/macie2-2020-01-01/UpdateAutomatedDiscoveryConfiguration"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class UpdateAutomatedDiscoveryConfigurationRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * Specifies whether to automatically enable automated sensitive data discovery for accounts in the organization.
     * Valid values are: ALL (default), enable it for all existing accounts and new member accounts; NEW, enable it only
     * for new member accounts; and, NONE, don't enable it for any accounts.
     * </p>
     * <p>
     * If you specify NEW or NONE, automated sensitive data discovery continues to be enabled for any existing accounts
     * that it's currently enabled for. To enable or disable it for individual member accounts, specify NEW or NONE, and
     * then enable or disable it for each account by using the BatchUpdateAutomatedDiscoveryAccounts operation.
     * </p>
     */
    private String autoEnableOrganizationMembers;
    /**
     * <p>
     * The new status of automated sensitive data discovery for the organization or account. Valid values are: ENABLED,
     * start or resume all automated sensitive data discovery activities; and, DISABLED, stop performing all automated
     * sensitive data discovery activities.
     * </p>
     * <p>
     * If you specify DISABLED for an administrator account, you also disable automated sensitive data discovery for all
     * member accounts in the organization.
     * </p>
     */
    private String status;

    /**
     * <p>
     * Specifies whether to automatically enable automated sensitive data discovery for accounts in the organization.
     * Valid values are: ALL (default), enable it for all existing accounts and new member accounts; NEW, enable it only
     * for new member accounts; and, NONE, don't enable it for any accounts.
     * </p>
     * <p>
     * If you specify NEW or NONE, automated sensitive data discovery continues to be enabled for any existing accounts
     * that it's currently enabled for. To enable or disable it for individual member accounts, specify NEW or NONE, and
     * then enable or disable it for each account by using the BatchUpdateAutomatedDiscoveryAccounts operation.
     * </p>
     * 
     * @param autoEnableOrganizationMembers
     *        Specifies whether to automatically enable automated sensitive data discovery for accounts in the
     *        organization. Valid values are: ALL (default), enable it for all existing accounts and new member
     *        accounts; NEW, enable it only for new member accounts; and, NONE, don't enable it for any accounts.</p>
     *        <p>
     *        If you specify NEW or NONE, automated sensitive data discovery continues to be enabled for any existing
     *        accounts that it's currently enabled for. To enable or disable it for individual member accounts, specify
     *        NEW or NONE, and then enable or disable it for each account by using the
     *        BatchUpdateAutomatedDiscoveryAccounts operation.
     * @see AutoEnableMode
     */

    public void setAutoEnableOrganizationMembers(String autoEnableOrganizationMembers) {
        this.autoEnableOrganizationMembers = autoEnableOrganizationMembers;
    }

    /**
     * <p>
     * Specifies whether to automatically enable automated sensitive data discovery for accounts in the organization.
     * Valid values are: ALL (default), enable it for all existing accounts and new member accounts; NEW, enable it only
     * for new member accounts; and, NONE, don't enable it for any accounts.
     * </p>
     * <p>
     * If you specify NEW or NONE, automated sensitive data discovery continues to be enabled for any existing accounts
     * that it's currently enabled for. To enable or disable it for individual member accounts, specify NEW or NONE, and
     * then enable or disable it for each account by using the BatchUpdateAutomatedDiscoveryAccounts operation.
     * </p>
     * 
     * @return Specifies whether to automatically enable automated sensitive data discovery for accounts in the
     *         organization. Valid values are: ALL (default), enable it for all existing accounts and new member
     *         accounts; NEW, enable it only for new member accounts; and, NONE, don't enable it for any accounts.</p>
     *         <p>
     *         If you specify NEW or NONE, automated sensitive data discovery continues to be enabled for any existing
     *         accounts that it's currently enabled for. To enable or disable it for individual member accounts, specify
     *         NEW or NONE, and then enable or disable it for each account by using the
     *         BatchUpdateAutomatedDiscoveryAccounts operation.
     * @see AutoEnableMode
     */

    public String getAutoEnableOrganizationMembers() {
        return this.autoEnableOrganizationMembers;
    }

    /**
     * <p>
     * Specifies whether to automatically enable automated sensitive data discovery for accounts in the organization.
     * Valid values are: ALL (default), enable it for all existing accounts and new member accounts; NEW, enable it only
     * for new member accounts; and, NONE, don't enable it for any accounts.
     * </p>
     * <p>
     * If you specify NEW or NONE, automated sensitive data discovery continues to be enabled for any existing accounts
     * that it's currently enabled for. To enable or disable it for individual member accounts, specify NEW or NONE, and
     * then enable or disable it for each account by using the BatchUpdateAutomatedDiscoveryAccounts operation.
     * </p>
     * 
     * @param autoEnableOrganizationMembers
     *        Specifies whether to automatically enable automated sensitive data discovery for accounts in the
     *        organization. Valid values are: ALL (default), enable it for all existing accounts and new member
     *        accounts; NEW, enable it only for new member accounts; and, NONE, don't enable it for any accounts.</p>
     *        <p>
     *        If you specify NEW or NONE, automated sensitive data discovery continues to be enabled for any existing
     *        accounts that it's currently enabled for. To enable or disable it for individual member accounts, specify
     *        NEW or NONE, and then enable or disable it for each account by using the
     *        BatchUpdateAutomatedDiscoveryAccounts operation.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see AutoEnableMode
     */

    public UpdateAutomatedDiscoveryConfigurationRequest withAutoEnableOrganizationMembers(String autoEnableOrganizationMembers) {
        setAutoEnableOrganizationMembers(autoEnableOrganizationMembers);
        return this;
    }

    /**
     * <p>
     * Specifies whether to automatically enable automated sensitive data discovery for accounts in the organization.
     * Valid values are: ALL (default), enable it for all existing accounts and new member accounts; NEW, enable it only
     * for new member accounts; and, NONE, don't enable it for any accounts.
     * </p>
     * <p>
     * If you specify NEW or NONE, automated sensitive data discovery continues to be enabled for any existing accounts
     * that it's currently enabled for. To enable or disable it for individual member accounts, specify NEW or NONE, and
     * then enable or disable it for each account by using the BatchUpdateAutomatedDiscoveryAccounts operation.
     * </p>
     * 
     * @param autoEnableOrganizationMembers
     *        Specifies whether to automatically enable automated sensitive data discovery for accounts in the
     *        organization. Valid values are: ALL (default), enable it for all existing accounts and new member
     *        accounts; NEW, enable it only for new member accounts; and, NONE, don't enable it for any accounts.</p>
     *        <p>
     *        If you specify NEW or NONE, automated sensitive data discovery continues to be enabled for any existing
     *        accounts that it's currently enabled for. To enable or disable it for individual member accounts, specify
     *        NEW or NONE, and then enable or disable it for each account by using the
     *        BatchUpdateAutomatedDiscoveryAccounts operation.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see AutoEnableMode
     */

    public UpdateAutomatedDiscoveryConfigurationRequest withAutoEnableOrganizationMembers(AutoEnableMode autoEnableOrganizationMembers) {
        this.autoEnableOrganizationMembers = autoEnableOrganizationMembers.toString();
        return this;
    }

    /**
     * <p>
     * The new status of automated sensitive data discovery for the organization or account. Valid values are: ENABLED,
     * start or resume all automated sensitive data discovery activities; and, DISABLED, stop performing all automated
     * sensitive data discovery activities.
     * </p>
     * <p>
     * If you specify DISABLED for an administrator account, you also disable automated sensitive data discovery for all
     * member accounts in the organization.
     * </p>
     * 
     * @param status
     *        The new status of automated sensitive data discovery for the organization or account. Valid values are:
     *        ENABLED, start or resume all automated sensitive data discovery activities; and, DISABLED, stop performing
     *        all automated sensitive data discovery activities.</p>
     *        <p>
     *        If you specify DISABLED for an administrator account, you also disable automated sensitive data discovery
     *        for all member accounts in the organization.
     * @see AutomatedDiscoveryStatus
     */

    public void setStatus(String status) {
        this.status = status;
    }

    /**
     * <p>
     * The new status of automated sensitive data discovery for the organization or account. Valid values are: ENABLED,
     * start or resume all automated sensitive data discovery activities; and, DISABLED, stop performing all automated
     * sensitive data discovery activities.
     * </p>
     * <p>
     * If you specify DISABLED for an administrator account, you also disable automated sensitive data discovery for all
     * member accounts in the organization.
     * </p>
     * 
     * @return The new status of automated sensitive data discovery for the organization or account. Valid values are:
     *         ENABLED, start or resume all automated sensitive data discovery activities; and, DISABLED, stop
     *         performing all automated sensitive data discovery activities.</p>
     *         <p>
     *         If you specify DISABLED for an administrator account, you also disable automated sensitive data discovery
     *         for all member accounts in the organization.
     * @see AutomatedDiscoveryStatus
     */

    public String getStatus() {
        return this.status;
    }

    /**
     * <p>
     * The new status of automated sensitive data discovery for the organization or account. Valid values are: ENABLED,
     * start or resume all automated sensitive data discovery activities; and, DISABLED, stop performing all automated
     * sensitive data discovery activities.
     * </p>
     * <p>
     * If you specify DISABLED for an administrator account, you also disable automated sensitive data discovery for all
     * member accounts in the organization.
     * </p>
     * 
     * @param status
     *        The new status of automated sensitive data discovery for the organization or account. Valid values are:
     *        ENABLED, start or resume all automated sensitive data discovery activities; and, DISABLED, stop performing
     *        all automated sensitive data discovery activities.</p>
     *        <p>
     *        If you specify DISABLED for an administrator account, you also disable automated sensitive data discovery
     *        for all member accounts in the organization.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see AutomatedDiscoveryStatus
     */

    public UpdateAutomatedDiscoveryConfigurationRequest withStatus(String status) {
        setStatus(status);
        return this;
    }

    /**
     * <p>
     * The new status of automated sensitive data discovery for the organization or account. Valid values are: ENABLED,
     * start or resume all automated sensitive data discovery activities; and, DISABLED, stop performing all automated
     * sensitive data discovery activities.
     * </p>
     * <p>
     * If you specify DISABLED for an administrator account, you also disable automated sensitive data discovery for all
     * member accounts in the organization.
     * </p>
     * 
     * @param status
     *        The new status of automated sensitive data discovery for the organization or account. Valid values are:
     *        ENABLED, start or resume all automated sensitive data discovery activities; and, DISABLED, stop performing
     *        all automated sensitive data discovery activities.</p>
     *        <p>
     *        If you specify DISABLED for an administrator account, you also disable automated sensitive data discovery
     *        for all member accounts in the organization.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see AutomatedDiscoveryStatus
     */

    public UpdateAutomatedDiscoveryConfigurationRequest withStatus(AutomatedDiscoveryStatus status) {
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
        if (getAutoEnableOrganizationMembers() != null)
            sb.append("AutoEnableOrganizationMembers: ").append(getAutoEnableOrganizationMembers()).append(",");
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

        if (obj instanceof UpdateAutomatedDiscoveryConfigurationRequest == false)
            return false;
        UpdateAutomatedDiscoveryConfigurationRequest other = (UpdateAutomatedDiscoveryConfigurationRequest) obj;
        if (other.getAutoEnableOrganizationMembers() == null ^ this.getAutoEnableOrganizationMembers() == null)
            return false;
        if (other.getAutoEnableOrganizationMembers() != null
                && other.getAutoEnableOrganizationMembers().equals(this.getAutoEnableOrganizationMembers()) == false)
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

        hashCode = prime * hashCode + ((getAutoEnableOrganizationMembers() == null) ? 0 : getAutoEnableOrganizationMembers().hashCode());
        hashCode = prime * hashCode + ((getStatus() == null) ? 0 : getStatus().hashCode());
        return hashCode;
    }

    @Override
    public UpdateAutomatedDiscoveryConfigurationRequest clone() {
        return (UpdateAutomatedDiscoveryConfigurationRequest) super.clone();
    }

}
