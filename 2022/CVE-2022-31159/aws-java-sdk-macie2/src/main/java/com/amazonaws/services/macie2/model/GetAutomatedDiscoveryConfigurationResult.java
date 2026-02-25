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

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/macie2-2020-01-01/GetAutomatedDiscoveryConfiguration"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class GetAutomatedDiscoveryConfigurationResult extends com.amazonaws.AmazonWebServiceResult<com.amazonaws.ResponseMetadata> implements Serializable,
        Cloneable {

    /**
     * <p>
     * Specifies whether automated sensitive data discovery is enabled automatically for accounts in the organization.
     * Possible values are: ALL, enable it for all existing accounts and new member accounts; NEW, enable it only for
     * new member accounts; and, NONE, don't enable it for any accounts.
     * </p>
     */
    private String autoEnableOrganizationMembers;
    /**
     * <p>
     * The unique identifier for the classification scope that's used when performing automated sensitive data
     * discovery. The classification scope specifies S3 buckets to exclude from analyses.
     * </p>
     */
    private String classificationScopeId;
    /**
     * <p>
     * The date and time, in UTC and extended ISO 8601 format, when automated sensitive data discovery was most recently
     * disabled. This value is null if automated sensitive data discovery is currently enabled.
     * </p>
     */
    private java.util.Date disabledAt;
    /**
     * <p>
     * The date and time, in UTC and extended ISO 8601 format, when automated sensitive data discovery was initially
     * enabled. This value is null if automated sensitive data discovery has never been enabled.
     * </p>
     */
    private java.util.Date firstEnabledAt;
    /**
     * <p>
     * The date and time, in UTC and extended ISO 8601 format, when the configuration settings or status of automated
     * sensitive data discovery was most recently changed.
     * </p>
     */
    private java.util.Date lastUpdatedAt;
    /**
     * <p>
     * The unique identifier for the sensitivity inspection template that's used when performing automated sensitive
     * data discovery. The template specifies which allow lists, custom data identifiers, and managed data identifiers
     * to use when analyzing data.
     * </p>
     */
    private String sensitivityInspectionTemplateId;
    /**
     * <p>
     * The current status of automated sensitive data discovery for the organization or account. Possible values are:
     * ENABLED, use the specified settings to perform automated sensitive data discovery activities; and, DISABLED,
     * don't perform automated sensitive data discovery activities.
     * </p>
     */
    private String status;

    /**
     * <p>
     * Specifies whether automated sensitive data discovery is enabled automatically for accounts in the organization.
     * Possible values are: ALL, enable it for all existing accounts and new member accounts; NEW, enable it only for
     * new member accounts; and, NONE, don't enable it for any accounts.
     * </p>
     * 
     * @param autoEnableOrganizationMembers
     *        Specifies whether automated sensitive data discovery is enabled automatically for accounts in the
     *        organization. Possible values are: ALL, enable it for all existing accounts and new member accounts; NEW,
     *        enable it only for new member accounts; and, NONE, don't enable it for any accounts.
     * @see AutoEnableMode
     */

    public void setAutoEnableOrganizationMembers(String autoEnableOrganizationMembers) {
        this.autoEnableOrganizationMembers = autoEnableOrganizationMembers;
    }

    /**
     * <p>
     * Specifies whether automated sensitive data discovery is enabled automatically for accounts in the organization.
     * Possible values are: ALL, enable it for all existing accounts and new member accounts; NEW, enable it only for
     * new member accounts; and, NONE, don't enable it for any accounts.
     * </p>
     * 
     * @return Specifies whether automated sensitive data discovery is enabled automatically for accounts in the
     *         organization. Possible values are: ALL, enable it for all existing accounts and new member accounts; NEW,
     *         enable it only for new member accounts; and, NONE, don't enable it for any accounts.
     * @see AutoEnableMode
     */

    public String getAutoEnableOrganizationMembers() {
        return this.autoEnableOrganizationMembers;
    }

    /**
     * <p>
     * Specifies whether automated sensitive data discovery is enabled automatically for accounts in the organization.
     * Possible values are: ALL, enable it for all existing accounts and new member accounts; NEW, enable it only for
     * new member accounts; and, NONE, don't enable it for any accounts.
     * </p>
     * 
     * @param autoEnableOrganizationMembers
     *        Specifies whether automated sensitive data discovery is enabled automatically for accounts in the
     *        organization. Possible values are: ALL, enable it for all existing accounts and new member accounts; NEW,
     *        enable it only for new member accounts; and, NONE, don't enable it for any accounts.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see AutoEnableMode
     */

    public GetAutomatedDiscoveryConfigurationResult withAutoEnableOrganizationMembers(String autoEnableOrganizationMembers) {
        setAutoEnableOrganizationMembers(autoEnableOrganizationMembers);
        return this;
    }

    /**
     * <p>
     * Specifies whether automated sensitive data discovery is enabled automatically for accounts in the organization.
     * Possible values are: ALL, enable it for all existing accounts and new member accounts; NEW, enable it only for
     * new member accounts; and, NONE, don't enable it for any accounts.
     * </p>
     * 
     * @param autoEnableOrganizationMembers
     *        Specifies whether automated sensitive data discovery is enabled automatically for accounts in the
     *        organization. Possible values are: ALL, enable it for all existing accounts and new member accounts; NEW,
     *        enable it only for new member accounts; and, NONE, don't enable it for any accounts.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see AutoEnableMode
     */

    public GetAutomatedDiscoveryConfigurationResult withAutoEnableOrganizationMembers(AutoEnableMode autoEnableOrganizationMembers) {
        this.autoEnableOrganizationMembers = autoEnableOrganizationMembers.toString();
        return this;
    }

    /**
     * <p>
     * The unique identifier for the classification scope that's used when performing automated sensitive data
     * discovery. The classification scope specifies S3 buckets to exclude from analyses.
     * </p>
     * 
     * @param classificationScopeId
     *        The unique identifier for the classification scope that's used when performing automated sensitive data
     *        discovery. The classification scope specifies S3 buckets to exclude from analyses.
     */

    public void setClassificationScopeId(String classificationScopeId) {
        this.classificationScopeId = classificationScopeId;
    }

    /**
     * <p>
     * The unique identifier for the classification scope that's used when performing automated sensitive data
     * discovery. The classification scope specifies S3 buckets to exclude from analyses.
     * </p>
     * 
     * @return The unique identifier for the classification scope that's used when performing automated sensitive data
     *         discovery. The classification scope specifies S3 buckets to exclude from analyses.
     */

    public String getClassificationScopeId() {
        return this.classificationScopeId;
    }

    /**
     * <p>
     * The unique identifier for the classification scope that's used when performing automated sensitive data
     * discovery. The classification scope specifies S3 buckets to exclude from analyses.
     * </p>
     * 
     * @param classificationScopeId
     *        The unique identifier for the classification scope that's used when performing automated sensitive data
     *        discovery. The classification scope specifies S3 buckets to exclude from analyses.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public GetAutomatedDiscoveryConfigurationResult withClassificationScopeId(String classificationScopeId) {
        setClassificationScopeId(classificationScopeId);
        return this;
    }

    /**
     * <p>
     * The date and time, in UTC and extended ISO 8601 format, when automated sensitive data discovery was most recently
     * disabled. This value is null if automated sensitive data discovery is currently enabled.
     * </p>
     * 
     * @param disabledAt
     *        The date and time, in UTC and extended ISO 8601 format, when automated sensitive data discovery was most
     *        recently disabled. This value is null if automated sensitive data discovery is currently enabled.
     */

    public void setDisabledAt(java.util.Date disabledAt) {
        this.disabledAt = disabledAt;
    }

    /**
     * <p>
     * The date and time, in UTC and extended ISO 8601 format, when automated sensitive data discovery was most recently
     * disabled. This value is null if automated sensitive data discovery is currently enabled.
     * </p>
     * 
     * @return The date and time, in UTC and extended ISO 8601 format, when automated sensitive data discovery was most
     *         recently disabled. This value is null if automated sensitive data discovery is currently enabled.
     */

    public java.util.Date getDisabledAt() {
        return this.disabledAt;
    }

    /**
     * <p>
     * The date and time, in UTC and extended ISO 8601 format, when automated sensitive data discovery was most recently
     * disabled. This value is null if automated sensitive data discovery is currently enabled.
     * </p>
     * 
     * @param disabledAt
     *        The date and time, in UTC and extended ISO 8601 format, when automated sensitive data discovery was most
     *        recently disabled. This value is null if automated sensitive data discovery is currently enabled.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public GetAutomatedDiscoveryConfigurationResult withDisabledAt(java.util.Date disabledAt) {
        setDisabledAt(disabledAt);
        return this;
    }

    /**
     * <p>
     * The date and time, in UTC and extended ISO 8601 format, when automated sensitive data discovery was initially
     * enabled. This value is null if automated sensitive data discovery has never been enabled.
     * </p>
     * 
     * @param firstEnabledAt
     *        The date and time, in UTC and extended ISO 8601 format, when automated sensitive data discovery was
     *        initially enabled. This value is null if automated sensitive data discovery has never been enabled.
     */

    public void setFirstEnabledAt(java.util.Date firstEnabledAt) {
        this.firstEnabledAt = firstEnabledAt;
    }

    /**
     * <p>
     * The date and time, in UTC and extended ISO 8601 format, when automated sensitive data discovery was initially
     * enabled. This value is null if automated sensitive data discovery has never been enabled.
     * </p>
     * 
     * @return The date and time, in UTC and extended ISO 8601 format, when automated sensitive data discovery was
     *         initially enabled. This value is null if automated sensitive data discovery has never been enabled.
     */

    public java.util.Date getFirstEnabledAt() {
        return this.firstEnabledAt;
    }

    /**
     * <p>
     * The date and time, in UTC and extended ISO 8601 format, when automated sensitive data discovery was initially
     * enabled. This value is null if automated sensitive data discovery has never been enabled.
     * </p>
     * 
     * @param firstEnabledAt
     *        The date and time, in UTC and extended ISO 8601 format, when automated sensitive data discovery was
     *        initially enabled. This value is null if automated sensitive data discovery has never been enabled.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public GetAutomatedDiscoveryConfigurationResult withFirstEnabledAt(java.util.Date firstEnabledAt) {
        setFirstEnabledAt(firstEnabledAt);
        return this;
    }

    /**
     * <p>
     * The date and time, in UTC and extended ISO 8601 format, when the configuration settings or status of automated
     * sensitive data discovery was most recently changed.
     * </p>
     * 
     * @param lastUpdatedAt
     *        The date and time, in UTC and extended ISO 8601 format, when the configuration settings or status of
     *        automated sensitive data discovery was most recently changed.
     */

    public void setLastUpdatedAt(java.util.Date lastUpdatedAt) {
        this.lastUpdatedAt = lastUpdatedAt;
    }

    /**
     * <p>
     * The date and time, in UTC and extended ISO 8601 format, when the configuration settings or status of automated
     * sensitive data discovery was most recently changed.
     * </p>
     * 
     * @return The date and time, in UTC and extended ISO 8601 format, when the configuration settings or status of
     *         automated sensitive data discovery was most recently changed.
     */

    public java.util.Date getLastUpdatedAt() {
        return this.lastUpdatedAt;
    }

    /**
     * <p>
     * The date and time, in UTC and extended ISO 8601 format, when the configuration settings or status of automated
     * sensitive data discovery was most recently changed.
     * </p>
     * 
     * @param lastUpdatedAt
     *        The date and time, in UTC and extended ISO 8601 format, when the configuration settings or status of
     *        automated sensitive data discovery was most recently changed.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public GetAutomatedDiscoveryConfigurationResult withLastUpdatedAt(java.util.Date lastUpdatedAt) {
        setLastUpdatedAt(lastUpdatedAt);
        return this;
    }

    /**
     * <p>
     * The unique identifier for the sensitivity inspection template that's used when performing automated sensitive
     * data discovery. The template specifies which allow lists, custom data identifiers, and managed data identifiers
     * to use when analyzing data.
     * </p>
     * 
     * @param sensitivityInspectionTemplateId
     *        The unique identifier for the sensitivity inspection template that's used when performing automated
     *        sensitive data discovery. The template specifies which allow lists, custom data identifiers, and managed
     *        data identifiers to use when analyzing data.
     */

    public void setSensitivityInspectionTemplateId(String sensitivityInspectionTemplateId) {
        this.sensitivityInspectionTemplateId = sensitivityInspectionTemplateId;
    }

    /**
     * <p>
     * The unique identifier for the sensitivity inspection template that's used when performing automated sensitive
     * data discovery. The template specifies which allow lists, custom data identifiers, and managed data identifiers
     * to use when analyzing data.
     * </p>
     * 
     * @return The unique identifier for the sensitivity inspection template that's used when performing automated
     *         sensitive data discovery. The template specifies which allow lists, custom data identifiers, and managed
     *         data identifiers to use when analyzing data.
     */

    public String getSensitivityInspectionTemplateId() {
        return this.sensitivityInspectionTemplateId;
    }

    /**
     * <p>
     * The unique identifier for the sensitivity inspection template that's used when performing automated sensitive
     * data discovery. The template specifies which allow lists, custom data identifiers, and managed data identifiers
     * to use when analyzing data.
     * </p>
     * 
     * @param sensitivityInspectionTemplateId
     *        The unique identifier for the sensitivity inspection template that's used when performing automated
     *        sensitive data discovery. The template specifies which allow lists, custom data identifiers, and managed
     *        data identifiers to use when analyzing data.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public GetAutomatedDiscoveryConfigurationResult withSensitivityInspectionTemplateId(String sensitivityInspectionTemplateId) {
        setSensitivityInspectionTemplateId(sensitivityInspectionTemplateId);
        return this;
    }

    /**
     * <p>
     * The current status of automated sensitive data discovery for the organization or account. Possible values are:
     * ENABLED, use the specified settings to perform automated sensitive data discovery activities; and, DISABLED,
     * don't perform automated sensitive data discovery activities.
     * </p>
     * 
     * @param status
     *        The current status of automated sensitive data discovery for the organization or account. Possible values
     *        are: ENABLED, use the specified settings to perform automated sensitive data discovery activities; and,
     *        DISABLED, don't perform automated sensitive data discovery activities.
     * @see AutomatedDiscoveryStatus
     */

    public void setStatus(String status) {
        this.status = status;
    }

    /**
     * <p>
     * The current status of automated sensitive data discovery for the organization or account. Possible values are:
     * ENABLED, use the specified settings to perform automated sensitive data discovery activities; and, DISABLED,
     * don't perform automated sensitive data discovery activities.
     * </p>
     * 
     * @return The current status of automated sensitive data discovery for the organization or account. Possible values
     *         are: ENABLED, use the specified settings to perform automated sensitive data discovery activities; and,
     *         DISABLED, don't perform automated sensitive data discovery activities.
     * @see AutomatedDiscoveryStatus
     */

    public String getStatus() {
        return this.status;
    }

    /**
     * <p>
     * The current status of automated sensitive data discovery for the organization or account. Possible values are:
     * ENABLED, use the specified settings to perform automated sensitive data discovery activities; and, DISABLED,
     * don't perform automated sensitive data discovery activities.
     * </p>
     * 
     * @param status
     *        The current status of automated sensitive data discovery for the organization or account. Possible values
     *        are: ENABLED, use the specified settings to perform automated sensitive data discovery activities; and,
     *        DISABLED, don't perform automated sensitive data discovery activities.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see AutomatedDiscoveryStatus
     */

    public GetAutomatedDiscoveryConfigurationResult withStatus(String status) {
        setStatus(status);
        return this;
    }

    /**
     * <p>
     * The current status of automated sensitive data discovery for the organization or account. Possible values are:
     * ENABLED, use the specified settings to perform automated sensitive data discovery activities; and, DISABLED,
     * don't perform automated sensitive data discovery activities.
     * </p>
     * 
     * @param status
     *        The current status of automated sensitive data discovery for the organization or account. Possible values
     *        are: ENABLED, use the specified settings to perform automated sensitive data discovery activities; and,
     *        DISABLED, don't perform automated sensitive data discovery activities.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see AutomatedDiscoveryStatus
     */

    public GetAutomatedDiscoveryConfigurationResult withStatus(AutomatedDiscoveryStatus status) {
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
        if (getClassificationScopeId() != null)
            sb.append("ClassificationScopeId: ").append(getClassificationScopeId()).append(",");
        if (getDisabledAt() != null)
            sb.append("DisabledAt: ").append(getDisabledAt()).append(",");
        if (getFirstEnabledAt() != null)
            sb.append("FirstEnabledAt: ").append(getFirstEnabledAt()).append(",");
        if (getLastUpdatedAt() != null)
            sb.append("LastUpdatedAt: ").append(getLastUpdatedAt()).append(",");
        if (getSensitivityInspectionTemplateId() != null)
            sb.append("SensitivityInspectionTemplateId: ").append(getSensitivityInspectionTemplateId()).append(",");
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

        if (obj instanceof GetAutomatedDiscoveryConfigurationResult == false)
            return false;
        GetAutomatedDiscoveryConfigurationResult other = (GetAutomatedDiscoveryConfigurationResult) obj;
        if (other.getAutoEnableOrganizationMembers() == null ^ this.getAutoEnableOrganizationMembers() == null)
            return false;
        if (other.getAutoEnableOrganizationMembers() != null
                && other.getAutoEnableOrganizationMembers().equals(this.getAutoEnableOrganizationMembers()) == false)
            return false;
        if (other.getClassificationScopeId() == null ^ this.getClassificationScopeId() == null)
            return false;
        if (other.getClassificationScopeId() != null && other.getClassificationScopeId().equals(this.getClassificationScopeId()) == false)
            return false;
        if (other.getDisabledAt() == null ^ this.getDisabledAt() == null)
            return false;
        if (other.getDisabledAt() != null && other.getDisabledAt().equals(this.getDisabledAt()) == false)
            return false;
        if (other.getFirstEnabledAt() == null ^ this.getFirstEnabledAt() == null)
            return false;
        if (other.getFirstEnabledAt() != null && other.getFirstEnabledAt().equals(this.getFirstEnabledAt()) == false)
            return false;
        if (other.getLastUpdatedAt() == null ^ this.getLastUpdatedAt() == null)
            return false;
        if (other.getLastUpdatedAt() != null && other.getLastUpdatedAt().equals(this.getLastUpdatedAt()) == false)
            return false;
        if (other.getSensitivityInspectionTemplateId() == null ^ this.getSensitivityInspectionTemplateId() == null)
            return false;
        if (other.getSensitivityInspectionTemplateId() != null
                && other.getSensitivityInspectionTemplateId().equals(this.getSensitivityInspectionTemplateId()) == false)
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
        hashCode = prime * hashCode + ((getClassificationScopeId() == null) ? 0 : getClassificationScopeId().hashCode());
        hashCode = prime * hashCode + ((getDisabledAt() == null) ? 0 : getDisabledAt().hashCode());
        hashCode = prime * hashCode + ((getFirstEnabledAt() == null) ? 0 : getFirstEnabledAt().hashCode());
        hashCode = prime * hashCode + ((getLastUpdatedAt() == null) ? 0 : getLastUpdatedAt().hashCode());
        hashCode = prime * hashCode + ((getSensitivityInspectionTemplateId() == null) ? 0 : getSensitivityInspectionTemplateId().hashCode());
        hashCode = prime * hashCode + ((getStatus() == null) ? 0 : getStatus().hashCode());
        return hashCode;
    }

    @Override
    public GetAutomatedDiscoveryConfigurationResult clone() {
        try {
            return (GetAutomatedDiscoveryConfigurationResult) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

}
