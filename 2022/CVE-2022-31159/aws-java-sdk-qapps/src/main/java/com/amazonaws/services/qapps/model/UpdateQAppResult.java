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
package com.amazonaws.services.qapps.model;

import java.io.Serializable;
import javax.annotation.Generated;

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/UpdateQApp" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class UpdateQAppResult extends com.amazonaws.AmazonWebServiceResult<com.amazonaws.ResponseMetadata> implements Serializable, Cloneable {

    /**
     * <p>
     * The unique identifier of the updated Q App.
     * </p>
     */
    private String appId;
    /**
     * <p>
     * The Amazon Resource Name (ARN) of the updated Q App.
     * </p>
     */
    private String appArn;
    /**
     * <p>
     * The new title of the updated Q App.
     * </p>
     */
    private String title;
    /**
     * <p>
     * The new description of the updated Q App.
     * </p>
     */
    private String description;
    /**
     * <p>
     * The initial prompt for the updated Q App.
     * </p>
     */
    private String initialPrompt;
    /**
     * <p>
     * The new version of the updated Q App.
     * </p>
     */
    private Integer appVersion;
    /**
     * <p>
     * The status of the updated Q App.
     * </p>
     */
    private String status;
    /**
     * <p>
     * The date and time the Q App was originally created.
     * </p>
     */
    private java.util.Date createdAt;
    /**
     * <p>
     * The user who originally created the Q App.
     * </p>
     */
    private String createdBy;
    /**
     * <p>
     * The date and time the Q App was last updated.
     * </p>
     */
    private java.util.Date updatedAt;
    /**
     * <p>
     * The user who last updated the Q App.
     * </p>
     */
    private String updatedBy;
    /**
     * <p>
     * The capabilities required for the updated Q App.
     * </p>
     */
    private java.util.List<String> requiredCapabilities;

    /**
     * <p>
     * The unique identifier of the updated Q App.
     * </p>
     * 
     * @param appId
     *        The unique identifier of the updated Q App.
     */

    public void setAppId(String appId) {
        this.appId = appId;
    }

    /**
     * <p>
     * The unique identifier of the updated Q App.
     * </p>
     * 
     * @return The unique identifier of the updated Q App.
     */

    public String getAppId() {
        return this.appId;
    }

    /**
     * <p>
     * The unique identifier of the updated Q App.
     * </p>
     * 
     * @param appId
     *        The unique identifier of the updated Q App.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateQAppResult withAppId(String appId) {
        setAppId(appId);
        return this;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the updated Q App.
     * </p>
     * 
     * @param appArn
     *        The Amazon Resource Name (ARN) of the updated Q App.
     */

    public void setAppArn(String appArn) {
        this.appArn = appArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the updated Q App.
     * </p>
     * 
     * @return The Amazon Resource Name (ARN) of the updated Q App.
     */

    public String getAppArn() {
        return this.appArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the updated Q App.
     * </p>
     * 
     * @param appArn
     *        The Amazon Resource Name (ARN) of the updated Q App.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateQAppResult withAppArn(String appArn) {
        setAppArn(appArn);
        return this;
    }

    /**
     * <p>
     * The new title of the updated Q App.
     * </p>
     * 
     * @param title
     *        The new title of the updated Q App.
     */

    public void setTitle(String title) {
        this.title = title;
    }

    /**
     * <p>
     * The new title of the updated Q App.
     * </p>
     * 
     * @return The new title of the updated Q App.
     */

    public String getTitle() {
        return this.title;
    }

    /**
     * <p>
     * The new title of the updated Q App.
     * </p>
     * 
     * @param title
     *        The new title of the updated Q App.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateQAppResult withTitle(String title) {
        setTitle(title);
        return this;
    }

    /**
     * <p>
     * The new description of the updated Q App.
     * </p>
     * 
     * @param description
     *        The new description of the updated Q App.
     */

    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * <p>
     * The new description of the updated Q App.
     * </p>
     * 
     * @return The new description of the updated Q App.
     */

    public String getDescription() {
        return this.description;
    }

    /**
     * <p>
     * The new description of the updated Q App.
     * </p>
     * 
     * @param description
     *        The new description of the updated Q App.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateQAppResult withDescription(String description) {
        setDescription(description);
        return this;
    }

    /**
     * <p>
     * The initial prompt for the updated Q App.
     * </p>
     * 
     * @param initialPrompt
     *        The initial prompt for the updated Q App.
     */

    public void setInitialPrompt(String initialPrompt) {
        this.initialPrompt = initialPrompt;
    }

    /**
     * <p>
     * The initial prompt for the updated Q App.
     * </p>
     * 
     * @return The initial prompt for the updated Q App.
     */

    public String getInitialPrompt() {
        return this.initialPrompt;
    }

    /**
     * <p>
     * The initial prompt for the updated Q App.
     * </p>
     * 
     * @param initialPrompt
     *        The initial prompt for the updated Q App.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateQAppResult withInitialPrompt(String initialPrompt) {
        setInitialPrompt(initialPrompt);
        return this;
    }

    /**
     * <p>
     * The new version of the updated Q App.
     * </p>
     * 
     * @param appVersion
     *        The new version of the updated Q App.
     */

    public void setAppVersion(Integer appVersion) {
        this.appVersion = appVersion;
    }

    /**
     * <p>
     * The new version of the updated Q App.
     * </p>
     * 
     * @return The new version of the updated Q App.
     */

    public Integer getAppVersion() {
        return this.appVersion;
    }

    /**
     * <p>
     * The new version of the updated Q App.
     * </p>
     * 
     * @param appVersion
     *        The new version of the updated Q App.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateQAppResult withAppVersion(Integer appVersion) {
        setAppVersion(appVersion);
        return this;
    }

    /**
     * <p>
     * The status of the updated Q App.
     * </p>
     * 
     * @param status
     *        The status of the updated Q App.
     * @see AppStatus
     */

    public void setStatus(String status) {
        this.status = status;
    }

    /**
     * <p>
     * The status of the updated Q App.
     * </p>
     * 
     * @return The status of the updated Q App.
     * @see AppStatus
     */

    public String getStatus() {
        return this.status;
    }

    /**
     * <p>
     * The status of the updated Q App.
     * </p>
     * 
     * @param status
     *        The status of the updated Q App.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see AppStatus
     */

    public UpdateQAppResult withStatus(String status) {
        setStatus(status);
        return this;
    }

    /**
     * <p>
     * The status of the updated Q App.
     * </p>
     * 
     * @param status
     *        The status of the updated Q App.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see AppStatus
     */

    public UpdateQAppResult withStatus(AppStatus status) {
        this.status = status.toString();
        return this;
    }

    /**
     * <p>
     * The date and time the Q App was originally created.
     * </p>
     * 
     * @param createdAt
     *        The date and time the Q App was originally created.
     */

    public void setCreatedAt(java.util.Date createdAt) {
        this.createdAt = createdAt;
    }

    /**
     * <p>
     * The date and time the Q App was originally created.
     * </p>
     * 
     * @return The date and time the Q App was originally created.
     */

    public java.util.Date getCreatedAt() {
        return this.createdAt;
    }

    /**
     * <p>
     * The date and time the Q App was originally created.
     * </p>
     * 
     * @param createdAt
     *        The date and time the Q App was originally created.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateQAppResult withCreatedAt(java.util.Date createdAt) {
        setCreatedAt(createdAt);
        return this;
    }

    /**
     * <p>
     * The user who originally created the Q App.
     * </p>
     * 
     * @param createdBy
     *        The user who originally created the Q App.
     */

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    /**
     * <p>
     * The user who originally created the Q App.
     * </p>
     * 
     * @return The user who originally created the Q App.
     */

    public String getCreatedBy() {
        return this.createdBy;
    }

    /**
     * <p>
     * The user who originally created the Q App.
     * </p>
     * 
     * @param createdBy
     *        The user who originally created the Q App.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateQAppResult withCreatedBy(String createdBy) {
        setCreatedBy(createdBy);
        return this;
    }

    /**
     * <p>
     * The date and time the Q App was last updated.
     * </p>
     * 
     * @param updatedAt
     *        The date and time the Q App was last updated.
     */

    public void setUpdatedAt(java.util.Date updatedAt) {
        this.updatedAt = updatedAt;
    }

    /**
     * <p>
     * The date and time the Q App was last updated.
     * </p>
     * 
     * @return The date and time the Q App was last updated.
     */

    public java.util.Date getUpdatedAt() {
        return this.updatedAt;
    }

    /**
     * <p>
     * The date and time the Q App was last updated.
     * </p>
     * 
     * @param updatedAt
     *        The date and time the Q App was last updated.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateQAppResult withUpdatedAt(java.util.Date updatedAt) {
        setUpdatedAt(updatedAt);
        return this;
    }

    /**
     * <p>
     * The user who last updated the Q App.
     * </p>
     * 
     * @param updatedBy
     *        The user who last updated the Q App.
     */

    public void setUpdatedBy(String updatedBy) {
        this.updatedBy = updatedBy;
    }

    /**
     * <p>
     * The user who last updated the Q App.
     * </p>
     * 
     * @return The user who last updated the Q App.
     */

    public String getUpdatedBy() {
        return this.updatedBy;
    }

    /**
     * <p>
     * The user who last updated the Q App.
     * </p>
     * 
     * @param updatedBy
     *        The user who last updated the Q App.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateQAppResult withUpdatedBy(String updatedBy) {
        setUpdatedBy(updatedBy);
        return this;
    }

    /**
     * <p>
     * The capabilities required for the updated Q App.
     * </p>
     * 
     * @return The capabilities required for the updated Q App.
     * @see AppRequiredCapability
     */

    public java.util.List<String> getRequiredCapabilities() {
        return requiredCapabilities;
    }

    /**
     * <p>
     * The capabilities required for the updated Q App.
     * </p>
     * 
     * @param requiredCapabilities
     *        The capabilities required for the updated Q App.
     * @see AppRequiredCapability
     */

    public void setRequiredCapabilities(java.util.Collection<String> requiredCapabilities) {
        if (requiredCapabilities == null) {
            this.requiredCapabilities = null;
            return;
        }

        this.requiredCapabilities = new java.util.ArrayList<String>(requiredCapabilities);
    }

    /**
     * <p>
     * The capabilities required for the updated Q App.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setRequiredCapabilities(java.util.Collection)} or {@link #withRequiredCapabilities(java.util.Collection)}
     * if you want to override the existing values.
     * </p>
     * 
     * @param requiredCapabilities
     *        The capabilities required for the updated Q App.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see AppRequiredCapability
     */

    public UpdateQAppResult withRequiredCapabilities(String... requiredCapabilities) {
        if (this.requiredCapabilities == null) {
            setRequiredCapabilities(new java.util.ArrayList<String>(requiredCapabilities.length));
        }
        for (String ele : requiredCapabilities) {
            this.requiredCapabilities.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The capabilities required for the updated Q App.
     * </p>
     * 
     * @param requiredCapabilities
     *        The capabilities required for the updated Q App.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see AppRequiredCapability
     */

    public UpdateQAppResult withRequiredCapabilities(java.util.Collection<String> requiredCapabilities) {
        setRequiredCapabilities(requiredCapabilities);
        return this;
    }

    /**
     * <p>
     * The capabilities required for the updated Q App.
     * </p>
     * 
     * @param requiredCapabilities
     *        The capabilities required for the updated Q App.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see AppRequiredCapability
     */

    public UpdateQAppResult withRequiredCapabilities(AppRequiredCapability... requiredCapabilities) {
        java.util.ArrayList<String> requiredCapabilitiesCopy = new java.util.ArrayList<String>(requiredCapabilities.length);
        for (AppRequiredCapability value : requiredCapabilities) {
            requiredCapabilitiesCopy.add(value.toString());
        }
        if (getRequiredCapabilities() == null) {
            setRequiredCapabilities(requiredCapabilitiesCopy);
        } else {
            getRequiredCapabilities().addAll(requiredCapabilitiesCopy);
        }
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
        if (getAppId() != null)
            sb.append("AppId: ").append(getAppId()).append(",");
        if (getAppArn() != null)
            sb.append("AppArn: ").append(getAppArn()).append(",");
        if (getTitle() != null)
            sb.append("Title: ").append(getTitle()).append(",");
        if (getDescription() != null)
            sb.append("Description: ").append(getDescription()).append(",");
        if (getInitialPrompt() != null)
            sb.append("InitialPrompt: ").append(getInitialPrompt()).append(",");
        if (getAppVersion() != null)
            sb.append("AppVersion: ").append(getAppVersion()).append(",");
        if (getStatus() != null)
            sb.append("Status: ").append(getStatus()).append(",");
        if (getCreatedAt() != null)
            sb.append("CreatedAt: ").append(getCreatedAt()).append(",");
        if (getCreatedBy() != null)
            sb.append("CreatedBy: ").append(getCreatedBy()).append(",");
        if (getUpdatedAt() != null)
            sb.append("UpdatedAt: ").append(getUpdatedAt()).append(",");
        if (getUpdatedBy() != null)
            sb.append("UpdatedBy: ").append(getUpdatedBy()).append(",");
        if (getRequiredCapabilities() != null)
            sb.append("RequiredCapabilities: ").append(getRequiredCapabilities());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof UpdateQAppResult == false)
            return false;
        UpdateQAppResult other = (UpdateQAppResult) obj;
        if (other.getAppId() == null ^ this.getAppId() == null)
            return false;
        if (other.getAppId() != null && other.getAppId().equals(this.getAppId()) == false)
            return false;
        if (other.getAppArn() == null ^ this.getAppArn() == null)
            return false;
        if (other.getAppArn() != null && other.getAppArn().equals(this.getAppArn()) == false)
            return false;
        if (other.getTitle() == null ^ this.getTitle() == null)
            return false;
        if (other.getTitle() != null && other.getTitle().equals(this.getTitle()) == false)
            return false;
        if (other.getDescription() == null ^ this.getDescription() == null)
            return false;
        if (other.getDescription() != null && other.getDescription().equals(this.getDescription()) == false)
            return false;
        if (other.getInitialPrompt() == null ^ this.getInitialPrompt() == null)
            return false;
        if (other.getInitialPrompt() != null && other.getInitialPrompt().equals(this.getInitialPrompt()) == false)
            return false;
        if (other.getAppVersion() == null ^ this.getAppVersion() == null)
            return false;
        if (other.getAppVersion() != null && other.getAppVersion().equals(this.getAppVersion()) == false)
            return false;
        if (other.getStatus() == null ^ this.getStatus() == null)
            return false;
        if (other.getStatus() != null && other.getStatus().equals(this.getStatus()) == false)
            return false;
        if (other.getCreatedAt() == null ^ this.getCreatedAt() == null)
            return false;
        if (other.getCreatedAt() != null && other.getCreatedAt().equals(this.getCreatedAt()) == false)
            return false;
        if (other.getCreatedBy() == null ^ this.getCreatedBy() == null)
            return false;
        if (other.getCreatedBy() != null && other.getCreatedBy().equals(this.getCreatedBy()) == false)
            return false;
        if (other.getUpdatedAt() == null ^ this.getUpdatedAt() == null)
            return false;
        if (other.getUpdatedAt() != null && other.getUpdatedAt().equals(this.getUpdatedAt()) == false)
            return false;
        if (other.getUpdatedBy() == null ^ this.getUpdatedBy() == null)
            return false;
        if (other.getUpdatedBy() != null && other.getUpdatedBy().equals(this.getUpdatedBy()) == false)
            return false;
        if (other.getRequiredCapabilities() == null ^ this.getRequiredCapabilities() == null)
            return false;
        if (other.getRequiredCapabilities() != null && other.getRequiredCapabilities().equals(this.getRequiredCapabilities()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getAppId() == null) ? 0 : getAppId().hashCode());
        hashCode = prime * hashCode + ((getAppArn() == null) ? 0 : getAppArn().hashCode());
        hashCode = prime * hashCode + ((getTitle() == null) ? 0 : getTitle().hashCode());
        hashCode = prime * hashCode + ((getDescription() == null) ? 0 : getDescription().hashCode());
        hashCode = prime * hashCode + ((getInitialPrompt() == null) ? 0 : getInitialPrompt().hashCode());
        hashCode = prime * hashCode + ((getAppVersion() == null) ? 0 : getAppVersion().hashCode());
        hashCode = prime * hashCode + ((getStatus() == null) ? 0 : getStatus().hashCode());
        hashCode = prime * hashCode + ((getCreatedAt() == null) ? 0 : getCreatedAt().hashCode());
        hashCode = prime * hashCode + ((getCreatedBy() == null) ? 0 : getCreatedBy().hashCode());
        hashCode = prime * hashCode + ((getUpdatedAt() == null) ? 0 : getUpdatedAt().hashCode());
        hashCode = prime * hashCode + ((getUpdatedBy() == null) ? 0 : getUpdatedBy().hashCode());
        hashCode = prime * hashCode + ((getRequiredCapabilities() == null) ? 0 : getRequiredCapabilities().hashCode());
        return hashCode;
    }

    @Override
    public UpdateQAppResult clone() {
        try {
            return (UpdateQAppResult) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

}
