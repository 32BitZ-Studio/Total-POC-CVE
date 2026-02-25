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

import com.amazonaws.AmazonWebServiceRequest;

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/workspaces-2015-04-08/CreateWorkspacesPool" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class CreateWorkspacesPoolRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The name of the pool.
     * </p>
     */
    private String poolName;
    /**
     * <p>
     * The pool description.
     * </p>
     */
    private String description;
    /**
     * <p>
     * The identifier of the bundle for the pool.
     * </p>
     */
    private String bundleId;
    /**
     * <p>
     * The identifier of the directory for the pool.
     * </p>
     */
    private String directoryId;
    /**
     * <p>
     * The user capacity of the pool.
     * </p>
     */
    private Capacity capacity;
    /**
     * <p>
     * The tags for the pool.
     * </p>
     */
    private com.amazonaws.internal.SdkInternalList<Tag> tags;
    /**
     * <p>
     * Indicates the application settings of the pool.
     * </p>
     */
    private ApplicationSettingsRequest applicationSettings;
    /**
     * <p>
     * Indicates the timeout settings of the pool.
     * </p>
     */
    private TimeoutSettings timeoutSettings;

    /**
     * <p>
     * The name of the pool.
     * </p>
     * 
     * @param poolName
     *        The name of the pool.
     */

    public void setPoolName(String poolName) {
        this.poolName = poolName;
    }

    /**
     * <p>
     * The name of the pool.
     * </p>
     * 
     * @return The name of the pool.
     */

    public String getPoolName() {
        return this.poolName;
    }

    /**
     * <p>
     * The name of the pool.
     * </p>
     * 
     * @param poolName
     *        The name of the pool.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateWorkspacesPoolRequest withPoolName(String poolName) {
        setPoolName(poolName);
        return this;
    }

    /**
     * <p>
     * The pool description.
     * </p>
     * 
     * @param description
     *        The pool description.
     */

    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * <p>
     * The pool description.
     * </p>
     * 
     * @return The pool description.
     */

    public String getDescription() {
        return this.description;
    }

    /**
     * <p>
     * The pool description.
     * </p>
     * 
     * @param description
     *        The pool description.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateWorkspacesPoolRequest withDescription(String description) {
        setDescription(description);
        return this;
    }

    /**
     * <p>
     * The identifier of the bundle for the pool.
     * </p>
     * 
     * @param bundleId
     *        The identifier of the bundle for the pool.
     */

    public void setBundleId(String bundleId) {
        this.bundleId = bundleId;
    }

    /**
     * <p>
     * The identifier of the bundle for the pool.
     * </p>
     * 
     * @return The identifier of the bundle for the pool.
     */

    public String getBundleId() {
        return this.bundleId;
    }

    /**
     * <p>
     * The identifier of the bundle for the pool.
     * </p>
     * 
     * @param bundleId
     *        The identifier of the bundle for the pool.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateWorkspacesPoolRequest withBundleId(String bundleId) {
        setBundleId(bundleId);
        return this;
    }

    /**
     * <p>
     * The identifier of the directory for the pool.
     * </p>
     * 
     * @param directoryId
     *        The identifier of the directory for the pool.
     */

    public void setDirectoryId(String directoryId) {
        this.directoryId = directoryId;
    }

    /**
     * <p>
     * The identifier of the directory for the pool.
     * </p>
     * 
     * @return The identifier of the directory for the pool.
     */

    public String getDirectoryId() {
        return this.directoryId;
    }

    /**
     * <p>
     * The identifier of the directory for the pool.
     * </p>
     * 
     * @param directoryId
     *        The identifier of the directory for the pool.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateWorkspacesPoolRequest withDirectoryId(String directoryId) {
        setDirectoryId(directoryId);
        return this;
    }

    /**
     * <p>
     * The user capacity of the pool.
     * </p>
     * 
     * @param capacity
     *        The user capacity of the pool.
     */

    public void setCapacity(Capacity capacity) {
        this.capacity = capacity;
    }

    /**
     * <p>
     * The user capacity of the pool.
     * </p>
     * 
     * @return The user capacity of the pool.
     */

    public Capacity getCapacity() {
        return this.capacity;
    }

    /**
     * <p>
     * The user capacity of the pool.
     * </p>
     * 
     * @param capacity
     *        The user capacity of the pool.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateWorkspacesPoolRequest withCapacity(Capacity capacity) {
        setCapacity(capacity);
        return this;
    }

    /**
     * <p>
     * The tags for the pool.
     * </p>
     * 
     * @return The tags for the pool.
     */

    public java.util.List<Tag> getTags() {
        if (tags == null) {
            tags = new com.amazonaws.internal.SdkInternalList<Tag>();
        }
        return tags;
    }

    /**
     * <p>
     * The tags for the pool.
     * </p>
     * 
     * @param tags
     *        The tags for the pool.
     */

    public void setTags(java.util.Collection<Tag> tags) {
        if (tags == null) {
            this.tags = null;
            return;
        }

        this.tags = new com.amazonaws.internal.SdkInternalList<Tag>(tags);
    }

    /**
     * <p>
     * The tags for the pool.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setTags(java.util.Collection)} or {@link #withTags(java.util.Collection)} if you want to override the
     * existing values.
     * </p>
     * 
     * @param tags
     *        The tags for the pool.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateWorkspacesPoolRequest withTags(Tag... tags) {
        if (this.tags == null) {
            setTags(new com.amazonaws.internal.SdkInternalList<Tag>(tags.length));
        }
        for (Tag ele : tags) {
            this.tags.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The tags for the pool.
     * </p>
     * 
     * @param tags
     *        The tags for the pool.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateWorkspacesPoolRequest withTags(java.util.Collection<Tag> tags) {
        setTags(tags);
        return this;
    }

    /**
     * <p>
     * Indicates the application settings of the pool.
     * </p>
     * 
     * @param applicationSettings
     *        Indicates the application settings of the pool.
     */

    public void setApplicationSettings(ApplicationSettingsRequest applicationSettings) {
        this.applicationSettings = applicationSettings;
    }

    /**
     * <p>
     * Indicates the application settings of the pool.
     * </p>
     * 
     * @return Indicates the application settings of the pool.
     */

    public ApplicationSettingsRequest getApplicationSettings() {
        return this.applicationSettings;
    }

    /**
     * <p>
     * Indicates the application settings of the pool.
     * </p>
     * 
     * @param applicationSettings
     *        Indicates the application settings of the pool.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateWorkspacesPoolRequest withApplicationSettings(ApplicationSettingsRequest applicationSettings) {
        setApplicationSettings(applicationSettings);
        return this;
    }

    /**
     * <p>
     * Indicates the timeout settings of the pool.
     * </p>
     * 
     * @param timeoutSettings
     *        Indicates the timeout settings of the pool.
     */

    public void setTimeoutSettings(TimeoutSettings timeoutSettings) {
        this.timeoutSettings = timeoutSettings;
    }

    /**
     * <p>
     * Indicates the timeout settings of the pool.
     * </p>
     * 
     * @return Indicates the timeout settings of the pool.
     */

    public TimeoutSettings getTimeoutSettings() {
        return this.timeoutSettings;
    }

    /**
     * <p>
     * Indicates the timeout settings of the pool.
     * </p>
     * 
     * @param timeoutSettings
     *        Indicates the timeout settings of the pool.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateWorkspacesPoolRequest withTimeoutSettings(TimeoutSettings timeoutSettings) {
        setTimeoutSettings(timeoutSettings);
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
        if (getPoolName() != null)
            sb.append("PoolName: ").append(getPoolName()).append(",");
        if (getDescription() != null)
            sb.append("Description: ").append(getDescription()).append(",");
        if (getBundleId() != null)
            sb.append("BundleId: ").append(getBundleId()).append(",");
        if (getDirectoryId() != null)
            sb.append("DirectoryId: ").append(getDirectoryId()).append(",");
        if (getCapacity() != null)
            sb.append("Capacity: ").append(getCapacity()).append(",");
        if (getTags() != null)
            sb.append("Tags: ").append(getTags()).append(",");
        if (getApplicationSettings() != null)
            sb.append("ApplicationSettings: ").append(getApplicationSettings()).append(",");
        if (getTimeoutSettings() != null)
            sb.append("TimeoutSettings: ").append(getTimeoutSettings());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof CreateWorkspacesPoolRequest == false)
            return false;
        CreateWorkspacesPoolRequest other = (CreateWorkspacesPoolRequest) obj;
        if (other.getPoolName() == null ^ this.getPoolName() == null)
            return false;
        if (other.getPoolName() != null && other.getPoolName().equals(this.getPoolName()) == false)
            return false;
        if (other.getDescription() == null ^ this.getDescription() == null)
            return false;
        if (other.getDescription() != null && other.getDescription().equals(this.getDescription()) == false)
            return false;
        if (other.getBundleId() == null ^ this.getBundleId() == null)
            return false;
        if (other.getBundleId() != null && other.getBundleId().equals(this.getBundleId()) == false)
            return false;
        if (other.getDirectoryId() == null ^ this.getDirectoryId() == null)
            return false;
        if (other.getDirectoryId() != null && other.getDirectoryId().equals(this.getDirectoryId()) == false)
            return false;
        if (other.getCapacity() == null ^ this.getCapacity() == null)
            return false;
        if (other.getCapacity() != null && other.getCapacity().equals(this.getCapacity()) == false)
            return false;
        if (other.getTags() == null ^ this.getTags() == null)
            return false;
        if (other.getTags() != null && other.getTags().equals(this.getTags()) == false)
            return false;
        if (other.getApplicationSettings() == null ^ this.getApplicationSettings() == null)
            return false;
        if (other.getApplicationSettings() != null && other.getApplicationSettings().equals(this.getApplicationSettings()) == false)
            return false;
        if (other.getTimeoutSettings() == null ^ this.getTimeoutSettings() == null)
            return false;
        if (other.getTimeoutSettings() != null && other.getTimeoutSettings().equals(this.getTimeoutSettings()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getPoolName() == null) ? 0 : getPoolName().hashCode());
        hashCode = prime * hashCode + ((getDescription() == null) ? 0 : getDescription().hashCode());
        hashCode = prime * hashCode + ((getBundleId() == null) ? 0 : getBundleId().hashCode());
        hashCode = prime * hashCode + ((getDirectoryId() == null) ? 0 : getDirectoryId().hashCode());
        hashCode = prime * hashCode + ((getCapacity() == null) ? 0 : getCapacity().hashCode());
        hashCode = prime * hashCode + ((getTags() == null) ? 0 : getTags().hashCode());
        hashCode = prime * hashCode + ((getApplicationSettings() == null) ? 0 : getApplicationSettings().hashCode());
        hashCode = prime * hashCode + ((getTimeoutSettings() == null) ? 0 : getTimeoutSettings().hashCode());
        return hashCode;
    }

    @Override
    public CreateWorkspacesPoolRequest clone() {
        return (CreateWorkspacesPoolRequest) super.clone();
    }

}
