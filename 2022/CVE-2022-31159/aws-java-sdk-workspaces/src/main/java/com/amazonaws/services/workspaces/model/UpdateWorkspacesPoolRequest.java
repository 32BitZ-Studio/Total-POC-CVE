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
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/workspaces-2015-04-08/UpdateWorkspacesPool" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class UpdateWorkspacesPoolRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The identifier of the specified pool to update.
     * </p>
     */
    private String poolId;
    /**
     * <p>
     * Describes the specified pool to update.
     * </p>
     */
    private String description;
    /**
     * <p>
     * The identifier of the bundle.
     * </p>
     */
    private String bundleId;
    /**
     * <p>
     * The identifier of the directory.
     * </p>
     */
    private String directoryId;
    /**
     * <p>
     * The desired capacity for the pool.
     * </p>
     */
    private Capacity capacity;
    /**
     * <p>
     * The persistent application settings for users in the pool.
     * </p>
     */
    private ApplicationSettingsRequest applicationSettings;
    /**
     * <p>
     * Indicates the timeout settings of the specified pool.
     * </p>
     */
    private TimeoutSettings timeoutSettings;

    /**
     * <p>
     * The identifier of the specified pool to update.
     * </p>
     * 
     * @param poolId
     *        The identifier of the specified pool to update.
     */

    public void setPoolId(String poolId) {
        this.poolId = poolId;
    }

    /**
     * <p>
     * The identifier of the specified pool to update.
     * </p>
     * 
     * @return The identifier of the specified pool to update.
     */

    public String getPoolId() {
        return this.poolId;
    }

    /**
     * <p>
     * The identifier of the specified pool to update.
     * </p>
     * 
     * @param poolId
     *        The identifier of the specified pool to update.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateWorkspacesPoolRequest withPoolId(String poolId) {
        setPoolId(poolId);
        return this;
    }

    /**
     * <p>
     * Describes the specified pool to update.
     * </p>
     * 
     * @param description
     *        Describes the specified pool to update.
     */

    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * <p>
     * Describes the specified pool to update.
     * </p>
     * 
     * @return Describes the specified pool to update.
     */

    public String getDescription() {
        return this.description;
    }

    /**
     * <p>
     * Describes the specified pool to update.
     * </p>
     * 
     * @param description
     *        Describes the specified pool to update.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateWorkspacesPoolRequest withDescription(String description) {
        setDescription(description);
        return this;
    }

    /**
     * <p>
     * The identifier of the bundle.
     * </p>
     * 
     * @param bundleId
     *        The identifier of the bundle.
     */

    public void setBundleId(String bundleId) {
        this.bundleId = bundleId;
    }

    /**
     * <p>
     * The identifier of the bundle.
     * </p>
     * 
     * @return The identifier of the bundle.
     */

    public String getBundleId() {
        return this.bundleId;
    }

    /**
     * <p>
     * The identifier of the bundle.
     * </p>
     * 
     * @param bundleId
     *        The identifier of the bundle.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateWorkspacesPoolRequest withBundleId(String bundleId) {
        setBundleId(bundleId);
        return this;
    }

    /**
     * <p>
     * The identifier of the directory.
     * </p>
     * 
     * @param directoryId
     *        The identifier of the directory.
     */

    public void setDirectoryId(String directoryId) {
        this.directoryId = directoryId;
    }

    /**
     * <p>
     * The identifier of the directory.
     * </p>
     * 
     * @return The identifier of the directory.
     */

    public String getDirectoryId() {
        return this.directoryId;
    }

    /**
     * <p>
     * The identifier of the directory.
     * </p>
     * 
     * @param directoryId
     *        The identifier of the directory.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateWorkspacesPoolRequest withDirectoryId(String directoryId) {
        setDirectoryId(directoryId);
        return this;
    }

    /**
     * <p>
     * The desired capacity for the pool.
     * </p>
     * 
     * @param capacity
     *        The desired capacity for the pool.
     */

    public void setCapacity(Capacity capacity) {
        this.capacity = capacity;
    }

    /**
     * <p>
     * The desired capacity for the pool.
     * </p>
     * 
     * @return The desired capacity for the pool.
     */

    public Capacity getCapacity() {
        return this.capacity;
    }

    /**
     * <p>
     * The desired capacity for the pool.
     * </p>
     * 
     * @param capacity
     *        The desired capacity for the pool.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateWorkspacesPoolRequest withCapacity(Capacity capacity) {
        setCapacity(capacity);
        return this;
    }

    /**
     * <p>
     * The persistent application settings for users in the pool.
     * </p>
     * 
     * @param applicationSettings
     *        The persistent application settings for users in the pool.
     */

    public void setApplicationSettings(ApplicationSettingsRequest applicationSettings) {
        this.applicationSettings = applicationSettings;
    }

    /**
     * <p>
     * The persistent application settings for users in the pool.
     * </p>
     * 
     * @return The persistent application settings for users in the pool.
     */

    public ApplicationSettingsRequest getApplicationSettings() {
        return this.applicationSettings;
    }

    /**
     * <p>
     * The persistent application settings for users in the pool.
     * </p>
     * 
     * @param applicationSettings
     *        The persistent application settings for users in the pool.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateWorkspacesPoolRequest withApplicationSettings(ApplicationSettingsRequest applicationSettings) {
        setApplicationSettings(applicationSettings);
        return this;
    }

    /**
     * <p>
     * Indicates the timeout settings of the specified pool.
     * </p>
     * 
     * @param timeoutSettings
     *        Indicates the timeout settings of the specified pool.
     */

    public void setTimeoutSettings(TimeoutSettings timeoutSettings) {
        this.timeoutSettings = timeoutSettings;
    }

    /**
     * <p>
     * Indicates the timeout settings of the specified pool.
     * </p>
     * 
     * @return Indicates the timeout settings of the specified pool.
     */

    public TimeoutSettings getTimeoutSettings() {
        return this.timeoutSettings;
    }

    /**
     * <p>
     * Indicates the timeout settings of the specified pool.
     * </p>
     * 
     * @param timeoutSettings
     *        Indicates the timeout settings of the specified pool.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateWorkspacesPoolRequest withTimeoutSettings(TimeoutSettings timeoutSettings) {
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
        if (getPoolId() != null)
            sb.append("PoolId: ").append(getPoolId()).append(",");
        if (getDescription() != null)
            sb.append("Description: ").append(getDescription()).append(",");
        if (getBundleId() != null)
            sb.append("BundleId: ").append(getBundleId()).append(",");
        if (getDirectoryId() != null)
            sb.append("DirectoryId: ").append(getDirectoryId()).append(",");
        if (getCapacity() != null)
            sb.append("Capacity: ").append(getCapacity()).append(",");
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

        if (obj instanceof UpdateWorkspacesPoolRequest == false)
            return false;
        UpdateWorkspacesPoolRequest other = (UpdateWorkspacesPoolRequest) obj;
        if (other.getPoolId() == null ^ this.getPoolId() == null)
            return false;
        if (other.getPoolId() != null && other.getPoolId().equals(this.getPoolId()) == false)
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

        hashCode = prime * hashCode + ((getPoolId() == null) ? 0 : getPoolId().hashCode());
        hashCode = prime * hashCode + ((getDescription() == null) ? 0 : getDescription().hashCode());
        hashCode = prime * hashCode + ((getBundleId() == null) ? 0 : getBundleId().hashCode());
        hashCode = prime * hashCode + ((getDirectoryId() == null) ? 0 : getDirectoryId().hashCode());
        hashCode = prime * hashCode + ((getCapacity() == null) ? 0 : getCapacity().hashCode());
        hashCode = prime * hashCode + ((getApplicationSettings() == null) ? 0 : getApplicationSettings().hashCode());
        hashCode = prime * hashCode + ((getTimeoutSettings() == null) ? 0 : getTimeoutSettings().hashCode());
        return hashCode;
    }

    @Override
    public UpdateWorkspacesPoolRequest clone() {
        return (UpdateWorkspacesPoolRequest) super.clone();
    }

}
