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
 * Describes a pool of WorkSpaces.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/workspaces-2015-04-08/WorkspacesPool" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class WorkspacesPool implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The identifier of a pool.
     * </p>
     */
    private String poolId;
    /**
     * <p>
     * The Amazon Resource Name (ARN) for the pool.
     * </p>
     */
    private String poolArn;
    /**
     * <p>
     * The capacity status for the pool
     * </p>
     */
    private CapacityStatus capacityStatus;
    /**
     * <p>
     * The name of the pool,
     * </p>
     */
    private String poolName;
    /**
     * <p>
     * The description of the pool.
     * </p>
     */
    private String description;
    /**
     * <p>
     * The current state of the pool.
     * </p>
     */
    private String state;
    /**
     * <p>
     * The time the pool was created.
     * </p>
     */
    private java.util.Date createdAt;
    /**
     * <p>
     * The identifier of the bundle used by the pool.
     * </p>
     */
    private String bundleId;
    /**
     * <p>
     * The identifier of the directory used by the pool.
     * </p>
     */
    private String directoryId;
    /**
     * <p>
     * The pool errors.
     * </p>
     */
    private com.amazonaws.internal.SdkInternalList<WorkspacesPoolError> errors;
    /**
     * <p>
     * The persistent application settings for users of the pool.
     * </p>
     */
    private ApplicationSettingsResponse applicationSettings;
    /**
     * <p>
     * The amount of time that a pool session remains active after users disconnect. If they try to reconnect to the
     * pool session after a disconnection or network interruption within this time interval, they are connected to their
     * previous session. Otherwise, they are connected to a new session with a new pool instance.
     * </p>
     */
    private TimeoutSettings timeoutSettings;

    /**
     * <p>
     * The identifier of a pool.
     * </p>
     * 
     * @param poolId
     *        The identifier of a pool.
     */

    public void setPoolId(String poolId) {
        this.poolId = poolId;
    }

    /**
     * <p>
     * The identifier of a pool.
     * </p>
     * 
     * @return The identifier of a pool.
     */

    public String getPoolId() {
        return this.poolId;
    }

    /**
     * <p>
     * The identifier of a pool.
     * </p>
     * 
     * @param poolId
     *        The identifier of a pool.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public WorkspacesPool withPoolId(String poolId) {
        setPoolId(poolId);
        return this;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) for the pool.
     * </p>
     * 
     * @param poolArn
     *        The Amazon Resource Name (ARN) for the pool.
     */

    public void setPoolArn(String poolArn) {
        this.poolArn = poolArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) for the pool.
     * </p>
     * 
     * @return The Amazon Resource Name (ARN) for the pool.
     */

    public String getPoolArn() {
        return this.poolArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) for the pool.
     * </p>
     * 
     * @param poolArn
     *        The Amazon Resource Name (ARN) for the pool.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public WorkspacesPool withPoolArn(String poolArn) {
        setPoolArn(poolArn);
        return this;
    }

    /**
     * <p>
     * The capacity status for the pool
     * </p>
     * 
     * @param capacityStatus
     *        The capacity status for the pool
     */

    public void setCapacityStatus(CapacityStatus capacityStatus) {
        this.capacityStatus = capacityStatus;
    }

    /**
     * <p>
     * The capacity status for the pool
     * </p>
     * 
     * @return The capacity status for the pool
     */

    public CapacityStatus getCapacityStatus() {
        return this.capacityStatus;
    }

    /**
     * <p>
     * The capacity status for the pool
     * </p>
     * 
     * @param capacityStatus
     *        The capacity status for the pool
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public WorkspacesPool withCapacityStatus(CapacityStatus capacityStatus) {
        setCapacityStatus(capacityStatus);
        return this;
    }

    /**
     * <p>
     * The name of the pool,
     * </p>
     * 
     * @param poolName
     *        The name of the pool,
     */

    public void setPoolName(String poolName) {
        this.poolName = poolName;
    }

    /**
     * <p>
     * The name of the pool,
     * </p>
     * 
     * @return The name of the pool,
     */

    public String getPoolName() {
        return this.poolName;
    }

    /**
     * <p>
     * The name of the pool,
     * </p>
     * 
     * @param poolName
     *        The name of the pool,
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public WorkspacesPool withPoolName(String poolName) {
        setPoolName(poolName);
        return this;
    }

    /**
     * <p>
     * The description of the pool.
     * </p>
     * 
     * @param description
     *        The description of the pool.
     */

    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * <p>
     * The description of the pool.
     * </p>
     * 
     * @return The description of the pool.
     */

    public String getDescription() {
        return this.description;
    }

    /**
     * <p>
     * The description of the pool.
     * </p>
     * 
     * @param description
     *        The description of the pool.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public WorkspacesPool withDescription(String description) {
        setDescription(description);
        return this;
    }

    /**
     * <p>
     * The current state of the pool.
     * </p>
     * 
     * @param state
     *        The current state of the pool.
     * @see WorkspacesPoolState
     */

    public void setState(String state) {
        this.state = state;
    }

    /**
     * <p>
     * The current state of the pool.
     * </p>
     * 
     * @return The current state of the pool.
     * @see WorkspacesPoolState
     */

    public String getState() {
        return this.state;
    }

    /**
     * <p>
     * The current state of the pool.
     * </p>
     * 
     * @param state
     *        The current state of the pool.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see WorkspacesPoolState
     */

    public WorkspacesPool withState(String state) {
        setState(state);
        return this;
    }

    /**
     * <p>
     * The current state of the pool.
     * </p>
     * 
     * @param state
     *        The current state of the pool.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see WorkspacesPoolState
     */

    public WorkspacesPool withState(WorkspacesPoolState state) {
        this.state = state.toString();
        return this;
    }

    /**
     * <p>
     * The time the pool was created.
     * </p>
     * 
     * @param createdAt
     *        The time the pool was created.
     */

    public void setCreatedAt(java.util.Date createdAt) {
        this.createdAt = createdAt;
    }

    /**
     * <p>
     * The time the pool was created.
     * </p>
     * 
     * @return The time the pool was created.
     */

    public java.util.Date getCreatedAt() {
        return this.createdAt;
    }

    /**
     * <p>
     * The time the pool was created.
     * </p>
     * 
     * @param createdAt
     *        The time the pool was created.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public WorkspacesPool withCreatedAt(java.util.Date createdAt) {
        setCreatedAt(createdAt);
        return this;
    }

    /**
     * <p>
     * The identifier of the bundle used by the pool.
     * </p>
     * 
     * @param bundleId
     *        The identifier of the bundle used by the pool.
     */

    public void setBundleId(String bundleId) {
        this.bundleId = bundleId;
    }

    /**
     * <p>
     * The identifier of the bundle used by the pool.
     * </p>
     * 
     * @return The identifier of the bundle used by the pool.
     */

    public String getBundleId() {
        return this.bundleId;
    }

    /**
     * <p>
     * The identifier of the bundle used by the pool.
     * </p>
     * 
     * @param bundleId
     *        The identifier of the bundle used by the pool.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public WorkspacesPool withBundleId(String bundleId) {
        setBundleId(bundleId);
        return this;
    }

    /**
     * <p>
     * The identifier of the directory used by the pool.
     * </p>
     * 
     * @param directoryId
     *        The identifier of the directory used by the pool.
     */

    public void setDirectoryId(String directoryId) {
        this.directoryId = directoryId;
    }

    /**
     * <p>
     * The identifier of the directory used by the pool.
     * </p>
     * 
     * @return The identifier of the directory used by the pool.
     */

    public String getDirectoryId() {
        return this.directoryId;
    }

    /**
     * <p>
     * The identifier of the directory used by the pool.
     * </p>
     * 
     * @param directoryId
     *        The identifier of the directory used by the pool.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public WorkspacesPool withDirectoryId(String directoryId) {
        setDirectoryId(directoryId);
        return this;
    }

    /**
     * <p>
     * The pool errors.
     * </p>
     * 
     * @return The pool errors.
     */

    public java.util.List<WorkspacesPoolError> getErrors() {
        if (errors == null) {
            errors = new com.amazonaws.internal.SdkInternalList<WorkspacesPoolError>();
        }
        return errors;
    }

    /**
     * <p>
     * The pool errors.
     * </p>
     * 
     * @param errors
     *        The pool errors.
     */

    public void setErrors(java.util.Collection<WorkspacesPoolError> errors) {
        if (errors == null) {
            this.errors = null;
            return;
        }

        this.errors = new com.amazonaws.internal.SdkInternalList<WorkspacesPoolError>(errors);
    }

    /**
     * <p>
     * The pool errors.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setErrors(java.util.Collection)} or {@link #withErrors(java.util.Collection)} if you want to override the
     * existing values.
     * </p>
     * 
     * @param errors
     *        The pool errors.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public WorkspacesPool withErrors(WorkspacesPoolError... errors) {
        if (this.errors == null) {
            setErrors(new com.amazonaws.internal.SdkInternalList<WorkspacesPoolError>(errors.length));
        }
        for (WorkspacesPoolError ele : errors) {
            this.errors.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The pool errors.
     * </p>
     * 
     * @param errors
     *        The pool errors.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public WorkspacesPool withErrors(java.util.Collection<WorkspacesPoolError> errors) {
        setErrors(errors);
        return this;
    }

    /**
     * <p>
     * The persistent application settings for users of the pool.
     * </p>
     * 
     * @param applicationSettings
     *        The persistent application settings for users of the pool.
     */

    public void setApplicationSettings(ApplicationSettingsResponse applicationSettings) {
        this.applicationSettings = applicationSettings;
    }

    /**
     * <p>
     * The persistent application settings for users of the pool.
     * </p>
     * 
     * @return The persistent application settings for users of the pool.
     */

    public ApplicationSettingsResponse getApplicationSettings() {
        return this.applicationSettings;
    }

    /**
     * <p>
     * The persistent application settings for users of the pool.
     * </p>
     * 
     * @param applicationSettings
     *        The persistent application settings for users of the pool.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public WorkspacesPool withApplicationSettings(ApplicationSettingsResponse applicationSettings) {
        setApplicationSettings(applicationSettings);
        return this;
    }

    /**
     * <p>
     * The amount of time that a pool session remains active after users disconnect. If they try to reconnect to the
     * pool session after a disconnection or network interruption within this time interval, they are connected to their
     * previous session. Otherwise, they are connected to a new session with a new pool instance.
     * </p>
     * 
     * @param timeoutSettings
     *        The amount of time that a pool session remains active after users disconnect. If they try to reconnect to
     *        the pool session after a disconnection or network interruption within this time interval, they are
     *        connected to their previous session. Otherwise, they are connected to a new session with a new pool
     *        instance.
     */

    public void setTimeoutSettings(TimeoutSettings timeoutSettings) {
        this.timeoutSettings = timeoutSettings;
    }

    /**
     * <p>
     * The amount of time that a pool session remains active after users disconnect. If they try to reconnect to the
     * pool session after a disconnection or network interruption within this time interval, they are connected to their
     * previous session. Otherwise, they are connected to a new session with a new pool instance.
     * </p>
     * 
     * @return The amount of time that a pool session remains active after users disconnect. If they try to reconnect to
     *         the pool session after a disconnection or network interruption within this time interval, they are
     *         connected to their previous session. Otherwise, they are connected to a new session with a new pool
     *         instance.
     */

    public TimeoutSettings getTimeoutSettings() {
        return this.timeoutSettings;
    }

    /**
     * <p>
     * The amount of time that a pool session remains active after users disconnect. If they try to reconnect to the
     * pool session after a disconnection or network interruption within this time interval, they are connected to their
     * previous session. Otherwise, they are connected to a new session with a new pool instance.
     * </p>
     * 
     * @param timeoutSettings
     *        The amount of time that a pool session remains active after users disconnect. If they try to reconnect to
     *        the pool session after a disconnection or network interruption within this time interval, they are
     *        connected to their previous session. Otherwise, they are connected to a new session with a new pool
     *        instance.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public WorkspacesPool withTimeoutSettings(TimeoutSettings timeoutSettings) {
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
        if (getPoolArn() != null)
            sb.append("PoolArn: ").append(getPoolArn()).append(",");
        if (getCapacityStatus() != null)
            sb.append("CapacityStatus: ").append(getCapacityStatus()).append(",");
        if (getPoolName() != null)
            sb.append("PoolName: ").append(getPoolName()).append(",");
        if (getDescription() != null)
            sb.append("Description: ").append(getDescription()).append(",");
        if (getState() != null)
            sb.append("State: ").append(getState()).append(",");
        if (getCreatedAt() != null)
            sb.append("CreatedAt: ").append(getCreatedAt()).append(",");
        if (getBundleId() != null)
            sb.append("BundleId: ").append(getBundleId()).append(",");
        if (getDirectoryId() != null)
            sb.append("DirectoryId: ").append(getDirectoryId()).append(",");
        if (getErrors() != null)
            sb.append("Errors: ").append(getErrors()).append(",");
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

        if (obj instanceof WorkspacesPool == false)
            return false;
        WorkspacesPool other = (WorkspacesPool) obj;
        if (other.getPoolId() == null ^ this.getPoolId() == null)
            return false;
        if (other.getPoolId() != null && other.getPoolId().equals(this.getPoolId()) == false)
            return false;
        if (other.getPoolArn() == null ^ this.getPoolArn() == null)
            return false;
        if (other.getPoolArn() != null && other.getPoolArn().equals(this.getPoolArn()) == false)
            return false;
        if (other.getCapacityStatus() == null ^ this.getCapacityStatus() == null)
            return false;
        if (other.getCapacityStatus() != null && other.getCapacityStatus().equals(this.getCapacityStatus()) == false)
            return false;
        if (other.getPoolName() == null ^ this.getPoolName() == null)
            return false;
        if (other.getPoolName() != null && other.getPoolName().equals(this.getPoolName()) == false)
            return false;
        if (other.getDescription() == null ^ this.getDescription() == null)
            return false;
        if (other.getDescription() != null && other.getDescription().equals(this.getDescription()) == false)
            return false;
        if (other.getState() == null ^ this.getState() == null)
            return false;
        if (other.getState() != null && other.getState().equals(this.getState()) == false)
            return false;
        if (other.getCreatedAt() == null ^ this.getCreatedAt() == null)
            return false;
        if (other.getCreatedAt() != null && other.getCreatedAt().equals(this.getCreatedAt()) == false)
            return false;
        if (other.getBundleId() == null ^ this.getBundleId() == null)
            return false;
        if (other.getBundleId() != null && other.getBundleId().equals(this.getBundleId()) == false)
            return false;
        if (other.getDirectoryId() == null ^ this.getDirectoryId() == null)
            return false;
        if (other.getDirectoryId() != null && other.getDirectoryId().equals(this.getDirectoryId()) == false)
            return false;
        if (other.getErrors() == null ^ this.getErrors() == null)
            return false;
        if (other.getErrors() != null && other.getErrors().equals(this.getErrors()) == false)
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
        hashCode = prime * hashCode + ((getPoolArn() == null) ? 0 : getPoolArn().hashCode());
        hashCode = prime * hashCode + ((getCapacityStatus() == null) ? 0 : getCapacityStatus().hashCode());
        hashCode = prime * hashCode + ((getPoolName() == null) ? 0 : getPoolName().hashCode());
        hashCode = prime * hashCode + ((getDescription() == null) ? 0 : getDescription().hashCode());
        hashCode = prime * hashCode + ((getState() == null) ? 0 : getState().hashCode());
        hashCode = prime * hashCode + ((getCreatedAt() == null) ? 0 : getCreatedAt().hashCode());
        hashCode = prime * hashCode + ((getBundleId() == null) ? 0 : getBundleId().hashCode());
        hashCode = prime * hashCode + ((getDirectoryId() == null) ? 0 : getDirectoryId().hashCode());
        hashCode = prime * hashCode + ((getErrors() == null) ? 0 : getErrors().hashCode());
        hashCode = prime * hashCode + ((getApplicationSettings() == null) ? 0 : getApplicationSettings().hashCode());
        hashCode = prime * hashCode + ((getTimeoutSettings() == null) ? 0 : getTimeoutSettings().hashCode());
        return hashCode;
    }

    @Override
    public WorkspacesPool clone() {
        try {
            return (WorkspacesPool) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.workspaces.model.transform.WorkspacesPoolMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
