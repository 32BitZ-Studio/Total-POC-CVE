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
 * The persistent application settings for WorkSpaces Pools users.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/workspaces-2015-04-08/ApplicationSettingsRequest"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ApplicationSettingsRequest implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * Enables or disables persistent application settings for users during their pool sessions.
     * </p>
     */
    private String status;
    /**
     * <p>
     * The path prefix for the S3 bucket where users’ persistent application settings are stored. You can allow the same
     * persistent application settings to be used across multiple pools by specifying the same settings group for each
     * pool.
     * </p>
     */
    private String settingsGroup;

    /**
     * <p>
     * Enables or disables persistent application settings for users during their pool sessions.
     * </p>
     * 
     * @param status
     *        Enables or disables persistent application settings for users during their pool sessions.
     * @see ApplicationSettingsStatusEnum
     */

    public void setStatus(String status) {
        this.status = status;
    }

    /**
     * <p>
     * Enables or disables persistent application settings for users during their pool sessions.
     * </p>
     * 
     * @return Enables or disables persistent application settings for users during their pool sessions.
     * @see ApplicationSettingsStatusEnum
     */

    public String getStatus() {
        return this.status;
    }

    /**
     * <p>
     * Enables or disables persistent application settings for users during their pool sessions.
     * </p>
     * 
     * @param status
     *        Enables or disables persistent application settings for users during their pool sessions.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ApplicationSettingsStatusEnum
     */

    public ApplicationSettingsRequest withStatus(String status) {
        setStatus(status);
        return this;
    }

    /**
     * <p>
     * Enables or disables persistent application settings for users during their pool sessions.
     * </p>
     * 
     * @param status
     *        Enables or disables persistent application settings for users during their pool sessions.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ApplicationSettingsStatusEnum
     */

    public ApplicationSettingsRequest withStatus(ApplicationSettingsStatusEnum status) {
        this.status = status.toString();
        return this;
    }

    /**
     * <p>
     * The path prefix for the S3 bucket where users’ persistent application settings are stored. You can allow the same
     * persistent application settings to be used across multiple pools by specifying the same settings group for each
     * pool.
     * </p>
     * 
     * @param settingsGroup
     *        The path prefix for the S3 bucket where users’ persistent application settings are stored. You can allow
     *        the same persistent application settings to be used across multiple pools by specifying the same settings
     *        group for each pool.
     */

    public void setSettingsGroup(String settingsGroup) {
        this.settingsGroup = settingsGroup;
    }

    /**
     * <p>
     * The path prefix for the S3 bucket where users’ persistent application settings are stored. You can allow the same
     * persistent application settings to be used across multiple pools by specifying the same settings group for each
     * pool.
     * </p>
     * 
     * @return The path prefix for the S3 bucket where users’ persistent application settings are stored. You can allow
     *         the same persistent application settings to be used across multiple pools by specifying the same settings
     *         group for each pool.
     */

    public String getSettingsGroup() {
        return this.settingsGroup;
    }

    /**
     * <p>
     * The path prefix for the S3 bucket where users’ persistent application settings are stored. You can allow the same
     * persistent application settings to be used across multiple pools by specifying the same settings group for each
     * pool.
     * </p>
     * 
     * @param settingsGroup
     *        The path prefix for the S3 bucket where users’ persistent application settings are stored. You can allow
     *        the same persistent application settings to be used across multiple pools by specifying the same settings
     *        group for each pool.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ApplicationSettingsRequest withSettingsGroup(String settingsGroup) {
        setSettingsGroup(settingsGroup);
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
        if (getStatus() != null)
            sb.append("Status: ").append(getStatus()).append(",");
        if (getSettingsGroup() != null)
            sb.append("SettingsGroup: ").append(getSettingsGroup());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ApplicationSettingsRequest == false)
            return false;
        ApplicationSettingsRequest other = (ApplicationSettingsRequest) obj;
        if (other.getStatus() == null ^ this.getStatus() == null)
            return false;
        if (other.getStatus() != null && other.getStatus().equals(this.getStatus()) == false)
            return false;
        if (other.getSettingsGroup() == null ^ this.getSettingsGroup() == null)
            return false;
        if (other.getSettingsGroup() != null && other.getSettingsGroup().equals(this.getSettingsGroup()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getStatus() == null) ? 0 : getStatus().hashCode());
        hashCode = prime * hashCode + ((getSettingsGroup() == null) ? 0 : getSettingsGroup().hashCode());
        return hashCode;
    }

    @Override
    public ApplicationSettingsRequest clone() {
        try {
            return (ApplicationSettingsRequest) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.workspaces.model.transform.ApplicationSettingsRequestMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
