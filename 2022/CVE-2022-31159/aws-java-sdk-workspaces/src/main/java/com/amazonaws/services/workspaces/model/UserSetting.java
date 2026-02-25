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
 * Information about the user's permission settings.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/workspaces-2015-04-08/UserSetting" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class UserSetting implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * Indicates the type of action.
     * </p>
     */
    private String action;
    /**
     * <p>
     * Indicates if the setting is enabled or disabled.
     * </p>
     */
    private String permission;
    /**
     * <p>
     * Indicates the maximum character length for the specified user setting.
     * </p>
     */
    private Integer maximumLength;

    /**
     * <p>
     * Indicates the type of action.
     * </p>
     * 
     * @param action
     *        Indicates the type of action.
     * @see UserSettingActionEnum
     */

    public void setAction(String action) {
        this.action = action;
    }

    /**
     * <p>
     * Indicates the type of action.
     * </p>
     * 
     * @return Indicates the type of action.
     * @see UserSettingActionEnum
     */

    public String getAction() {
        return this.action;
    }

    /**
     * <p>
     * Indicates the type of action.
     * </p>
     * 
     * @param action
     *        Indicates the type of action.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see UserSettingActionEnum
     */

    public UserSetting withAction(String action) {
        setAction(action);
        return this;
    }

    /**
     * <p>
     * Indicates the type of action.
     * </p>
     * 
     * @param action
     *        Indicates the type of action.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see UserSettingActionEnum
     */

    public UserSetting withAction(UserSettingActionEnum action) {
        this.action = action.toString();
        return this;
    }

    /**
     * <p>
     * Indicates if the setting is enabled or disabled.
     * </p>
     * 
     * @param permission
     *        Indicates if the setting is enabled or disabled.
     * @see UserSettingPermissionEnum
     */

    public void setPermission(String permission) {
        this.permission = permission;
    }

    /**
     * <p>
     * Indicates if the setting is enabled or disabled.
     * </p>
     * 
     * @return Indicates if the setting is enabled or disabled.
     * @see UserSettingPermissionEnum
     */

    public String getPermission() {
        return this.permission;
    }

    /**
     * <p>
     * Indicates if the setting is enabled or disabled.
     * </p>
     * 
     * @param permission
     *        Indicates if the setting is enabled or disabled.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see UserSettingPermissionEnum
     */

    public UserSetting withPermission(String permission) {
        setPermission(permission);
        return this;
    }

    /**
     * <p>
     * Indicates if the setting is enabled or disabled.
     * </p>
     * 
     * @param permission
     *        Indicates if the setting is enabled or disabled.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see UserSettingPermissionEnum
     */

    public UserSetting withPermission(UserSettingPermissionEnum permission) {
        this.permission = permission.toString();
        return this;
    }

    /**
     * <p>
     * Indicates the maximum character length for the specified user setting.
     * </p>
     * 
     * @param maximumLength
     *        Indicates the maximum character length for the specified user setting.
     */

    public void setMaximumLength(Integer maximumLength) {
        this.maximumLength = maximumLength;
    }

    /**
     * <p>
     * Indicates the maximum character length for the specified user setting.
     * </p>
     * 
     * @return Indicates the maximum character length for the specified user setting.
     */

    public Integer getMaximumLength() {
        return this.maximumLength;
    }

    /**
     * <p>
     * Indicates the maximum character length for the specified user setting.
     * </p>
     * 
     * @param maximumLength
     *        Indicates the maximum character length for the specified user setting.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UserSetting withMaximumLength(Integer maximumLength) {
        setMaximumLength(maximumLength);
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
        if (getAction() != null)
            sb.append("Action: ").append(getAction()).append(",");
        if (getPermission() != null)
            sb.append("Permission: ").append(getPermission()).append(",");
        if (getMaximumLength() != null)
            sb.append("MaximumLength: ").append(getMaximumLength());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof UserSetting == false)
            return false;
        UserSetting other = (UserSetting) obj;
        if (other.getAction() == null ^ this.getAction() == null)
            return false;
        if (other.getAction() != null && other.getAction().equals(this.getAction()) == false)
            return false;
        if (other.getPermission() == null ^ this.getPermission() == null)
            return false;
        if (other.getPermission() != null && other.getPermission().equals(this.getPermission()) == false)
            return false;
        if (other.getMaximumLength() == null ^ this.getMaximumLength() == null)
            return false;
        if (other.getMaximumLength() != null && other.getMaximumLength().equals(this.getMaximumLength()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getAction() == null) ? 0 : getAction().hashCode());
        hashCode = prime * hashCode + ((getPermission() == null) ? 0 : getPermission().hashCode());
        hashCode = prime * hashCode + ((getMaximumLength() == null) ? 0 : getMaximumLength().hashCode());
        return hashCode;
    }

    @Override
    public UserSetting clone() {
        try {
            return (UserSetting) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.workspaces.model.transform.UserSettingMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
