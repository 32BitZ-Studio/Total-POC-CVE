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
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * An Amazon Q App associated with a user, either owned by the user or favorited.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/UserAppItem" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class UserAppItem implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The unique identifier of the Q App.
     * </p>
     */
    private String appId;
    /**
     * <p>
     * The Amazon Resource Name (ARN) of the Q App.
     * </p>
     */
    private String appArn;
    /**
     * <p>
     * The title of the Q App.
     * </p>
     */
    private String title;
    /**
     * <p>
     * The description of the Q App.
     * </p>
     */
    private String description;
    /**
     * <p>
     * The date and time the user's association with the Q App was created.
     * </p>
     */
    private java.util.Date createdAt;
    /**
     * <p>
     * A flag indicating whether the user can edit the Q App.
     * </p>
     */
    private Boolean canEdit;
    /**
     * <p>
     * The status of the user's association with the Q App.
     * </p>
     */
    private String status;

    /**
     * <p>
     * The unique identifier of the Q App.
     * </p>
     * 
     * @param appId
     *        The unique identifier of the Q App.
     */

    public void setAppId(String appId) {
        this.appId = appId;
    }

    /**
     * <p>
     * The unique identifier of the Q App.
     * </p>
     * 
     * @return The unique identifier of the Q App.
     */

    public String getAppId() {
        return this.appId;
    }

    /**
     * <p>
     * The unique identifier of the Q App.
     * </p>
     * 
     * @param appId
     *        The unique identifier of the Q App.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UserAppItem withAppId(String appId) {
        setAppId(appId);
        return this;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the Q App.
     * </p>
     * 
     * @param appArn
     *        The Amazon Resource Name (ARN) of the Q App.
     */

    public void setAppArn(String appArn) {
        this.appArn = appArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the Q App.
     * </p>
     * 
     * @return The Amazon Resource Name (ARN) of the Q App.
     */

    public String getAppArn() {
        return this.appArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the Q App.
     * </p>
     * 
     * @param appArn
     *        The Amazon Resource Name (ARN) of the Q App.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UserAppItem withAppArn(String appArn) {
        setAppArn(appArn);
        return this;
    }

    /**
     * <p>
     * The title of the Q App.
     * </p>
     * 
     * @param title
     *        The title of the Q App.
     */

    public void setTitle(String title) {
        this.title = title;
    }

    /**
     * <p>
     * The title of the Q App.
     * </p>
     * 
     * @return The title of the Q App.
     */

    public String getTitle() {
        return this.title;
    }

    /**
     * <p>
     * The title of the Q App.
     * </p>
     * 
     * @param title
     *        The title of the Q App.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UserAppItem withTitle(String title) {
        setTitle(title);
        return this;
    }

    /**
     * <p>
     * The description of the Q App.
     * </p>
     * 
     * @param description
     *        The description of the Q App.
     */

    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * <p>
     * The description of the Q App.
     * </p>
     * 
     * @return The description of the Q App.
     */

    public String getDescription() {
        return this.description;
    }

    /**
     * <p>
     * The description of the Q App.
     * </p>
     * 
     * @param description
     *        The description of the Q App.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UserAppItem withDescription(String description) {
        setDescription(description);
        return this;
    }

    /**
     * <p>
     * The date and time the user's association with the Q App was created.
     * </p>
     * 
     * @param createdAt
     *        The date and time the user's association with the Q App was created.
     */

    public void setCreatedAt(java.util.Date createdAt) {
        this.createdAt = createdAt;
    }

    /**
     * <p>
     * The date and time the user's association with the Q App was created.
     * </p>
     * 
     * @return The date and time the user's association with the Q App was created.
     */

    public java.util.Date getCreatedAt() {
        return this.createdAt;
    }

    /**
     * <p>
     * The date and time the user's association with the Q App was created.
     * </p>
     * 
     * @param createdAt
     *        The date and time the user's association with the Q App was created.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UserAppItem withCreatedAt(java.util.Date createdAt) {
        setCreatedAt(createdAt);
        return this;
    }

    /**
     * <p>
     * A flag indicating whether the user can edit the Q App.
     * </p>
     * 
     * @param canEdit
     *        A flag indicating whether the user can edit the Q App.
     */

    public void setCanEdit(Boolean canEdit) {
        this.canEdit = canEdit;
    }

    /**
     * <p>
     * A flag indicating whether the user can edit the Q App.
     * </p>
     * 
     * @return A flag indicating whether the user can edit the Q App.
     */

    public Boolean getCanEdit() {
        return this.canEdit;
    }

    /**
     * <p>
     * A flag indicating whether the user can edit the Q App.
     * </p>
     * 
     * @param canEdit
     *        A flag indicating whether the user can edit the Q App.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UserAppItem withCanEdit(Boolean canEdit) {
        setCanEdit(canEdit);
        return this;
    }

    /**
     * <p>
     * A flag indicating whether the user can edit the Q App.
     * </p>
     * 
     * @return A flag indicating whether the user can edit the Q App.
     */

    public Boolean isCanEdit() {
        return this.canEdit;
    }

    /**
     * <p>
     * The status of the user's association with the Q App.
     * </p>
     * 
     * @param status
     *        The status of the user's association with the Q App.
     */

    public void setStatus(String status) {
        this.status = status;
    }

    /**
     * <p>
     * The status of the user's association with the Q App.
     * </p>
     * 
     * @return The status of the user's association with the Q App.
     */

    public String getStatus() {
        return this.status;
    }

    /**
     * <p>
     * The status of the user's association with the Q App.
     * </p>
     * 
     * @param status
     *        The status of the user's association with the Q App.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UserAppItem withStatus(String status) {
        setStatus(status);
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
        if (getCreatedAt() != null)
            sb.append("CreatedAt: ").append(getCreatedAt()).append(",");
        if (getCanEdit() != null)
            sb.append("CanEdit: ").append(getCanEdit()).append(",");
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

        if (obj instanceof UserAppItem == false)
            return false;
        UserAppItem other = (UserAppItem) obj;
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
        if (other.getCreatedAt() == null ^ this.getCreatedAt() == null)
            return false;
        if (other.getCreatedAt() != null && other.getCreatedAt().equals(this.getCreatedAt()) == false)
            return false;
        if (other.getCanEdit() == null ^ this.getCanEdit() == null)
            return false;
        if (other.getCanEdit() != null && other.getCanEdit().equals(this.getCanEdit()) == false)
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

        hashCode = prime * hashCode + ((getAppId() == null) ? 0 : getAppId().hashCode());
        hashCode = prime * hashCode + ((getAppArn() == null) ? 0 : getAppArn().hashCode());
        hashCode = prime * hashCode + ((getTitle() == null) ? 0 : getTitle().hashCode());
        hashCode = prime * hashCode + ((getDescription() == null) ? 0 : getDescription().hashCode());
        hashCode = prime * hashCode + ((getCreatedAt() == null) ? 0 : getCreatedAt().hashCode());
        hashCode = prime * hashCode + ((getCanEdit() == null) ? 0 : getCanEdit().hashCode());
        hashCode = prime * hashCode + ((getStatus() == null) ? 0 : getStatus().hashCode());
        return hashCode;
    }

    @Override
    public UserAppItem clone() {
        try {
            return (UserAppItem) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.qapps.model.transform.UserAppItemMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
