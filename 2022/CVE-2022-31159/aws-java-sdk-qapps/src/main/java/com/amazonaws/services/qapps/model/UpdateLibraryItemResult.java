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
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/UpdateLibraryItem" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class UpdateLibraryItemResult extends com.amazonaws.AmazonWebServiceResult<com.amazonaws.ResponseMetadata> implements Serializable, Cloneable {

    /**
     * <p>
     * The unique identifier of the updated library item.
     * </p>
     */
    private String libraryItemId;
    /**
     * <p>
     * The unique identifier of the Q App associated with the library item.
     * </p>
     */
    private String appId;
    /**
     * <p>
     * The version of the Q App associated with the library item.
     * </p>
     */
    private Integer appVersion;
    /**
     * <p>
     * The categories associated with the updated library item.
     * </p>
     */
    private java.util.List<Category> categories;
    /**
     * <p>
     * The new status of the updated library item.
     * </p>
     */
    private String status;
    /**
     * <p>
     * The date and time the library item was originally created.
     * </p>
     */
    private java.util.Date createdAt;
    /**
     * <p>
     * The user who originally created the library item.
     * </p>
     */
    private String createdBy;
    /**
     * <p>
     * The date and time the library item was last updated.
     * </p>
     */
    private java.util.Date updatedAt;
    /**
     * <p>
     * The user who last updated the library item.
     * </p>
     */
    private String updatedBy;
    /**
     * <p>
     * The number of ratings the library item has received.
     * </p>
     */
    private Integer ratingCount;
    /**
     * <p>
     * Whether the current user has rated the library item.
     * </p>
     */
    private Boolean isRatedByUser;
    /**
     * <p>
     * The number of users who have the associated Q App.
     * </p>
     */
    private Integer userCount;

    /**
     * <p>
     * The unique identifier of the updated library item.
     * </p>
     * 
     * @param libraryItemId
     *        The unique identifier of the updated library item.
     */

    public void setLibraryItemId(String libraryItemId) {
        this.libraryItemId = libraryItemId;
    }

    /**
     * <p>
     * The unique identifier of the updated library item.
     * </p>
     * 
     * @return The unique identifier of the updated library item.
     */

    public String getLibraryItemId() {
        return this.libraryItemId;
    }

    /**
     * <p>
     * The unique identifier of the updated library item.
     * </p>
     * 
     * @param libraryItemId
     *        The unique identifier of the updated library item.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateLibraryItemResult withLibraryItemId(String libraryItemId) {
        setLibraryItemId(libraryItemId);
        return this;
    }

    /**
     * <p>
     * The unique identifier of the Q App associated with the library item.
     * </p>
     * 
     * @param appId
     *        The unique identifier of the Q App associated with the library item.
     */

    public void setAppId(String appId) {
        this.appId = appId;
    }

    /**
     * <p>
     * The unique identifier of the Q App associated with the library item.
     * </p>
     * 
     * @return The unique identifier of the Q App associated with the library item.
     */

    public String getAppId() {
        return this.appId;
    }

    /**
     * <p>
     * The unique identifier of the Q App associated with the library item.
     * </p>
     * 
     * @param appId
     *        The unique identifier of the Q App associated with the library item.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateLibraryItemResult withAppId(String appId) {
        setAppId(appId);
        return this;
    }

    /**
     * <p>
     * The version of the Q App associated with the library item.
     * </p>
     * 
     * @param appVersion
     *        The version of the Q App associated with the library item.
     */

    public void setAppVersion(Integer appVersion) {
        this.appVersion = appVersion;
    }

    /**
     * <p>
     * The version of the Q App associated with the library item.
     * </p>
     * 
     * @return The version of the Q App associated with the library item.
     */

    public Integer getAppVersion() {
        return this.appVersion;
    }

    /**
     * <p>
     * The version of the Q App associated with the library item.
     * </p>
     * 
     * @param appVersion
     *        The version of the Q App associated with the library item.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateLibraryItemResult withAppVersion(Integer appVersion) {
        setAppVersion(appVersion);
        return this;
    }

    /**
     * <p>
     * The categories associated with the updated library item.
     * </p>
     * 
     * @return The categories associated with the updated library item.
     */

    public java.util.List<Category> getCategories() {
        return categories;
    }

    /**
     * <p>
     * The categories associated with the updated library item.
     * </p>
     * 
     * @param categories
     *        The categories associated with the updated library item.
     */

    public void setCategories(java.util.Collection<Category> categories) {
        if (categories == null) {
            this.categories = null;
            return;
        }

        this.categories = new java.util.ArrayList<Category>(categories);
    }

    /**
     * <p>
     * The categories associated with the updated library item.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setCategories(java.util.Collection)} or {@link #withCategories(java.util.Collection)} if you want to
     * override the existing values.
     * </p>
     * 
     * @param categories
     *        The categories associated with the updated library item.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateLibraryItemResult withCategories(Category... categories) {
        if (this.categories == null) {
            setCategories(new java.util.ArrayList<Category>(categories.length));
        }
        for (Category ele : categories) {
            this.categories.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The categories associated with the updated library item.
     * </p>
     * 
     * @param categories
     *        The categories associated with the updated library item.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateLibraryItemResult withCategories(java.util.Collection<Category> categories) {
        setCategories(categories);
        return this;
    }

    /**
     * <p>
     * The new status of the updated library item.
     * </p>
     * 
     * @param status
     *        The new status of the updated library item.
     */

    public void setStatus(String status) {
        this.status = status;
    }

    /**
     * <p>
     * The new status of the updated library item.
     * </p>
     * 
     * @return The new status of the updated library item.
     */

    public String getStatus() {
        return this.status;
    }

    /**
     * <p>
     * The new status of the updated library item.
     * </p>
     * 
     * @param status
     *        The new status of the updated library item.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateLibraryItemResult withStatus(String status) {
        setStatus(status);
        return this;
    }

    /**
     * <p>
     * The date and time the library item was originally created.
     * </p>
     * 
     * @param createdAt
     *        The date and time the library item was originally created.
     */

    public void setCreatedAt(java.util.Date createdAt) {
        this.createdAt = createdAt;
    }

    /**
     * <p>
     * The date and time the library item was originally created.
     * </p>
     * 
     * @return The date and time the library item was originally created.
     */

    public java.util.Date getCreatedAt() {
        return this.createdAt;
    }

    /**
     * <p>
     * The date and time the library item was originally created.
     * </p>
     * 
     * @param createdAt
     *        The date and time the library item was originally created.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateLibraryItemResult withCreatedAt(java.util.Date createdAt) {
        setCreatedAt(createdAt);
        return this;
    }

    /**
     * <p>
     * The user who originally created the library item.
     * </p>
     * 
     * @param createdBy
     *        The user who originally created the library item.
     */

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    /**
     * <p>
     * The user who originally created the library item.
     * </p>
     * 
     * @return The user who originally created the library item.
     */

    public String getCreatedBy() {
        return this.createdBy;
    }

    /**
     * <p>
     * The user who originally created the library item.
     * </p>
     * 
     * @param createdBy
     *        The user who originally created the library item.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateLibraryItemResult withCreatedBy(String createdBy) {
        setCreatedBy(createdBy);
        return this;
    }

    /**
     * <p>
     * The date and time the library item was last updated.
     * </p>
     * 
     * @param updatedAt
     *        The date and time the library item was last updated.
     */

    public void setUpdatedAt(java.util.Date updatedAt) {
        this.updatedAt = updatedAt;
    }

    /**
     * <p>
     * The date and time the library item was last updated.
     * </p>
     * 
     * @return The date and time the library item was last updated.
     */

    public java.util.Date getUpdatedAt() {
        return this.updatedAt;
    }

    /**
     * <p>
     * The date and time the library item was last updated.
     * </p>
     * 
     * @param updatedAt
     *        The date and time the library item was last updated.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateLibraryItemResult withUpdatedAt(java.util.Date updatedAt) {
        setUpdatedAt(updatedAt);
        return this;
    }

    /**
     * <p>
     * The user who last updated the library item.
     * </p>
     * 
     * @param updatedBy
     *        The user who last updated the library item.
     */

    public void setUpdatedBy(String updatedBy) {
        this.updatedBy = updatedBy;
    }

    /**
     * <p>
     * The user who last updated the library item.
     * </p>
     * 
     * @return The user who last updated the library item.
     */

    public String getUpdatedBy() {
        return this.updatedBy;
    }

    /**
     * <p>
     * The user who last updated the library item.
     * </p>
     * 
     * @param updatedBy
     *        The user who last updated the library item.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateLibraryItemResult withUpdatedBy(String updatedBy) {
        setUpdatedBy(updatedBy);
        return this;
    }

    /**
     * <p>
     * The number of ratings the library item has received.
     * </p>
     * 
     * @param ratingCount
     *        The number of ratings the library item has received.
     */

    public void setRatingCount(Integer ratingCount) {
        this.ratingCount = ratingCount;
    }

    /**
     * <p>
     * The number of ratings the library item has received.
     * </p>
     * 
     * @return The number of ratings the library item has received.
     */

    public Integer getRatingCount() {
        return this.ratingCount;
    }

    /**
     * <p>
     * The number of ratings the library item has received.
     * </p>
     * 
     * @param ratingCount
     *        The number of ratings the library item has received.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateLibraryItemResult withRatingCount(Integer ratingCount) {
        setRatingCount(ratingCount);
        return this;
    }

    /**
     * <p>
     * Whether the current user has rated the library item.
     * </p>
     * 
     * @param isRatedByUser
     *        Whether the current user has rated the library item.
     */

    public void setIsRatedByUser(Boolean isRatedByUser) {
        this.isRatedByUser = isRatedByUser;
    }

    /**
     * <p>
     * Whether the current user has rated the library item.
     * </p>
     * 
     * @return Whether the current user has rated the library item.
     */

    public Boolean getIsRatedByUser() {
        return this.isRatedByUser;
    }

    /**
     * <p>
     * Whether the current user has rated the library item.
     * </p>
     * 
     * @param isRatedByUser
     *        Whether the current user has rated the library item.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateLibraryItemResult withIsRatedByUser(Boolean isRatedByUser) {
        setIsRatedByUser(isRatedByUser);
        return this;
    }

    /**
     * <p>
     * Whether the current user has rated the library item.
     * </p>
     * 
     * @return Whether the current user has rated the library item.
     */

    public Boolean isRatedByUser() {
        return this.isRatedByUser;
    }

    /**
     * <p>
     * The number of users who have the associated Q App.
     * </p>
     * 
     * @param userCount
     *        The number of users who have the associated Q App.
     */

    public void setUserCount(Integer userCount) {
        this.userCount = userCount;
    }

    /**
     * <p>
     * The number of users who have the associated Q App.
     * </p>
     * 
     * @return The number of users who have the associated Q App.
     */

    public Integer getUserCount() {
        return this.userCount;
    }

    /**
     * <p>
     * The number of users who have the associated Q App.
     * </p>
     * 
     * @param userCount
     *        The number of users who have the associated Q App.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateLibraryItemResult withUserCount(Integer userCount) {
        setUserCount(userCount);
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
        if (getLibraryItemId() != null)
            sb.append("LibraryItemId: ").append(getLibraryItemId()).append(",");
        if (getAppId() != null)
            sb.append("AppId: ").append(getAppId()).append(",");
        if (getAppVersion() != null)
            sb.append("AppVersion: ").append(getAppVersion()).append(",");
        if (getCategories() != null)
            sb.append("Categories: ").append(getCategories()).append(",");
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
        if (getRatingCount() != null)
            sb.append("RatingCount: ").append(getRatingCount()).append(",");
        if (getIsRatedByUser() != null)
            sb.append("IsRatedByUser: ").append(getIsRatedByUser()).append(",");
        if (getUserCount() != null)
            sb.append("UserCount: ").append(getUserCount());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof UpdateLibraryItemResult == false)
            return false;
        UpdateLibraryItemResult other = (UpdateLibraryItemResult) obj;
        if (other.getLibraryItemId() == null ^ this.getLibraryItemId() == null)
            return false;
        if (other.getLibraryItemId() != null && other.getLibraryItemId().equals(this.getLibraryItemId()) == false)
            return false;
        if (other.getAppId() == null ^ this.getAppId() == null)
            return false;
        if (other.getAppId() != null && other.getAppId().equals(this.getAppId()) == false)
            return false;
        if (other.getAppVersion() == null ^ this.getAppVersion() == null)
            return false;
        if (other.getAppVersion() != null && other.getAppVersion().equals(this.getAppVersion()) == false)
            return false;
        if (other.getCategories() == null ^ this.getCategories() == null)
            return false;
        if (other.getCategories() != null && other.getCategories().equals(this.getCategories()) == false)
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
        if (other.getRatingCount() == null ^ this.getRatingCount() == null)
            return false;
        if (other.getRatingCount() != null && other.getRatingCount().equals(this.getRatingCount()) == false)
            return false;
        if (other.getIsRatedByUser() == null ^ this.getIsRatedByUser() == null)
            return false;
        if (other.getIsRatedByUser() != null && other.getIsRatedByUser().equals(this.getIsRatedByUser()) == false)
            return false;
        if (other.getUserCount() == null ^ this.getUserCount() == null)
            return false;
        if (other.getUserCount() != null && other.getUserCount().equals(this.getUserCount()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getLibraryItemId() == null) ? 0 : getLibraryItemId().hashCode());
        hashCode = prime * hashCode + ((getAppId() == null) ? 0 : getAppId().hashCode());
        hashCode = prime * hashCode + ((getAppVersion() == null) ? 0 : getAppVersion().hashCode());
        hashCode = prime * hashCode + ((getCategories() == null) ? 0 : getCategories().hashCode());
        hashCode = prime * hashCode + ((getStatus() == null) ? 0 : getStatus().hashCode());
        hashCode = prime * hashCode + ((getCreatedAt() == null) ? 0 : getCreatedAt().hashCode());
        hashCode = prime * hashCode + ((getCreatedBy() == null) ? 0 : getCreatedBy().hashCode());
        hashCode = prime * hashCode + ((getUpdatedAt() == null) ? 0 : getUpdatedAt().hashCode());
        hashCode = prime * hashCode + ((getUpdatedBy() == null) ? 0 : getUpdatedBy().hashCode());
        hashCode = prime * hashCode + ((getRatingCount() == null) ? 0 : getRatingCount().hashCode());
        hashCode = prime * hashCode + ((getIsRatedByUser() == null) ? 0 : getIsRatedByUser().hashCode());
        hashCode = prime * hashCode + ((getUserCount() == null) ? 0 : getUserCount().hashCode());
        return hashCode;
    }

    @Override
    public UpdateLibraryItemResult clone() {
        try {
            return (UpdateLibraryItemResult) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

}
