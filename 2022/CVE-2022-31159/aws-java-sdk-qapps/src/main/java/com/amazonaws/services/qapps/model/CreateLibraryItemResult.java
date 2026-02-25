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
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/CreateLibraryItem" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class CreateLibraryItemResult extends com.amazonaws.AmazonWebServiceResult<com.amazonaws.ResponseMetadata> implements Serializable, Cloneable {

    /**
     * <p>
     * The unique identifier of the new library item.
     * </p>
     */
    private String libraryItemId;
    /**
     * <p>
     * The status of the new library item, such as "Published".
     * </p>
     */
    private String status;
    /**
     * <p>
     * The date and time the library item was created.
     * </p>
     */
    private java.util.Date createdAt;
    /**
     * <p>
     * The user who created the library item.
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
     * The number of ratings the library item has received from users.
     * </p>
     */
    private Integer ratingCount;

    /**
     * <p>
     * The unique identifier of the new library item.
     * </p>
     * 
     * @param libraryItemId
     *        The unique identifier of the new library item.
     */

    public void setLibraryItemId(String libraryItemId) {
        this.libraryItemId = libraryItemId;
    }

    /**
     * <p>
     * The unique identifier of the new library item.
     * </p>
     * 
     * @return The unique identifier of the new library item.
     */

    public String getLibraryItemId() {
        return this.libraryItemId;
    }

    /**
     * <p>
     * The unique identifier of the new library item.
     * </p>
     * 
     * @param libraryItemId
     *        The unique identifier of the new library item.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateLibraryItemResult withLibraryItemId(String libraryItemId) {
        setLibraryItemId(libraryItemId);
        return this;
    }

    /**
     * <p>
     * The status of the new library item, such as "Published".
     * </p>
     * 
     * @param status
     *        The status of the new library item, such as "Published".
     */

    public void setStatus(String status) {
        this.status = status;
    }

    /**
     * <p>
     * The status of the new library item, such as "Published".
     * </p>
     * 
     * @return The status of the new library item, such as "Published".
     */

    public String getStatus() {
        return this.status;
    }

    /**
     * <p>
     * The status of the new library item, such as "Published".
     * </p>
     * 
     * @param status
     *        The status of the new library item, such as "Published".
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateLibraryItemResult withStatus(String status) {
        setStatus(status);
        return this;
    }

    /**
     * <p>
     * The date and time the library item was created.
     * </p>
     * 
     * @param createdAt
     *        The date and time the library item was created.
     */

    public void setCreatedAt(java.util.Date createdAt) {
        this.createdAt = createdAt;
    }

    /**
     * <p>
     * The date and time the library item was created.
     * </p>
     * 
     * @return The date and time the library item was created.
     */

    public java.util.Date getCreatedAt() {
        return this.createdAt;
    }

    /**
     * <p>
     * The date and time the library item was created.
     * </p>
     * 
     * @param createdAt
     *        The date and time the library item was created.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateLibraryItemResult withCreatedAt(java.util.Date createdAt) {
        setCreatedAt(createdAt);
        return this;
    }

    /**
     * <p>
     * The user who created the library item.
     * </p>
     * 
     * @param createdBy
     *        The user who created the library item.
     */

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    /**
     * <p>
     * The user who created the library item.
     * </p>
     * 
     * @return The user who created the library item.
     */

    public String getCreatedBy() {
        return this.createdBy;
    }

    /**
     * <p>
     * The user who created the library item.
     * </p>
     * 
     * @param createdBy
     *        The user who created the library item.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateLibraryItemResult withCreatedBy(String createdBy) {
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

    public CreateLibraryItemResult withUpdatedAt(java.util.Date updatedAt) {
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

    public CreateLibraryItemResult withUpdatedBy(String updatedBy) {
        setUpdatedBy(updatedBy);
        return this;
    }

    /**
     * <p>
     * The number of ratings the library item has received from users.
     * </p>
     * 
     * @param ratingCount
     *        The number of ratings the library item has received from users.
     */

    public void setRatingCount(Integer ratingCount) {
        this.ratingCount = ratingCount;
    }

    /**
     * <p>
     * The number of ratings the library item has received from users.
     * </p>
     * 
     * @return The number of ratings the library item has received from users.
     */

    public Integer getRatingCount() {
        return this.ratingCount;
    }

    /**
     * <p>
     * The number of ratings the library item has received from users.
     * </p>
     * 
     * @param ratingCount
     *        The number of ratings the library item has received from users.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateLibraryItemResult withRatingCount(Integer ratingCount) {
        setRatingCount(ratingCount);
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
            sb.append("RatingCount: ").append(getRatingCount());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof CreateLibraryItemResult == false)
            return false;
        CreateLibraryItemResult other = (CreateLibraryItemResult) obj;
        if (other.getLibraryItemId() == null ^ this.getLibraryItemId() == null)
            return false;
        if (other.getLibraryItemId() != null && other.getLibraryItemId().equals(this.getLibraryItemId()) == false)
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
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getLibraryItemId() == null) ? 0 : getLibraryItemId().hashCode());
        hashCode = prime * hashCode + ((getStatus() == null) ? 0 : getStatus().hashCode());
        hashCode = prime * hashCode + ((getCreatedAt() == null) ? 0 : getCreatedAt().hashCode());
        hashCode = prime * hashCode + ((getCreatedBy() == null) ? 0 : getCreatedBy().hashCode());
        hashCode = prime * hashCode + ((getUpdatedAt() == null) ? 0 : getUpdatedAt().hashCode());
        hashCode = prime * hashCode + ((getUpdatedBy() == null) ? 0 : getUpdatedBy().hashCode());
        hashCode = prime * hashCode + ((getRatingCount() == null) ? 0 : getRatingCount().hashCode());
        return hashCode;
    }

    @Override
    public CreateLibraryItemResult clone() {
        try {
            return (CreateLibraryItemResult) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

}
