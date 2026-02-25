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

import com.amazonaws.AmazonWebServiceRequest;

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/UpdateLibraryItem" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class UpdateLibraryItemRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The unique identifier of the Amazon Q Business application environment instance.
     * </p>
     */
    private String instanceId;
    /**
     * <p>
     * The unique identifier of the library item to update.
     * </p>
     */
    private String libraryItemId;
    /**
     * <p>
     * The new status to set for the library item, such as "Published" or "Hidden".
     * </p>
     */
    private String status;
    /**
     * <p>
     * The new categories to associate with the library item.
     * </p>
     */
    private java.util.List<String> categories;

    /**
     * <p>
     * The unique identifier of the Amazon Q Business application environment instance.
     * </p>
     * 
     * @param instanceId
     *        The unique identifier of the Amazon Q Business application environment instance.
     */

    public void setInstanceId(String instanceId) {
        this.instanceId = instanceId;
    }

    /**
     * <p>
     * The unique identifier of the Amazon Q Business application environment instance.
     * </p>
     * 
     * @return The unique identifier of the Amazon Q Business application environment instance.
     */

    public String getInstanceId() {
        return this.instanceId;
    }

    /**
     * <p>
     * The unique identifier of the Amazon Q Business application environment instance.
     * </p>
     * 
     * @param instanceId
     *        The unique identifier of the Amazon Q Business application environment instance.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateLibraryItemRequest withInstanceId(String instanceId) {
        setInstanceId(instanceId);
        return this;
    }

    /**
     * <p>
     * The unique identifier of the library item to update.
     * </p>
     * 
     * @param libraryItemId
     *        The unique identifier of the library item to update.
     */

    public void setLibraryItemId(String libraryItemId) {
        this.libraryItemId = libraryItemId;
    }

    /**
     * <p>
     * The unique identifier of the library item to update.
     * </p>
     * 
     * @return The unique identifier of the library item to update.
     */

    public String getLibraryItemId() {
        return this.libraryItemId;
    }

    /**
     * <p>
     * The unique identifier of the library item to update.
     * </p>
     * 
     * @param libraryItemId
     *        The unique identifier of the library item to update.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateLibraryItemRequest withLibraryItemId(String libraryItemId) {
        setLibraryItemId(libraryItemId);
        return this;
    }

    /**
     * <p>
     * The new status to set for the library item, such as "Published" or "Hidden".
     * </p>
     * 
     * @param status
     *        The new status to set for the library item, such as "Published" or "Hidden".
     * @see LibraryItemStatus
     */

    public void setStatus(String status) {
        this.status = status;
    }

    /**
     * <p>
     * The new status to set for the library item, such as "Published" or "Hidden".
     * </p>
     * 
     * @return The new status to set for the library item, such as "Published" or "Hidden".
     * @see LibraryItemStatus
     */

    public String getStatus() {
        return this.status;
    }

    /**
     * <p>
     * The new status to set for the library item, such as "Published" or "Hidden".
     * </p>
     * 
     * @param status
     *        The new status to set for the library item, such as "Published" or "Hidden".
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see LibraryItemStatus
     */

    public UpdateLibraryItemRequest withStatus(String status) {
        setStatus(status);
        return this;
    }

    /**
     * <p>
     * The new status to set for the library item, such as "Published" or "Hidden".
     * </p>
     * 
     * @param status
     *        The new status to set for the library item, such as "Published" or "Hidden".
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see LibraryItemStatus
     */

    public UpdateLibraryItemRequest withStatus(LibraryItemStatus status) {
        this.status = status.toString();
        return this;
    }

    /**
     * <p>
     * The new categories to associate with the library item.
     * </p>
     * 
     * @return The new categories to associate with the library item.
     */

    public java.util.List<String> getCategories() {
        return categories;
    }

    /**
     * <p>
     * The new categories to associate with the library item.
     * </p>
     * 
     * @param categories
     *        The new categories to associate with the library item.
     */

    public void setCategories(java.util.Collection<String> categories) {
        if (categories == null) {
            this.categories = null;
            return;
        }

        this.categories = new java.util.ArrayList<String>(categories);
    }

    /**
     * <p>
     * The new categories to associate with the library item.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setCategories(java.util.Collection)} or {@link #withCategories(java.util.Collection)} if you want to
     * override the existing values.
     * </p>
     * 
     * @param categories
     *        The new categories to associate with the library item.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateLibraryItemRequest withCategories(String... categories) {
        if (this.categories == null) {
            setCategories(new java.util.ArrayList<String>(categories.length));
        }
        for (String ele : categories) {
            this.categories.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The new categories to associate with the library item.
     * </p>
     * 
     * @param categories
     *        The new categories to associate with the library item.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public UpdateLibraryItemRequest withCategories(java.util.Collection<String> categories) {
        setCategories(categories);
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
        if (getInstanceId() != null)
            sb.append("InstanceId: ").append(getInstanceId()).append(",");
        if (getLibraryItemId() != null)
            sb.append("LibraryItemId: ").append(getLibraryItemId()).append(",");
        if (getStatus() != null)
            sb.append("Status: ").append(getStatus()).append(",");
        if (getCategories() != null)
            sb.append("Categories: ").append(getCategories());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof UpdateLibraryItemRequest == false)
            return false;
        UpdateLibraryItemRequest other = (UpdateLibraryItemRequest) obj;
        if (other.getInstanceId() == null ^ this.getInstanceId() == null)
            return false;
        if (other.getInstanceId() != null && other.getInstanceId().equals(this.getInstanceId()) == false)
            return false;
        if (other.getLibraryItemId() == null ^ this.getLibraryItemId() == null)
            return false;
        if (other.getLibraryItemId() != null && other.getLibraryItemId().equals(this.getLibraryItemId()) == false)
            return false;
        if (other.getStatus() == null ^ this.getStatus() == null)
            return false;
        if (other.getStatus() != null && other.getStatus().equals(this.getStatus()) == false)
            return false;
        if (other.getCategories() == null ^ this.getCategories() == null)
            return false;
        if (other.getCategories() != null && other.getCategories().equals(this.getCategories()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getInstanceId() == null) ? 0 : getInstanceId().hashCode());
        hashCode = prime * hashCode + ((getLibraryItemId() == null) ? 0 : getLibraryItemId().hashCode());
        hashCode = prime * hashCode + ((getStatus() == null) ? 0 : getStatus().hashCode());
        hashCode = prime * hashCode + ((getCategories() == null) ? 0 : getCategories().hashCode());
        return hashCode;
    }

    @Override
    public UpdateLibraryItemRequest clone() {
        return (UpdateLibraryItemRequest) super.clone();
    }

}
