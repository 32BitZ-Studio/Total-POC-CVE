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
 * A category used to classify and filter library items for Amazon Q Apps.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/Category" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class Category implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The unique identifier of the category.
     * </p>
     */
    private String id;
    /**
     * <p>
     * The title or name of the category.
     * </p>
     */
    private String title;

    /**
     * <p>
     * The unique identifier of the category.
     * </p>
     * 
     * @param id
     *        The unique identifier of the category.
     */

    public void setId(String id) {
        this.id = id;
    }

    /**
     * <p>
     * The unique identifier of the category.
     * </p>
     * 
     * @return The unique identifier of the category.
     */

    public String getId() {
        return this.id;
    }

    /**
     * <p>
     * The unique identifier of the category.
     * </p>
     * 
     * @param id
     *        The unique identifier of the category.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Category withId(String id) {
        setId(id);
        return this;
    }

    /**
     * <p>
     * The title or name of the category.
     * </p>
     * 
     * @param title
     *        The title or name of the category.
     */

    public void setTitle(String title) {
        this.title = title;
    }

    /**
     * <p>
     * The title or name of the category.
     * </p>
     * 
     * @return The title or name of the category.
     */

    public String getTitle() {
        return this.title;
    }

    /**
     * <p>
     * The title or name of the category.
     * </p>
     * 
     * @param title
     *        The title or name of the category.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Category withTitle(String title) {
        setTitle(title);
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
        if (getId() != null)
            sb.append("Id: ").append(getId()).append(",");
        if (getTitle() != null)
            sb.append("Title: ").append(getTitle());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof Category == false)
            return false;
        Category other = (Category) obj;
        if (other.getId() == null ^ this.getId() == null)
            return false;
        if (other.getId() != null && other.getId().equals(this.getId()) == false)
            return false;
        if (other.getTitle() == null ^ this.getTitle() == null)
            return false;
        if (other.getTitle() != null && other.getTitle().equals(this.getTitle()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getId() == null) ? 0 : getId().hashCode());
        hashCode = prime * hashCode + ((getTitle() == null) ? 0 : getTitle().hashCode());
        return hashCode;
    }

    @Override
    public Category clone() {
        try {
            return (Category) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.qapps.model.transform.CategoryMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
