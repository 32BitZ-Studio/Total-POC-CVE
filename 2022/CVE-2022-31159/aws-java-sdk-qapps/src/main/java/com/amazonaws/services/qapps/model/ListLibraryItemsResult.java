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
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/ListLibraryItems" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ListLibraryItemsResult extends com.amazonaws.AmazonWebServiceResult<com.amazonaws.ResponseMetadata> implements Serializable, Cloneable {

    /**
     * <p>
     * The list of library items meeting the request criteria.
     * </p>
     */
    private java.util.List<LibraryItemMember> libraryItems;
    /**
     * <p>
     * The token to use to request the next page of results.
     * </p>
     */
    private String nextToken;

    /**
     * <p>
     * The list of library items meeting the request criteria.
     * </p>
     * 
     * @return The list of library items meeting the request criteria.
     */

    public java.util.List<LibraryItemMember> getLibraryItems() {
        return libraryItems;
    }

    /**
     * <p>
     * The list of library items meeting the request criteria.
     * </p>
     * 
     * @param libraryItems
     *        The list of library items meeting the request criteria.
     */

    public void setLibraryItems(java.util.Collection<LibraryItemMember> libraryItems) {
        if (libraryItems == null) {
            this.libraryItems = null;
            return;
        }

        this.libraryItems = new java.util.ArrayList<LibraryItemMember>(libraryItems);
    }

    /**
     * <p>
     * The list of library items meeting the request criteria.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setLibraryItems(java.util.Collection)} or {@link #withLibraryItems(java.util.Collection)} if you want to
     * override the existing values.
     * </p>
     * 
     * @param libraryItems
     *        The list of library items meeting the request criteria.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListLibraryItemsResult withLibraryItems(LibraryItemMember... libraryItems) {
        if (this.libraryItems == null) {
            setLibraryItems(new java.util.ArrayList<LibraryItemMember>(libraryItems.length));
        }
        for (LibraryItemMember ele : libraryItems) {
            this.libraryItems.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The list of library items meeting the request criteria.
     * </p>
     * 
     * @param libraryItems
     *        The list of library items meeting the request criteria.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListLibraryItemsResult withLibraryItems(java.util.Collection<LibraryItemMember> libraryItems) {
        setLibraryItems(libraryItems);
        return this;
    }

    /**
     * <p>
     * The token to use to request the next page of results.
     * </p>
     * 
     * @param nextToken
     *        The token to use to request the next page of results.
     */

    public void setNextToken(String nextToken) {
        this.nextToken = nextToken;
    }

    /**
     * <p>
     * The token to use to request the next page of results.
     * </p>
     * 
     * @return The token to use to request the next page of results.
     */

    public String getNextToken() {
        return this.nextToken;
    }

    /**
     * <p>
     * The token to use to request the next page of results.
     * </p>
     * 
     * @param nextToken
     *        The token to use to request the next page of results.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListLibraryItemsResult withNextToken(String nextToken) {
        setNextToken(nextToken);
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
        if (getLibraryItems() != null)
            sb.append("LibraryItems: ").append(getLibraryItems()).append(",");
        if (getNextToken() != null)
            sb.append("NextToken: ").append(getNextToken());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ListLibraryItemsResult == false)
            return false;
        ListLibraryItemsResult other = (ListLibraryItemsResult) obj;
        if (other.getLibraryItems() == null ^ this.getLibraryItems() == null)
            return false;
        if (other.getLibraryItems() != null && other.getLibraryItems().equals(this.getLibraryItems()) == false)
            return false;
        if (other.getNextToken() == null ^ this.getNextToken() == null)
            return false;
        if (other.getNextToken() != null && other.getNextToken().equals(this.getNextToken()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getLibraryItems() == null) ? 0 : getLibraryItems().hashCode());
        hashCode = prime * hashCode + ((getNextToken() == null) ? 0 : getNextToken().hashCode());
        return hashCode;
    }

    @Override
    public ListLibraryItemsResult clone() {
        try {
            return (ListLibraryItemsResult) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

}
