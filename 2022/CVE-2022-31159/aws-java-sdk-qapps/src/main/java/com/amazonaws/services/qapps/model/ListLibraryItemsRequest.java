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
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/ListLibraryItems" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ListLibraryItemsRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The unique identifier of the Amazon Q Business application environment instance.
     * </p>
     */
    private String instanceId;
    /**
     * <p>
     * The maximum number of library items to return in the response.
     * </p>
     */
    private Integer limit;
    /**
     * <p>
     * The token to request the next page of results.
     * </p>
     */
    private String nextToken;
    /**
     * <p>
     * Optional category to filter the library items by.
     * </p>
     */
    private String categoryId;

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

    public ListLibraryItemsRequest withInstanceId(String instanceId) {
        setInstanceId(instanceId);
        return this;
    }

    /**
     * <p>
     * The maximum number of library items to return in the response.
     * </p>
     * 
     * @param limit
     *        The maximum number of library items to return in the response.
     */

    public void setLimit(Integer limit) {
        this.limit = limit;
    }

    /**
     * <p>
     * The maximum number of library items to return in the response.
     * </p>
     * 
     * @return The maximum number of library items to return in the response.
     */

    public Integer getLimit() {
        return this.limit;
    }

    /**
     * <p>
     * The maximum number of library items to return in the response.
     * </p>
     * 
     * @param limit
     *        The maximum number of library items to return in the response.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListLibraryItemsRequest withLimit(Integer limit) {
        setLimit(limit);
        return this;
    }

    /**
     * <p>
     * The token to request the next page of results.
     * </p>
     * 
     * @param nextToken
     *        The token to request the next page of results.
     */

    public void setNextToken(String nextToken) {
        this.nextToken = nextToken;
    }

    /**
     * <p>
     * The token to request the next page of results.
     * </p>
     * 
     * @return The token to request the next page of results.
     */

    public String getNextToken() {
        return this.nextToken;
    }

    /**
     * <p>
     * The token to request the next page of results.
     * </p>
     * 
     * @param nextToken
     *        The token to request the next page of results.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListLibraryItemsRequest withNextToken(String nextToken) {
        setNextToken(nextToken);
        return this;
    }

    /**
     * <p>
     * Optional category to filter the library items by.
     * </p>
     * 
     * @param categoryId
     *        Optional category to filter the library items by.
     */

    public void setCategoryId(String categoryId) {
        this.categoryId = categoryId;
    }

    /**
     * <p>
     * Optional category to filter the library items by.
     * </p>
     * 
     * @return Optional category to filter the library items by.
     */

    public String getCategoryId() {
        return this.categoryId;
    }

    /**
     * <p>
     * Optional category to filter the library items by.
     * </p>
     * 
     * @param categoryId
     *        Optional category to filter the library items by.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListLibraryItemsRequest withCategoryId(String categoryId) {
        setCategoryId(categoryId);
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
        if (getLimit() != null)
            sb.append("Limit: ").append(getLimit()).append(",");
        if (getNextToken() != null)
            sb.append("NextToken: ").append(getNextToken()).append(",");
        if (getCategoryId() != null)
            sb.append("CategoryId: ").append(getCategoryId());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ListLibraryItemsRequest == false)
            return false;
        ListLibraryItemsRequest other = (ListLibraryItemsRequest) obj;
        if (other.getInstanceId() == null ^ this.getInstanceId() == null)
            return false;
        if (other.getInstanceId() != null && other.getInstanceId().equals(this.getInstanceId()) == false)
            return false;
        if (other.getLimit() == null ^ this.getLimit() == null)
            return false;
        if (other.getLimit() != null && other.getLimit().equals(this.getLimit()) == false)
            return false;
        if (other.getNextToken() == null ^ this.getNextToken() == null)
            return false;
        if (other.getNextToken() != null && other.getNextToken().equals(this.getNextToken()) == false)
            return false;
        if (other.getCategoryId() == null ^ this.getCategoryId() == null)
            return false;
        if (other.getCategoryId() != null && other.getCategoryId().equals(this.getCategoryId()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getInstanceId() == null) ? 0 : getInstanceId().hashCode());
        hashCode = prime * hashCode + ((getLimit() == null) ? 0 : getLimit().hashCode());
        hashCode = prime * hashCode + ((getNextToken() == null) ? 0 : getNextToken().hashCode());
        hashCode = prime * hashCode + ((getCategoryId() == null) ? 0 : getCategoryId().hashCode());
        return hashCode;
    }

    @Override
    public ListLibraryItemsRequest clone() {
        return (ListLibraryItemsRequest) super.clone();
    }

}
