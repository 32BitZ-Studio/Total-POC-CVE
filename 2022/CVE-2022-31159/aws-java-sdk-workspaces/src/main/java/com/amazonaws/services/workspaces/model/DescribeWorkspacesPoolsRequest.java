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

import com.amazonaws.AmazonWebServiceRequest;

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/workspaces-2015-04-08/DescribeWorkspacesPools" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class DescribeWorkspacesPoolsRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The identifier of the WorkSpaces Pools.
     * </p>
     */
    private com.amazonaws.internal.SdkInternalList<String> poolIds;
    /**
     * <p>
     * The filter conditions for the WorkSpaces Pool to return.
     * </p>
     */
    private com.amazonaws.internal.SdkInternalList<DescribeWorkspacesPoolsFilter> filters;
    /**
     * <p>
     * The maximum number of items to return.
     * </p>
     */
    private Integer limit;
    /**
     * <p>
     * If you received a <code>NextToken</code> from a previous call that was paginated, provide this token to receive
     * the next set of results.
     * </p>
     */
    private String nextToken;

    /**
     * <p>
     * The identifier of the WorkSpaces Pools.
     * </p>
     * 
     * @return The identifier of the WorkSpaces Pools.
     */

    public java.util.List<String> getPoolIds() {
        if (poolIds == null) {
            poolIds = new com.amazonaws.internal.SdkInternalList<String>();
        }
        return poolIds;
    }

    /**
     * <p>
     * The identifier of the WorkSpaces Pools.
     * </p>
     * 
     * @param poolIds
     *        The identifier of the WorkSpaces Pools.
     */

    public void setPoolIds(java.util.Collection<String> poolIds) {
        if (poolIds == null) {
            this.poolIds = null;
            return;
        }

        this.poolIds = new com.amazonaws.internal.SdkInternalList<String>(poolIds);
    }

    /**
     * <p>
     * The identifier of the WorkSpaces Pools.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setPoolIds(java.util.Collection)} or {@link #withPoolIds(java.util.Collection)} if you want to override
     * the existing values.
     * </p>
     * 
     * @param poolIds
     *        The identifier of the WorkSpaces Pools.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeWorkspacesPoolsRequest withPoolIds(String... poolIds) {
        if (this.poolIds == null) {
            setPoolIds(new com.amazonaws.internal.SdkInternalList<String>(poolIds.length));
        }
        for (String ele : poolIds) {
            this.poolIds.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The identifier of the WorkSpaces Pools.
     * </p>
     * 
     * @param poolIds
     *        The identifier of the WorkSpaces Pools.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeWorkspacesPoolsRequest withPoolIds(java.util.Collection<String> poolIds) {
        setPoolIds(poolIds);
        return this;
    }

    /**
     * <p>
     * The filter conditions for the WorkSpaces Pool to return.
     * </p>
     * 
     * @return The filter conditions for the WorkSpaces Pool to return.
     */

    public java.util.List<DescribeWorkspacesPoolsFilter> getFilters() {
        if (filters == null) {
            filters = new com.amazonaws.internal.SdkInternalList<DescribeWorkspacesPoolsFilter>();
        }
        return filters;
    }

    /**
     * <p>
     * The filter conditions for the WorkSpaces Pool to return.
     * </p>
     * 
     * @param filters
     *        The filter conditions for the WorkSpaces Pool to return.
     */

    public void setFilters(java.util.Collection<DescribeWorkspacesPoolsFilter> filters) {
        if (filters == null) {
            this.filters = null;
            return;
        }

        this.filters = new com.amazonaws.internal.SdkInternalList<DescribeWorkspacesPoolsFilter>(filters);
    }

    /**
     * <p>
     * The filter conditions for the WorkSpaces Pool to return.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setFilters(java.util.Collection)} or {@link #withFilters(java.util.Collection)} if you want to override
     * the existing values.
     * </p>
     * 
     * @param filters
     *        The filter conditions for the WorkSpaces Pool to return.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeWorkspacesPoolsRequest withFilters(DescribeWorkspacesPoolsFilter... filters) {
        if (this.filters == null) {
            setFilters(new com.amazonaws.internal.SdkInternalList<DescribeWorkspacesPoolsFilter>(filters.length));
        }
        for (DescribeWorkspacesPoolsFilter ele : filters) {
            this.filters.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The filter conditions for the WorkSpaces Pool to return.
     * </p>
     * 
     * @param filters
     *        The filter conditions for the WorkSpaces Pool to return.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeWorkspacesPoolsRequest withFilters(java.util.Collection<DescribeWorkspacesPoolsFilter> filters) {
        setFilters(filters);
        return this;
    }

    /**
     * <p>
     * The maximum number of items to return.
     * </p>
     * 
     * @param limit
     *        The maximum number of items to return.
     */

    public void setLimit(Integer limit) {
        this.limit = limit;
    }

    /**
     * <p>
     * The maximum number of items to return.
     * </p>
     * 
     * @return The maximum number of items to return.
     */

    public Integer getLimit() {
        return this.limit;
    }

    /**
     * <p>
     * The maximum number of items to return.
     * </p>
     * 
     * @param limit
     *        The maximum number of items to return.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeWorkspacesPoolsRequest withLimit(Integer limit) {
        setLimit(limit);
        return this;
    }

    /**
     * <p>
     * If you received a <code>NextToken</code> from a previous call that was paginated, provide this token to receive
     * the next set of results.
     * </p>
     * 
     * @param nextToken
     *        If you received a <code>NextToken</code> from a previous call that was paginated, provide this token to
     *        receive the next set of results.
     */

    public void setNextToken(String nextToken) {
        this.nextToken = nextToken;
    }

    /**
     * <p>
     * If you received a <code>NextToken</code> from a previous call that was paginated, provide this token to receive
     * the next set of results.
     * </p>
     * 
     * @return If you received a <code>NextToken</code> from a previous call that was paginated, provide this token to
     *         receive the next set of results.
     */

    public String getNextToken() {
        return this.nextToken;
    }

    /**
     * <p>
     * If you received a <code>NextToken</code> from a previous call that was paginated, provide this token to receive
     * the next set of results.
     * </p>
     * 
     * @param nextToken
     *        If you received a <code>NextToken</code> from a previous call that was paginated, provide this token to
     *        receive the next set of results.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeWorkspacesPoolsRequest withNextToken(String nextToken) {
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
        if (getPoolIds() != null)
            sb.append("PoolIds: ").append(getPoolIds()).append(",");
        if (getFilters() != null)
            sb.append("Filters: ").append(getFilters()).append(",");
        if (getLimit() != null)
            sb.append("Limit: ").append(getLimit()).append(",");
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

        if (obj instanceof DescribeWorkspacesPoolsRequest == false)
            return false;
        DescribeWorkspacesPoolsRequest other = (DescribeWorkspacesPoolsRequest) obj;
        if (other.getPoolIds() == null ^ this.getPoolIds() == null)
            return false;
        if (other.getPoolIds() != null && other.getPoolIds().equals(this.getPoolIds()) == false)
            return false;
        if (other.getFilters() == null ^ this.getFilters() == null)
            return false;
        if (other.getFilters() != null && other.getFilters().equals(this.getFilters()) == false)
            return false;
        if (other.getLimit() == null ^ this.getLimit() == null)
            return false;
        if (other.getLimit() != null && other.getLimit().equals(this.getLimit()) == false)
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

        hashCode = prime * hashCode + ((getPoolIds() == null) ? 0 : getPoolIds().hashCode());
        hashCode = prime * hashCode + ((getFilters() == null) ? 0 : getFilters().hashCode());
        hashCode = prime * hashCode + ((getLimit() == null) ? 0 : getLimit().hashCode());
        hashCode = prime * hashCode + ((getNextToken() == null) ? 0 : getNextToken().hashCode());
        return hashCode;
    }

    @Override
    public DescribeWorkspacesPoolsRequest clone() {
        return (DescribeWorkspacesPoolsRequest) super.clone();
    }

}
