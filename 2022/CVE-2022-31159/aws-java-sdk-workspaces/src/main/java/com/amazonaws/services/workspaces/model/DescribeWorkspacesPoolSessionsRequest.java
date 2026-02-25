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
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/workspaces-2015-04-08/DescribeWorkspacesPoolSessions"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class DescribeWorkspacesPoolSessionsRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The identifier of the pool.
     * </p>
     */
    private String poolId;
    /**
     * <p>
     * The identifier of the user.
     * </p>
     */
    private String userId;
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
     * The identifier of the pool.
     * </p>
     * 
     * @param poolId
     *        The identifier of the pool.
     */

    public void setPoolId(String poolId) {
        this.poolId = poolId;
    }

    /**
     * <p>
     * The identifier of the pool.
     * </p>
     * 
     * @return The identifier of the pool.
     */

    public String getPoolId() {
        return this.poolId;
    }

    /**
     * <p>
     * The identifier of the pool.
     * </p>
     * 
     * @param poolId
     *        The identifier of the pool.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeWorkspacesPoolSessionsRequest withPoolId(String poolId) {
        setPoolId(poolId);
        return this;
    }

    /**
     * <p>
     * The identifier of the user.
     * </p>
     * 
     * @param userId
     *        The identifier of the user.
     */

    public void setUserId(String userId) {
        this.userId = userId;
    }

    /**
     * <p>
     * The identifier of the user.
     * </p>
     * 
     * @return The identifier of the user.
     */

    public String getUserId() {
        return this.userId;
    }

    /**
     * <p>
     * The identifier of the user.
     * </p>
     * 
     * @param userId
     *        The identifier of the user.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeWorkspacesPoolSessionsRequest withUserId(String userId) {
        setUserId(userId);
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

    public DescribeWorkspacesPoolSessionsRequest withLimit(Integer limit) {
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

    public DescribeWorkspacesPoolSessionsRequest withNextToken(String nextToken) {
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
        if (getPoolId() != null)
            sb.append("PoolId: ").append(getPoolId()).append(",");
        if (getUserId() != null)
            sb.append("UserId: ").append(getUserId()).append(",");
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

        if (obj instanceof DescribeWorkspacesPoolSessionsRequest == false)
            return false;
        DescribeWorkspacesPoolSessionsRequest other = (DescribeWorkspacesPoolSessionsRequest) obj;
        if (other.getPoolId() == null ^ this.getPoolId() == null)
            return false;
        if (other.getPoolId() != null && other.getPoolId().equals(this.getPoolId()) == false)
            return false;
        if (other.getUserId() == null ^ this.getUserId() == null)
            return false;
        if (other.getUserId() != null && other.getUserId().equals(this.getUserId()) == false)
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

        hashCode = prime * hashCode + ((getPoolId() == null) ? 0 : getPoolId().hashCode());
        hashCode = prime * hashCode + ((getUserId() == null) ? 0 : getUserId().hashCode());
        hashCode = prime * hashCode + ((getLimit() == null) ? 0 : getLimit().hashCode());
        hashCode = prime * hashCode + ((getNextToken() == null) ? 0 : getNextToken().hashCode());
        return hashCode;
    }

    @Override
    public DescribeWorkspacesPoolSessionsRequest clone() {
        return (DescribeWorkspacesPoolSessionsRequest) super.clone();
    }

}
