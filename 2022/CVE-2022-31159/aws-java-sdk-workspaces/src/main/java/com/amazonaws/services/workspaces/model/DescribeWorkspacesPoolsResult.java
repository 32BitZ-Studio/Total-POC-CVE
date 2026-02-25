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

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/workspaces-2015-04-08/DescribeWorkspacesPools" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class DescribeWorkspacesPoolsResult extends com.amazonaws.AmazonWebServiceResult<com.amazonaws.ResponseMetadata> implements Serializable, Cloneable {

    /**
     * <p>
     * Information about the WorkSpaces Pools.
     * </p>
     */
    private com.amazonaws.internal.SdkInternalList<WorkspacesPool> workspacesPools;
    /**
     * <p>
     * If you received a <code>NextToken</code> from a previous call that was paginated, provide this token to receive
     * the next set of results.
     * </p>
     */
    private String nextToken;

    /**
     * <p>
     * Information about the WorkSpaces Pools.
     * </p>
     * 
     * @return Information about the WorkSpaces Pools.
     */

    public java.util.List<WorkspacesPool> getWorkspacesPools() {
        if (workspacesPools == null) {
            workspacesPools = new com.amazonaws.internal.SdkInternalList<WorkspacesPool>();
        }
        return workspacesPools;
    }

    /**
     * <p>
     * Information about the WorkSpaces Pools.
     * </p>
     * 
     * @param workspacesPools
     *        Information about the WorkSpaces Pools.
     */

    public void setWorkspacesPools(java.util.Collection<WorkspacesPool> workspacesPools) {
        if (workspacesPools == null) {
            this.workspacesPools = null;
            return;
        }

        this.workspacesPools = new com.amazonaws.internal.SdkInternalList<WorkspacesPool>(workspacesPools);
    }

    /**
     * <p>
     * Information about the WorkSpaces Pools.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setWorkspacesPools(java.util.Collection)} or {@link #withWorkspacesPools(java.util.Collection)} if you
     * want to override the existing values.
     * </p>
     * 
     * @param workspacesPools
     *        Information about the WorkSpaces Pools.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeWorkspacesPoolsResult withWorkspacesPools(WorkspacesPool... workspacesPools) {
        if (this.workspacesPools == null) {
            setWorkspacesPools(new com.amazonaws.internal.SdkInternalList<WorkspacesPool>(workspacesPools.length));
        }
        for (WorkspacesPool ele : workspacesPools) {
            this.workspacesPools.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * Information about the WorkSpaces Pools.
     * </p>
     * 
     * @param workspacesPools
     *        Information about the WorkSpaces Pools.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeWorkspacesPoolsResult withWorkspacesPools(java.util.Collection<WorkspacesPool> workspacesPools) {
        setWorkspacesPools(workspacesPools);
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

    public DescribeWorkspacesPoolsResult withNextToken(String nextToken) {
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
        if (getWorkspacesPools() != null)
            sb.append("WorkspacesPools: ").append(getWorkspacesPools()).append(",");
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

        if (obj instanceof DescribeWorkspacesPoolsResult == false)
            return false;
        DescribeWorkspacesPoolsResult other = (DescribeWorkspacesPoolsResult) obj;
        if (other.getWorkspacesPools() == null ^ this.getWorkspacesPools() == null)
            return false;
        if (other.getWorkspacesPools() != null && other.getWorkspacesPools().equals(this.getWorkspacesPools()) == false)
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

        hashCode = prime * hashCode + ((getWorkspacesPools() == null) ? 0 : getWorkspacesPools().hashCode());
        hashCode = prime * hashCode + ((getNextToken() == null) ? 0 : getNextToken().hashCode());
        return hashCode;
    }

    @Override
    public DescribeWorkspacesPoolsResult clone() {
        try {
            return (DescribeWorkspacesPoolsResult) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

}
