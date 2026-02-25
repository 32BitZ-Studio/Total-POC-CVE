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
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/workspaces-2015-04-08/StopWorkspacesPool" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class StopWorkspacesPoolRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The identifier of the pool.
     * </p>
     */
    private String poolId;

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

    public StopWorkspacesPoolRequest withPoolId(String poolId) {
        setPoolId(poolId);
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
            sb.append("PoolId: ").append(getPoolId());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof StopWorkspacesPoolRequest == false)
            return false;
        StopWorkspacesPoolRequest other = (StopWorkspacesPoolRequest) obj;
        if (other.getPoolId() == null ^ this.getPoolId() == null)
            return false;
        if (other.getPoolId() != null && other.getPoolId().equals(this.getPoolId()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getPoolId() == null) ? 0 : getPoolId().hashCode());
        return hashCode;
    }

    @Override
    public StopWorkspacesPoolRequest clone() {
        return (StopWorkspacesPoolRequest) super.clone();
    }

}
