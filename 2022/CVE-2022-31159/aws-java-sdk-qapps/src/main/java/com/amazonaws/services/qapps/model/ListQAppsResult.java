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
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/ListQApps" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ListQAppsResult extends com.amazonaws.AmazonWebServiceResult<com.amazonaws.ResponseMetadata> implements Serializable, Cloneable {

    /**
     * <p>
     * The list of Amazon Q Apps meeting the request criteria.
     * </p>
     */
    private java.util.List<UserAppItem> apps;
    /**
     * <p>
     * The token to use to request the next page of results.
     * </p>
     */
    private String nextToken;

    /**
     * <p>
     * The list of Amazon Q Apps meeting the request criteria.
     * </p>
     * 
     * @return The list of Amazon Q Apps meeting the request criteria.
     */

    public java.util.List<UserAppItem> getApps() {
        return apps;
    }

    /**
     * <p>
     * The list of Amazon Q Apps meeting the request criteria.
     * </p>
     * 
     * @param apps
     *        The list of Amazon Q Apps meeting the request criteria.
     */

    public void setApps(java.util.Collection<UserAppItem> apps) {
        if (apps == null) {
            this.apps = null;
            return;
        }

        this.apps = new java.util.ArrayList<UserAppItem>(apps);
    }

    /**
     * <p>
     * The list of Amazon Q Apps meeting the request criteria.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setApps(java.util.Collection)} or {@link #withApps(java.util.Collection)} if you want to override the
     * existing values.
     * </p>
     * 
     * @param apps
     *        The list of Amazon Q Apps meeting the request criteria.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListQAppsResult withApps(UserAppItem... apps) {
        if (this.apps == null) {
            setApps(new java.util.ArrayList<UserAppItem>(apps.length));
        }
        for (UserAppItem ele : apps) {
            this.apps.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The list of Amazon Q Apps meeting the request criteria.
     * </p>
     * 
     * @param apps
     *        The list of Amazon Q Apps meeting the request criteria.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListQAppsResult withApps(java.util.Collection<UserAppItem> apps) {
        setApps(apps);
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

    public ListQAppsResult withNextToken(String nextToken) {
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
        if (getApps() != null)
            sb.append("Apps: ").append(getApps()).append(",");
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

        if (obj instanceof ListQAppsResult == false)
            return false;
        ListQAppsResult other = (ListQAppsResult) obj;
        if (other.getApps() == null ^ this.getApps() == null)
            return false;
        if (other.getApps() != null && other.getApps().equals(this.getApps()) == false)
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

        hashCode = prime * hashCode + ((getApps() == null) ? 0 : getApps().hashCode());
        hashCode = prime * hashCode + ((getNextToken() == null) ? 0 : getNextToken().hashCode());
        return hashCode;
    }

    @Override
    public ListQAppsResult clone() {
        try {
            return (ListQAppsResult) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

}
