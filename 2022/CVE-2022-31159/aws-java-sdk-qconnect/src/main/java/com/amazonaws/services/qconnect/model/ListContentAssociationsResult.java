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
package com.amazonaws.services.qconnect.model;

import java.io.Serializable;
import javax.annotation.Generated;

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qconnect-2020-10-19/ListContentAssociations" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ListContentAssociationsResult extends com.amazonaws.AmazonWebServiceResult<com.amazonaws.ResponseMetadata> implements Serializable, Cloneable {

    /**
     * <p>
     * Summary information about content associations.
     * </p>
     */
    private java.util.List<ContentAssociationSummary> contentAssociationSummaries;
    /**
     * <p>
     * If there are additional results, this is the token for the next set of results.
     * </p>
     */
    private String nextToken;

    /**
     * <p>
     * Summary information about content associations.
     * </p>
     * 
     * @return Summary information about content associations.
     */

    public java.util.List<ContentAssociationSummary> getContentAssociationSummaries() {
        return contentAssociationSummaries;
    }

    /**
     * <p>
     * Summary information about content associations.
     * </p>
     * 
     * @param contentAssociationSummaries
     *        Summary information about content associations.
     */

    public void setContentAssociationSummaries(java.util.Collection<ContentAssociationSummary> contentAssociationSummaries) {
        if (contentAssociationSummaries == null) {
            this.contentAssociationSummaries = null;
            return;
        }

        this.contentAssociationSummaries = new java.util.ArrayList<ContentAssociationSummary>(contentAssociationSummaries);
    }

    /**
     * <p>
     * Summary information about content associations.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setContentAssociationSummaries(java.util.Collection)} or
     * {@link #withContentAssociationSummaries(java.util.Collection)} if you want to override the existing values.
     * </p>
     * 
     * @param contentAssociationSummaries
     *        Summary information about content associations.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListContentAssociationsResult withContentAssociationSummaries(ContentAssociationSummary... contentAssociationSummaries) {
        if (this.contentAssociationSummaries == null) {
            setContentAssociationSummaries(new java.util.ArrayList<ContentAssociationSummary>(contentAssociationSummaries.length));
        }
        for (ContentAssociationSummary ele : contentAssociationSummaries) {
            this.contentAssociationSummaries.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * Summary information about content associations.
     * </p>
     * 
     * @param contentAssociationSummaries
     *        Summary information about content associations.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListContentAssociationsResult withContentAssociationSummaries(java.util.Collection<ContentAssociationSummary> contentAssociationSummaries) {
        setContentAssociationSummaries(contentAssociationSummaries);
        return this;
    }

    /**
     * <p>
     * If there are additional results, this is the token for the next set of results.
     * </p>
     * 
     * @param nextToken
     *        If there are additional results, this is the token for the next set of results.
     */

    public void setNextToken(String nextToken) {
        this.nextToken = nextToken;
    }

    /**
     * <p>
     * If there are additional results, this is the token for the next set of results.
     * </p>
     * 
     * @return If there are additional results, this is the token for the next set of results.
     */

    public String getNextToken() {
        return this.nextToken;
    }

    /**
     * <p>
     * If there are additional results, this is the token for the next set of results.
     * </p>
     * 
     * @param nextToken
     *        If there are additional results, this is the token for the next set of results.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ListContentAssociationsResult withNextToken(String nextToken) {
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
        if (getContentAssociationSummaries() != null)
            sb.append("ContentAssociationSummaries: ").append(getContentAssociationSummaries()).append(",");
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

        if (obj instanceof ListContentAssociationsResult == false)
            return false;
        ListContentAssociationsResult other = (ListContentAssociationsResult) obj;
        if (other.getContentAssociationSummaries() == null ^ this.getContentAssociationSummaries() == null)
            return false;
        if (other.getContentAssociationSummaries() != null && other.getContentAssociationSummaries().equals(this.getContentAssociationSummaries()) == false)
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

        hashCode = prime * hashCode + ((getContentAssociationSummaries() == null) ? 0 : getContentAssociationSummaries().hashCode());
        hashCode = prime * hashCode + ((getNextToken() == null) ? 0 : getNextToken().hashCode());
        return hashCode;
    }

    @Override
    public ListContentAssociationsResult clone() {
        try {
            return (ListContentAssociationsResult) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

}
