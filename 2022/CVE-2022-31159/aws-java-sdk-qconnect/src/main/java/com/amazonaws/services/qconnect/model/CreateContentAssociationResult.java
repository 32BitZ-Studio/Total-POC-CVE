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
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qconnect-2020-10-19/CreateContentAssociation" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class CreateContentAssociationResult extends com.amazonaws.AmazonWebServiceResult<com.amazonaws.ResponseMetadata> implements Serializable, Cloneable {

    /**
     * <p>
     * The association between Amazon Q in Connect content and another resource.
     * </p>
     */
    private ContentAssociationData contentAssociation;

    /**
     * <p>
     * The association between Amazon Q in Connect content and another resource.
     * </p>
     * 
     * @param contentAssociation
     *        The association between Amazon Q in Connect content and another resource.
     */

    public void setContentAssociation(ContentAssociationData contentAssociation) {
        this.contentAssociation = contentAssociation;
    }

    /**
     * <p>
     * The association between Amazon Q in Connect content and another resource.
     * </p>
     * 
     * @return The association between Amazon Q in Connect content and another resource.
     */

    public ContentAssociationData getContentAssociation() {
        return this.contentAssociation;
    }

    /**
     * <p>
     * The association between Amazon Q in Connect content and another resource.
     * </p>
     * 
     * @param contentAssociation
     *        The association between Amazon Q in Connect content and another resource.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateContentAssociationResult withContentAssociation(ContentAssociationData contentAssociation) {
        setContentAssociation(contentAssociation);
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
        if (getContentAssociation() != null)
            sb.append("ContentAssociation: ").append(getContentAssociation());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof CreateContentAssociationResult == false)
            return false;
        CreateContentAssociationResult other = (CreateContentAssociationResult) obj;
        if (other.getContentAssociation() == null ^ this.getContentAssociation() == null)
            return false;
        if (other.getContentAssociation() != null && other.getContentAssociation().equals(this.getContentAssociation()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getContentAssociation() == null) ? 0 : getContentAssociation().hashCode());
        return hashCode;
    }

    @Override
    public CreateContentAssociationResult clone() {
        try {
            return (CreateContentAssociationResult) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

}
