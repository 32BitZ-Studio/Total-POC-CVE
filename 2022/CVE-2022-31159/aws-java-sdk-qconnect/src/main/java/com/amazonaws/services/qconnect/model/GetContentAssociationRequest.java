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

import com.amazonaws.AmazonWebServiceRequest;

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qconnect-2020-10-19/GetContentAssociation" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class GetContentAssociationRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The identifier of the content association. Can be either the ID or the ARN. URLs cannot contain the ARN.
     * </p>
     */
    private String contentAssociationId;
    /**
     * <p>
     * The identifier of the content.
     * </p>
     */
    private String contentId;
    /**
     * <p>
     * The identifier of the knowledge base.
     * </p>
     */
    private String knowledgeBaseId;

    /**
     * <p>
     * The identifier of the content association. Can be either the ID or the ARN. URLs cannot contain the ARN.
     * </p>
     * 
     * @param contentAssociationId
     *        The identifier of the content association. Can be either the ID or the ARN. URLs cannot contain the ARN.
     */

    public void setContentAssociationId(String contentAssociationId) {
        this.contentAssociationId = contentAssociationId;
    }

    /**
     * <p>
     * The identifier of the content association. Can be either the ID or the ARN. URLs cannot contain the ARN.
     * </p>
     * 
     * @return The identifier of the content association. Can be either the ID or the ARN. URLs cannot contain the ARN.
     */

    public String getContentAssociationId() {
        return this.contentAssociationId;
    }

    /**
     * <p>
     * The identifier of the content association. Can be either the ID or the ARN. URLs cannot contain the ARN.
     * </p>
     * 
     * @param contentAssociationId
     *        The identifier of the content association. Can be either the ID or the ARN. URLs cannot contain the ARN.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public GetContentAssociationRequest withContentAssociationId(String contentAssociationId) {
        setContentAssociationId(contentAssociationId);
        return this;
    }

    /**
     * <p>
     * The identifier of the content.
     * </p>
     * 
     * @param contentId
     *        The identifier of the content.
     */

    public void setContentId(String contentId) {
        this.contentId = contentId;
    }

    /**
     * <p>
     * The identifier of the content.
     * </p>
     * 
     * @return The identifier of the content.
     */

    public String getContentId() {
        return this.contentId;
    }

    /**
     * <p>
     * The identifier of the content.
     * </p>
     * 
     * @param contentId
     *        The identifier of the content.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public GetContentAssociationRequest withContentId(String contentId) {
        setContentId(contentId);
        return this;
    }

    /**
     * <p>
     * The identifier of the knowledge base.
     * </p>
     * 
     * @param knowledgeBaseId
     *        The identifier of the knowledge base.
     */

    public void setKnowledgeBaseId(String knowledgeBaseId) {
        this.knowledgeBaseId = knowledgeBaseId;
    }

    /**
     * <p>
     * The identifier of the knowledge base.
     * </p>
     * 
     * @return The identifier of the knowledge base.
     */

    public String getKnowledgeBaseId() {
        return this.knowledgeBaseId;
    }

    /**
     * <p>
     * The identifier of the knowledge base.
     * </p>
     * 
     * @param knowledgeBaseId
     *        The identifier of the knowledge base.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public GetContentAssociationRequest withKnowledgeBaseId(String knowledgeBaseId) {
        setKnowledgeBaseId(knowledgeBaseId);
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
        if (getContentAssociationId() != null)
            sb.append("ContentAssociationId: ").append(getContentAssociationId()).append(",");
        if (getContentId() != null)
            sb.append("ContentId: ").append(getContentId()).append(",");
        if (getKnowledgeBaseId() != null)
            sb.append("KnowledgeBaseId: ").append(getKnowledgeBaseId());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof GetContentAssociationRequest == false)
            return false;
        GetContentAssociationRequest other = (GetContentAssociationRequest) obj;
        if (other.getContentAssociationId() == null ^ this.getContentAssociationId() == null)
            return false;
        if (other.getContentAssociationId() != null && other.getContentAssociationId().equals(this.getContentAssociationId()) == false)
            return false;
        if (other.getContentId() == null ^ this.getContentId() == null)
            return false;
        if (other.getContentId() != null && other.getContentId().equals(this.getContentId()) == false)
            return false;
        if (other.getKnowledgeBaseId() == null ^ this.getKnowledgeBaseId() == null)
            return false;
        if (other.getKnowledgeBaseId() != null && other.getKnowledgeBaseId().equals(this.getKnowledgeBaseId()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getContentAssociationId() == null) ? 0 : getContentAssociationId().hashCode());
        hashCode = prime * hashCode + ((getContentId() == null) ? 0 : getContentId().hashCode());
        hashCode = prime * hashCode + ((getKnowledgeBaseId() == null) ? 0 : getKnowledgeBaseId().hashCode());
        return hashCode;
    }

    @Override
    public GetContentAssociationRequest clone() {
        return (GetContentAssociationRequest) super.clone();
    }

}
