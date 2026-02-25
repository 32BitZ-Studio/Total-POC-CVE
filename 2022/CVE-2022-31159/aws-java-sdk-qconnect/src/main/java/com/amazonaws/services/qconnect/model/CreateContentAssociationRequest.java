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
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qconnect-2020-10-19/CreateContentAssociation" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class CreateContentAssociationRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The identifier of the associated resource.
     * </p>
     */
    private ContentAssociationContents association;
    /**
     * <p>
     * The type of association.
     * </p>
     */
    private String associationType;
    /**
     * <p>
     * A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided,
     * the Amazon Web Services SDK populates this field. For more information about idempotency, see <a
     * href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with
     * idempotent APIs</a>.
     * </p>
     */
    private String clientToken;
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
     * The tags used to organize, track, or control access for this resource.
     * </p>
     */
    private java.util.Map<String, String> tags;

    /**
     * <p>
     * The identifier of the associated resource.
     * </p>
     * 
     * @param association
     *        The identifier of the associated resource.
     */

    public void setAssociation(ContentAssociationContents association) {
        this.association = association;
    }

    /**
     * <p>
     * The identifier of the associated resource.
     * </p>
     * 
     * @return The identifier of the associated resource.
     */

    public ContentAssociationContents getAssociation() {
        return this.association;
    }

    /**
     * <p>
     * The identifier of the associated resource.
     * </p>
     * 
     * @param association
     *        The identifier of the associated resource.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateContentAssociationRequest withAssociation(ContentAssociationContents association) {
        setAssociation(association);
        return this;
    }

    /**
     * <p>
     * The type of association.
     * </p>
     * 
     * @param associationType
     *        The type of association.
     * @see ContentAssociationType
     */

    public void setAssociationType(String associationType) {
        this.associationType = associationType;
    }

    /**
     * <p>
     * The type of association.
     * </p>
     * 
     * @return The type of association.
     * @see ContentAssociationType
     */

    public String getAssociationType() {
        return this.associationType;
    }

    /**
     * <p>
     * The type of association.
     * </p>
     * 
     * @param associationType
     *        The type of association.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ContentAssociationType
     */

    public CreateContentAssociationRequest withAssociationType(String associationType) {
        setAssociationType(associationType);
        return this;
    }

    /**
     * <p>
     * The type of association.
     * </p>
     * 
     * @param associationType
     *        The type of association.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ContentAssociationType
     */

    public CreateContentAssociationRequest withAssociationType(ContentAssociationType associationType) {
        this.associationType = associationType.toString();
        return this;
    }

    /**
     * <p>
     * A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided,
     * the Amazon Web Services SDK populates this field. For more information about idempotency, see <a
     * href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with
     * idempotent APIs</a>.
     * </p>
     * 
     * @param clientToken
     *        A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not
     *        provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see <a
     *        href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries
     *        safe with idempotent APIs</a>.
     */

    public void setClientToken(String clientToken) {
        this.clientToken = clientToken;
    }

    /**
     * <p>
     * A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided,
     * the Amazon Web Services SDK populates this field. For more information about idempotency, see <a
     * href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with
     * idempotent APIs</a>.
     * </p>
     * 
     * @return A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not
     *         provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see
     *         <a href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making
     *         retries safe with idempotent APIs</a>.
     */

    public String getClientToken() {
        return this.clientToken;
    }

    /**
     * <p>
     * A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided,
     * the Amazon Web Services SDK populates this field. For more information about idempotency, see <a
     * href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with
     * idempotent APIs</a>.
     * </p>
     * 
     * @param clientToken
     *        A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not
     *        provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see <a
     *        href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries
     *        safe with idempotent APIs</a>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateContentAssociationRequest withClientToken(String clientToken) {
        setClientToken(clientToken);
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

    public CreateContentAssociationRequest withContentId(String contentId) {
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

    public CreateContentAssociationRequest withKnowledgeBaseId(String knowledgeBaseId) {
        setKnowledgeBaseId(knowledgeBaseId);
        return this;
    }

    /**
     * <p>
     * The tags used to organize, track, or control access for this resource.
     * </p>
     * 
     * @return The tags used to organize, track, or control access for this resource.
     */

    public java.util.Map<String, String> getTags() {
        return tags;
    }

    /**
     * <p>
     * The tags used to organize, track, or control access for this resource.
     * </p>
     * 
     * @param tags
     *        The tags used to organize, track, or control access for this resource.
     */

    public void setTags(java.util.Map<String, String> tags) {
        this.tags = tags;
    }

    /**
     * <p>
     * The tags used to organize, track, or control access for this resource.
     * </p>
     * 
     * @param tags
     *        The tags used to organize, track, or control access for this resource.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateContentAssociationRequest withTags(java.util.Map<String, String> tags) {
        setTags(tags);
        return this;
    }

    /**
     * Add a single Tags entry
     *
     * @see CreateContentAssociationRequest#withTags
     * @returns a reference to this object so that method calls can be chained together.
     */

    public CreateContentAssociationRequest addTagsEntry(String key, String value) {
        if (null == this.tags) {
            this.tags = new java.util.HashMap<String, String>();
        }
        if (this.tags.containsKey(key))
            throw new IllegalArgumentException("Duplicated keys (" + key.toString() + ") are provided.");
        this.tags.put(key, value);
        return this;
    }

    /**
     * Removes all the entries added into Tags.
     *
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateContentAssociationRequest clearTagsEntries() {
        this.tags = null;
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
        if (getAssociation() != null)
            sb.append("Association: ").append(getAssociation()).append(",");
        if (getAssociationType() != null)
            sb.append("AssociationType: ").append(getAssociationType()).append(",");
        if (getClientToken() != null)
            sb.append("ClientToken: ").append(getClientToken()).append(",");
        if (getContentId() != null)
            sb.append("ContentId: ").append(getContentId()).append(",");
        if (getKnowledgeBaseId() != null)
            sb.append("KnowledgeBaseId: ").append(getKnowledgeBaseId()).append(",");
        if (getTags() != null)
            sb.append("Tags: ").append(getTags());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof CreateContentAssociationRequest == false)
            return false;
        CreateContentAssociationRequest other = (CreateContentAssociationRequest) obj;
        if (other.getAssociation() == null ^ this.getAssociation() == null)
            return false;
        if (other.getAssociation() != null && other.getAssociation().equals(this.getAssociation()) == false)
            return false;
        if (other.getAssociationType() == null ^ this.getAssociationType() == null)
            return false;
        if (other.getAssociationType() != null && other.getAssociationType().equals(this.getAssociationType()) == false)
            return false;
        if (other.getClientToken() == null ^ this.getClientToken() == null)
            return false;
        if (other.getClientToken() != null && other.getClientToken().equals(this.getClientToken()) == false)
            return false;
        if (other.getContentId() == null ^ this.getContentId() == null)
            return false;
        if (other.getContentId() != null && other.getContentId().equals(this.getContentId()) == false)
            return false;
        if (other.getKnowledgeBaseId() == null ^ this.getKnowledgeBaseId() == null)
            return false;
        if (other.getKnowledgeBaseId() != null && other.getKnowledgeBaseId().equals(this.getKnowledgeBaseId()) == false)
            return false;
        if (other.getTags() == null ^ this.getTags() == null)
            return false;
        if (other.getTags() != null && other.getTags().equals(this.getTags()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getAssociation() == null) ? 0 : getAssociation().hashCode());
        hashCode = prime * hashCode + ((getAssociationType() == null) ? 0 : getAssociationType().hashCode());
        hashCode = prime * hashCode + ((getClientToken() == null) ? 0 : getClientToken().hashCode());
        hashCode = prime * hashCode + ((getContentId() == null) ? 0 : getContentId().hashCode());
        hashCode = prime * hashCode + ((getKnowledgeBaseId() == null) ? 0 : getKnowledgeBaseId().hashCode());
        hashCode = prime * hashCode + ((getTags() == null) ? 0 : getTags().hashCode());
        return hashCode;
    }

    @Override
    public CreateContentAssociationRequest clone() {
        return (CreateContentAssociationRequest) super.clone();
    }

}
