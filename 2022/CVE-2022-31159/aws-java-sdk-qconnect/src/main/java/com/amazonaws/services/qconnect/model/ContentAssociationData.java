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
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * Information about the content association.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qconnect-2020-10-19/ContentAssociationData" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ContentAssociationData implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The content association.
     * </p>
     */
    private ContentAssociationContents associationData;
    /**
     * <p>
     * The type of association.
     * </p>
     */
    private String associationType;
    /**
     * <p>
     * The Amazon Resource Name (ARN) of the content.
     * </p>
     */
    private String contentArn;
    /**
     * <p>
     * The Amazon Resource Name (ARN) of the content association.
     * </p>
     */
    private String contentAssociationArn;
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
     * The Amazon Resource Name (ARN) of the knowledge base.
     * </p>
     */
    private String knowledgeBaseArn;
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
     * The content association.
     * </p>
     * 
     * @param associationData
     *        The content association.
     */

    public void setAssociationData(ContentAssociationContents associationData) {
        this.associationData = associationData;
    }

    /**
     * <p>
     * The content association.
     * </p>
     * 
     * @return The content association.
     */

    public ContentAssociationContents getAssociationData() {
        return this.associationData;
    }

    /**
     * <p>
     * The content association.
     * </p>
     * 
     * @param associationData
     *        The content association.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ContentAssociationData withAssociationData(ContentAssociationContents associationData) {
        setAssociationData(associationData);
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

    public ContentAssociationData withAssociationType(String associationType) {
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

    public ContentAssociationData withAssociationType(ContentAssociationType associationType) {
        this.associationType = associationType.toString();
        return this;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the content.
     * </p>
     * 
     * @param contentArn
     *        The Amazon Resource Name (ARN) of the content.
     */

    public void setContentArn(String contentArn) {
        this.contentArn = contentArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the content.
     * </p>
     * 
     * @return The Amazon Resource Name (ARN) of the content.
     */

    public String getContentArn() {
        return this.contentArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the content.
     * </p>
     * 
     * @param contentArn
     *        The Amazon Resource Name (ARN) of the content.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ContentAssociationData withContentArn(String contentArn) {
        setContentArn(contentArn);
        return this;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the content association.
     * </p>
     * 
     * @param contentAssociationArn
     *        The Amazon Resource Name (ARN) of the content association.
     */

    public void setContentAssociationArn(String contentAssociationArn) {
        this.contentAssociationArn = contentAssociationArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the content association.
     * </p>
     * 
     * @return The Amazon Resource Name (ARN) of the content association.
     */

    public String getContentAssociationArn() {
        return this.contentAssociationArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the content association.
     * </p>
     * 
     * @param contentAssociationArn
     *        The Amazon Resource Name (ARN) of the content association.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ContentAssociationData withContentAssociationArn(String contentAssociationArn) {
        setContentAssociationArn(contentAssociationArn);
        return this;
    }

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

    public ContentAssociationData withContentAssociationId(String contentAssociationId) {
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

    public ContentAssociationData withContentId(String contentId) {
        setContentId(contentId);
        return this;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the knowledge base.
     * </p>
     * 
     * @param knowledgeBaseArn
     *        The Amazon Resource Name (ARN) of the knowledge base.
     */

    public void setKnowledgeBaseArn(String knowledgeBaseArn) {
        this.knowledgeBaseArn = knowledgeBaseArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the knowledge base.
     * </p>
     * 
     * @return The Amazon Resource Name (ARN) of the knowledge base.
     */

    public String getKnowledgeBaseArn() {
        return this.knowledgeBaseArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the knowledge base.
     * </p>
     * 
     * @param knowledgeBaseArn
     *        The Amazon Resource Name (ARN) of the knowledge base.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ContentAssociationData withKnowledgeBaseArn(String knowledgeBaseArn) {
        setKnowledgeBaseArn(knowledgeBaseArn);
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

    public ContentAssociationData withKnowledgeBaseId(String knowledgeBaseId) {
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

    public ContentAssociationData withTags(java.util.Map<String, String> tags) {
        setTags(tags);
        return this;
    }

    /**
     * Add a single Tags entry
     *
     * @see ContentAssociationData#withTags
     * @returns a reference to this object so that method calls can be chained together.
     */

    public ContentAssociationData addTagsEntry(String key, String value) {
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

    public ContentAssociationData clearTagsEntries() {
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
        if (getAssociationData() != null)
            sb.append("AssociationData: ").append(getAssociationData()).append(",");
        if (getAssociationType() != null)
            sb.append("AssociationType: ").append(getAssociationType()).append(",");
        if (getContentArn() != null)
            sb.append("ContentArn: ").append(getContentArn()).append(",");
        if (getContentAssociationArn() != null)
            sb.append("ContentAssociationArn: ").append(getContentAssociationArn()).append(",");
        if (getContentAssociationId() != null)
            sb.append("ContentAssociationId: ").append(getContentAssociationId()).append(",");
        if (getContentId() != null)
            sb.append("ContentId: ").append(getContentId()).append(",");
        if (getKnowledgeBaseArn() != null)
            sb.append("KnowledgeBaseArn: ").append(getKnowledgeBaseArn()).append(",");
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

        if (obj instanceof ContentAssociationData == false)
            return false;
        ContentAssociationData other = (ContentAssociationData) obj;
        if (other.getAssociationData() == null ^ this.getAssociationData() == null)
            return false;
        if (other.getAssociationData() != null && other.getAssociationData().equals(this.getAssociationData()) == false)
            return false;
        if (other.getAssociationType() == null ^ this.getAssociationType() == null)
            return false;
        if (other.getAssociationType() != null && other.getAssociationType().equals(this.getAssociationType()) == false)
            return false;
        if (other.getContentArn() == null ^ this.getContentArn() == null)
            return false;
        if (other.getContentArn() != null && other.getContentArn().equals(this.getContentArn()) == false)
            return false;
        if (other.getContentAssociationArn() == null ^ this.getContentAssociationArn() == null)
            return false;
        if (other.getContentAssociationArn() != null && other.getContentAssociationArn().equals(this.getContentAssociationArn()) == false)
            return false;
        if (other.getContentAssociationId() == null ^ this.getContentAssociationId() == null)
            return false;
        if (other.getContentAssociationId() != null && other.getContentAssociationId().equals(this.getContentAssociationId()) == false)
            return false;
        if (other.getContentId() == null ^ this.getContentId() == null)
            return false;
        if (other.getContentId() != null && other.getContentId().equals(this.getContentId()) == false)
            return false;
        if (other.getKnowledgeBaseArn() == null ^ this.getKnowledgeBaseArn() == null)
            return false;
        if (other.getKnowledgeBaseArn() != null && other.getKnowledgeBaseArn().equals(this.getKnowledgeBaseArn()) == false)
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

        hashCode = prime * hashCode + ((getAssociationData() == null) ? 0 : getAssociationData().hashCode());
        hashCode = prime * hashCode + ((getAssociationType() == null) ? 0 : getAssociationType().hashCode());
        hashCode = prime * hashCode + ((getContentArn() == null) ? 0 : getContentArn().hashCode());
        hashCode = prime * hashCode + ((getContentAssociationArn() == null) ? 0 : getContentAssociationArn().hashCode());
        hashCode = prime * hashCode + ((getContentAssociationId() == null) ? 0 : getContentAssociationId().hashCode());
        hashCode = prime * hashCode + ((getContentId() == null) ? 0 : getContentId().hashCode());
        hashCode = prime * hashCode + ((getKnowledgeBaseArn() == null) ? 0 : getKnowledgeBaseArn().hashCode());
        hashCode = prime * hashCode + ((getKnowledgeBaseId() == null) ? 0 : getKnowledgeBaseId().hashCode());
        hashCode = prime * hashCode + ((getTags() == null) ? 0 : getTags().hashCode());
        return hashCode;
    }

    @Override
    public ContentAssociationData clone() {
        try {
            return (ContentAssociationData) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.qconnect.model.transform.ContentAssociationDataMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
