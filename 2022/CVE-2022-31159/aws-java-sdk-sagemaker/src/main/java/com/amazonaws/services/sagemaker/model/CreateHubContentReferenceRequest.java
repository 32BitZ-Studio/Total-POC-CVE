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
package com.amazonaws.services.sagemaker.model;

import java.io.Serializable;
import javax.annotation.Generated;

import com.amazonaws.AmazonWebServiceRequest;

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/sagemaker-2017-07-24/CreateHubContentReference"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class CreateHubContentReferenceRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The name of the hub to add the hub content reference to.
     * </p>
     */
    private String hubName;
    /**
     * <p>
     * The ARN of the public hub content to reference.
     * </p>
     */
    private String sageMakerPublicHubContentArn;
    /**
     * <p>
     * The name of the hub content to reference.
     * </p>
     */
    private String hubContentName;
    /**
     * <p>
     * The minimum version of the hub content to reference.
     * </p>
     */
    private String minVersion;
    /**
     * <p>
     * Any tags associated with the hub content to reference.
     * </p>
     */
    private java.util.List<Tag> tags;

    /**
     * <p>
     * The name of the hub to add the hub content reference to.
     * </p>
     * 
     * @param hubName
     *        The name of the hub to add the hub content reference to.
     */

    public void setHubName(String hubName) {
        this.hubName = hubName;
    }

    /**
     * <p>
     * The name of the hub to add the hub content reference to.
     * </p>
     * 
     * @return The name of the hub to add the hub content reference to.
     */

    public String getHubName() {
        return this.hubName;
    }

    /**
     * <p>
     * The name of the hub to add the hub content reference to.
     * </p>
     * 
     * @param hubName
     *        The name of the hub to add the hub content reference to.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateHubContentReferenceRequest withHubName(String hubName) {
        setHubName(hubName);
        return this;
    }

    /**
     * <p>
     * The ARN of the public hub content to reference.
     * </p>
     * 
     * @param sageMakerPublicHubContentArn
     *        The ARN of the public hub content to reference.
     */

    public void setSageMakerPublicHubContentArn(String sageMakerPublicHubContentArn) {
        this.sageMakerPublicHubContentArn = sageMakerPublicHubContentArn;
    }

    /**
     * <p>
     * The ARN of the public hub content to reference.
     * </p>
     * 
     * @return The ARN of the public hub content to reference.
     */

    public String getSageMakerPublicHubContentArn() {
        return this.sageMakerPublicHubContentArn;
    }

    /**
     * <p>
     * The ARN of the public hub content to reference.
     * </p>
     * 
     * @param sageMakerPublicHubContentArn
     *        The ARN of the public hub content to reference.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateHubContentReferenceRequest withSageMakerPublicHubContentArn(String sageMakerPublicHubContentArn) {
        setSageMakerPublicHubContentArn(sageMakerPublicHubContentArn);
        return this;
    }

    /**
     * <p>
     * The name of the hub content to reference.
     * </p>
     * 
     * @param hubContentName
     *        The name of the hub content to reference.
     */

    public void setHubContentName(String hubContentName) {
        this.hubContentName = hubContentName;
    }

    /**
     * <p>
     * The name of the hub content to reference.
     * </p>
     * 
     * @return The name of the hub content to reference.
     */

    public String getHubContentName() {
        return this.hubContentName;
    }

    /**
     * <p>
     * The name of the hub content to reference.
     * </p>
     * 
     * @param hubContentName
     *        The name of the hub content to reference.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateHubContentReferenceRequest withHubContentName(String hubContentName) {
        setHubContentName(hubContentName);
        return this;
    }

    /**
     * <p>
     * The minimum version of the hub content to reference.
     * </p>
     * 
     * @param minVersion
     *        The minimum version of the hub content to reference.
     */

    public void setMinVersion(String minVersion) {
        this.minVersion = minVersion;
    }

    /**
     * <p>
     * The minimum version of the hub content to reference.
     * </p>
     * 
     * @return The minimum version of the hub content to reference.
     */

    public String getMinVersion() {
        return this.minVersion;
    }

    /**
     * <p>
     * The minimum version of the hub content to reference.
     * </p>
     * 
     * @param minVersion
     *        The minimum version of the hub content to reference.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateHubContentReferenceRequest withMinVersion(String minVersion) {
        setMinVersion(minVersion);
        return this;
    }

    /**
     * <p>
     * Any tags associated with the hub content to reference.
     * </p>
     * 
     * @return Any tags associated with the hub content to reference.
     */

    public java.util.List<Tag> getTags() {
        return tags;
    }

    /**
     * <p>
     * Any tags associated with the hub content to reference.
     * </p>
     * 
     * @param tags
     *        Any tags associated with the hub content to reference.
     */

    public void setTags(java.util.Collection<Tag> tags) {
        if (tags == null) {
            this.tags = null;
            return;
        }

        this.tags = new java.util.ArrayList<Tag>(tags);
    }

    /**
     * <p>
     * Any tags associated with the hub content to reference.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setTags(java.util.Collection)} or {@link #withTags(java.util.Collection)} if you want to override the
     * existing values.
     * </p>
     * 
     * @param tags
     *        Any tags associated with the hub content to reference.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateHubContentReferenceRequest withTags(Tag... tags) {
        if (this.tags == null) {
            setTags(new java.util.ArrayList<Tag>(tags.length));
        }
        for (Tag ele : tags) {
            this.tags.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * Any tags associated with the hub content to reference.
     * </p>
     * 
     * @param tags
     *        Any tags associated with the hub content to reference.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateHubContentReferenceRequest withTags(java.util.Collection<Tag> tags) {
        setTags(tags);
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
        if (getHubName() != null)
            sb.append("HubName: ").append(getHubName()).append(",");
        if (getSageMakerPublicHubContentArn() != null)
            sb.append("SageMakerPublicHubContentArn: ").append(getSageMakerPublicHubContentArn()).append(",");
        if (getHubContentName() != null)
            sb.append("HubContentName: ").append(getHubContentName()).append(",");
        if (getMinVersion() != null)
            sb.append("MinVersion: ").append(getMinVersion()).append(",");
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

        if (obj instanceof CreateHubContentReferenceRequest == false)
            return false;
        CreateHubContentReferenceRequest other = (CreateHubContentReferenceRequest) obj;
        if (other.getHubName() == null ^ this.getHubName() == null)
            return false;
        if (other.getHubName() != null && other.getHubName().equals(this.getHubName()) == false)
            return false;
        if (other.getSageMakerPublicHubContentArn() == null ^ this.getSageMakerPublicHubContentArn() == null)
            return false;
        if (other.getSageMakerPublicHubContentArn() != null && other.getSageMakerPublicHubContentArn().equals(this.getSageMakerPublicHubContentArn()) == false)
            return false;
        if (other.getHubContentName() == null ^ this.getHubContentName() == null)
            return false;
        if (other.getHubContentName() != null && other.getHubContentName().equals(this.getHubContentName()) == false)
            return false;
        if (other.getMinVersion() == null ^ this.getMinVersion() == null)
            return false;
        if (other.getMinVersion() != null && other.getMinVersion().equals(this.getMinVersion()) == false)
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

        hashCode = prime * hashCode + ((getHubName() == null) ? 0 : getHubName().hashCode());
        hashCode = prime * hashCode + ((getSageMakerPublicHubContentArn() == null) ? 0 : getSageMakerPublicHubContentArn().hashCode());
        hashCode = prime * hashCode + ((getHubContentName() == null) ? 0 : getHubContentName().hashCode());
        hashCode = prime * hashCode + ((getMinVersion() == null) ? 0 : getMinVersion().hashCode());
        hashCode = prime * hashCode + ((getTags() == null) ? 0 : getTags().hashCode());
        return hashCode;
    }

    @Override
    public CreateHubContentReferenceRequest clone() {
        return (CreateHubContentReferenceRequest) super.clone();
    }

}
