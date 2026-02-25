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
package com.amazonaws.services.networkmanager.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * Describes proposed changes to a network function group.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/networkmanager-2019-07-05/ProposedNetworkFunctionGroupChange"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ProposedNetworkFunctionGroupChange implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The list of proposed changes to the key-value tags associated with the network function group.
     * </p>
     */
    private java.util.List<Tag> tags;
    /**
     * <p>
     * The proposed new attachment policy rule number for the network function group.
     * </p>
     */
    private Integer attachmentPolicyRuleNumber;
    /**
     * <p>
     * The proposed name change for the network function group name.
     * </p>
     */
    private String networkFunctionGroupName;

    /**
     * <p>
     * The list of proposed changes to the key-value tags associated with the network function group.
     * </p>
     * 
     * @return The list of proposed changes to the key-value tags associated with the network function group.
     */

    public java.util.List<Tag> getTags() {
        return tags;
    }

    /**
     * <p>
     * The list of proposed changes to the key-value tags associated with the network function group.
     * </p>
     * 
     * @param tags
     *        The list of proposed changes to the key-value tags associated with the network function group.
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
     * The list of proposed changes to the key-value tags associated with the network function group.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setTags(java.util.Collection)} or {@link #withTags(java.util.Collection)} if you want to override the
     * existing values.
     * </p>
     * 
     * @param tags
     *        The list of proposed changes to the key-value tags associated with the network function group.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ProposedNetworkFunctionGroupChange withTags(Tag... tags) {
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
     * The list of proposed changes to the key-value tags associated with the network function group.
     * </p>
     * 
     * @param tags
     *        The list of proposed changes to the key-value tags associated with the network function group.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ProposedNetworkFunctionGroupChange withTags(java.util.Collection<Tag> tags) {
        setTags(tags);
        return this;
    }

    /**
     * <p>
     * The proposed new attachment policy rule number for the network function group.
     * </p>
     * 
     * @param attachmentPolicyRuleNumber
     *        The proposed new attachment policy rule number for the network function group.
     */

    public void setAttachmentPolicyRuleNumber(Integer attachmentPolicyRuleNumber) {
        this.attachmentPolicyRuleNumber = attachmentPolicyRuleNumber;
    }

    /**
     * <p>
     * The proposed new attachment policy rule number for the network function group.
     * </p>
     * 
     * @return The proposed new attachment policy rule number for the network function group.
     */

    public Integer getAttachmentPolicyRuleNumber() {
        return this.attachmentPolicyRuleNumber;
    }

    /**
     * <p>
     * The proposed new attachment policy rule number for the network function group.
     * </p>
     * 
     * @param attachmentPolicyRuleNumber
     *        The proposed new attachment policy rule number for the network function group.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ProposedNetworkFunctionGroupChange withAttachmentPolicyRuleNumber(Integer attachmentPolicyRuleNumber) {
        setAttachmentPolicyRuleNumber(attachmentPolicyRuleNumber);
        return this;
    }

    /**
     * <p>
     * The proposed name change for the network function group name.
     * </p>
     * 
     * @param networkFunctionGroupName
     *        The proposed name change for the network function group name.
     */

    public void setNetworkFunctionGroupName(String networkFunctionGroupName) {
        this.networkFunctionGroupName = networkFunctionGroupName;
    }

    /**
     * <p>
     * The proposed name change for the network function group name.
     * </p>
     * 
     * @return The proposed name change for the network function group name.
     */

    public String getNetworkFunctionGroupName() {
        return this.networkFunctionGroupName;
    }

    /**
     * <p>
     * The proposed name change for the network function group name.
     * </p>
     * 
     * @param networkFunctionGroupName
     *        The proposed name change for the network function group name.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ProposedNetworkFunctionGroupChange withNetworkFunctionGroupName(String networkFunctionGroupName) {
        setNetworkFunctionGroupName(networkFunctionGroupName);
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
        if (getTags() != null)
            sb.append("Tags: ").append(getTags()).append(",");
        if (getAttachmentPolicyRuleNumber() != null)
            sb.append("AttachmentPolicyRuleNumber: ").append(getAttachmentPolicyRuleNumber()).append(",");
        if (getNetworkFunctionGroupName() != null)
            sb.append("NetworkFunctionGroupName: ").append(getNetworkFunctionGroupName());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ProposedNetworkFunctionGroupChange == false)
            return false;
        ProposedNetworkFunctionGroupChange other = (ProposedNetworkFunctionGroupChange) obj;
        if (other.getTags() == null ^ this.getTags() == null)
            return false;
        if (other.getTags() != null && other.getTags().equals(this.getTags()) == false)
            return false;
        if (other.getAttachmentPolicyRuleNumber() == null ^ this.getAttachmentPolicyRuleNumber() == null)
            return false;
        if (other.getAttachmentPolicyRuleNumber() != null && other.getAttachmentPolicyRuleNumber().equals(this.getAttachmentPolicyRuleNumber()) == false)
            return false;
        if (other.getNetworkFunctionGroupName() == null ^ this.getNetworkFunctionGroupName() == null)
            return false;
        if (other.getNetworkFunctionGroupName() != null && other.getNetworkFunctionGroupName().equals(this.getNetworkFunctionGroupName()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getTags() == null) ? 0 : getTags().hashCode());
        hashCode = prime * hashCode + ((getAttachmentPolicyRuleNumber() == null) ? 0 : getAttachmentPolicyRuleNumber().hashCode());
        hashCode = prime * hashCode + ((getNetworkFunctionGroupName() == null) ? 0 : getNetworkFunctionGroupName().hashCode());
        return hashCode;
    }

    @Override
    public ProposedNetworkFunctionGroupChange clone() {
        try {
            return (ProposedNetworkFunctionGroupChange) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.networkmanager.model.transform.ProposedNetworkFunctionGroupChangeMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
