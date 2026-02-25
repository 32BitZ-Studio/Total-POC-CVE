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
 * The contents of a content association.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qconnect-2020-10-19/ContentAssociationContents"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ContentAssociationContents implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The data of the step-by-step guide association.
     * </p>
     */
    private AmazonConnectGuideAssociationData amazonConnectGuideAssociation;

    /**
     * <p>
     * The data of the step-by-step guide association.
     * </p>
     * 
     * @param amazonConnectGuideAssociation
     *        The data of the step-by-step guide association.
     */

    public void setAmazonConnectGuideAssociation(AmazonConnectGuideAssociationData amazonConnectGuideAssociation) {
        this.amazonConnectGuideAssociation = amazonConnectGuideAssociation;
    }

    /**
     * <p>
     * The data of the step-by-step guide association.
     * </p>
     * 
     * @return The data of the step-by-step guide association.
     */

    public AmazonConnectGuideAssociationData getAmazonConnectGuideAssociation() {
        return this.amazonConnectGuideAssociation;
    }

    /**
     * <p>
     * The data of the step-by-step guide association.
     * </p>
     * 
     * @param amazonConnectGuideAssociation
     *        The data of the step-by-step guide association.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ContentAssociationContents withAmazonConnectGuideAssociation(AmazonConnectGuideAssociationData amazonConnectGuideAssociation) {
        setAmazonConnectGuideAssociation(amazonConnectGuideAssociation);
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
        if (getAmazonConnectGuideAssociation() != null)
            sb.append("AmazonConnectGuideAssociation: ").append(getAmazonConnectGuideAssociation());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ContentAssociationContents == false)
            return false;
        ContentAssociationContents other = (ContentAssociationContents) obj;
        if (other.getAmazonConnectGuideAssociation() == null ^ this.getAmazonConnectGuideAssociation() == null)
            return false;
        if (other.getAmazonConnectGuideAssociation() != null
                && other.getAmazonConnectGuideAssociation().equals(this.getAmazonConnectGuideAssociation()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getAmazonConnectGuideAssociation() == null) ? 0 : getAmazonConnectGuideAssociation().hashCode());
        return hashCode;
    }

    @Override
    public ContentAssociationContents clone() {
        try {
            return (ContentAssociationContents) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.qconnect.model.transform.ContentAssociationContentsMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
