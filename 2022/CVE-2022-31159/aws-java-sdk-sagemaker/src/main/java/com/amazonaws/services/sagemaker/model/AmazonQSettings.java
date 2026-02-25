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
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * A collection of settings that configure the Amazon Q experience within the domain.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/sagemaker-2017-07-24/AmazonQSettings" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class AmazonQSettings implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * Whether Amazon Q has been enabled within the domain.
     * </p>
     */
    private String status;
    /**
     * <p>
     * The ARN of the Amazon Q profile used within the domain.
     * </p>
     */
    private String qProfileArn;

    /**
     * <p>
     * Whether Amazon Q has been enabled within the domain.
     * </p>
     * 
     * @param status
     *        Whether Amazon Q has been enabled within the domain.
     * @see FeatureStatus
     */

    public void setStatus(String status) {
        this.status = status;
    }

    /**
     * <p>
     * Whether Amazon Q has been enabled within the domain.
     * </p>
     * 
     * @return Whether Amazon Q has been enabled within the domain.
     * @see FeatureStatus
     */

    public String getStatus() {
        return this.status;
    }

    /**
     * <p>
     * Whether Amazon Q has been enabled within the domain.
     * </p>
     * 
     * @param status
     *        Whether Amazon Q has been enabled within the domain.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see FeatureStatus
     */

    public AmazonQSettings withStatus(String status) {
        setStatus(status);
        return this;
    }

    /**
     * <p>
     * Whether Amazon Q has been enabled within the domain.
     * </p>
     * 
     * @param status
     *        Whether Amazon Q has been enabled within the domain.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see FeatureStatus
     */

    public AmazonQSettings withStatus(FeatureStatus status) {
        this.status = status.toString();
        return this;
    }

    /**
     * <p>
     * The ARN of the Amazon Q profile used within the domain.
     * </p>
     * 
     * @param qProfileArn
     *        The ARN of the Amazon Q profile used within the domain.
     */

    public void setQProfileArn(String qProfileArn) {
        this.qProfileArn = qProfileArn;
    }

    /**
     * <p>
     * The ARN of the Amazon Q profile used within the domain.
     * </p>
     * 
     * @return The ARN of the Amazon Q profile used within the domain.
     */

    public String getQProfileArn() {
        return this.qProfileArn;
    }

    /**
     * <p>
     * The ARN of the Amazon Q profile used within the domain.
     * </p>
     * 
     * @param qProfileArn
     *        The ARN of the Amazon Q profile used within the domain.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AmazonQSettings withQProfileArn(String qProfileArn) {
        setQProfileArn(qProfileArn);
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
        if (getStatus() != null)
            sb.append("Status: ").append(getStatus()).append(",");
        if (getQProfileArn() != null)
            sb.append("QProfileArn: ").append(getQProfileArn());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof AmazonQSettings == false)
            return false;
        AmazonQSettings other = (AmazonQSettings) obj;
        if (other.getStatus() == null ^ this.getStatus() == null)
            return false;
        if (other.getStatus() != null && other.getStatus().equals(this.getStatus()) == false)
            return false;
        if (other.getQProfileArn() == null ^ this.getQProfileArn() == null)
            return false;
        if (other.getQProfileArn() != null && other.getQProfileArn().equals(this.getQProfileArn()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getStatus() == null) ? 0 : getStatus().hashCode());
        hashCode = prime * hashCode + ((getQProfileArn() == null) ? 0 : getQProfileArn().hashCode());
        return hashCode;
    }

    @Override
    public AmazonQSettings clone() {
        try {
            return (AmazonQSettings) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.sagemaker.model.transform.AmazonQSettingsMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
