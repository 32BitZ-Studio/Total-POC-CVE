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
 * An optional Key Management Service key to encrypt, decrypt, and re-encrypt model package information for regulated
 * workloads with highly sensitive data.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/sagemaker-2017-07-24/ModelPackageSecurityConfig"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ModelPackageSecurityConfig implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The KMS Key ID (<code>KMSKeyId</code>) used for encryption of model package information.
     * </p>
     */
    private String kmsKeyId;

    /**
     * <p>
     * The KMS Key ID (<code>KMSKeyId</code>) used for encryption of model package information.
     * </p>
     * 
     * @param kmsKeyId
     *        The KMS Key ID (<code>KMSKeyId</code>) used for encryption of model package information.
     */

    public void setKmsKeyId(String kmsKeyId) {
        this.kmsKeyId = kmsKeyId;
    }

    /**
     * <p>
     * The KMS Key ID (<code>KMSKeyId</code>) used for encryption of model package information.
     * </p>
     * 
     * @return The KMS Key ID (<code>KMSKeyId</code>) used for encryption of model package information.
     */

    public String getKmsKeyId() {
        return this.kmsKeyId;
    }

    /**
     * <p>
     * The KMS Key ID (<code>KMSKeyId</code>) used for encryption of model package information.
     * </p>
     * 
     * @param kmsKeyId
     *        The KMS Key ID (<code>KMSKeyId</code>) used for encryption of model package information.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ModelPackageSecurityConfig withKmsKeyId(String kmsKeyId) {
        setKmsKeyId(kmsKeyId);
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
        if (getKmsKeyId() != null)
            sb.append("KmsKeyId: ").append(getKmsKeyId());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ModelPackageSecurityConfig == false)
            return false;
        ModelPackageSecurityConfig other = (ModelPackageSecurityConfig) obj;
        if (other.getKmsKeyId() == null ^ this.getKmsKeyId() == null)
            return false;
        if (other.getKmsKeyId() != null && other.getKmsKeyId().equals(this.getKmsKeyId()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getKmsKeyId() == null) ? 0 : getKmsKeyId().hashCode());
        return hashCode;
    }

    @Override
    public ModelPackageSecurityConfig clone() {
        try {
            return (ModelPackageSecurityConfig) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.sagemaker.model.transform.ModelPackageSecurityConfigMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
