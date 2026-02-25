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
package com.amazonaws.services.stepfunctions.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * Settings to configure server-side encryption.
 * </p>
 * <p>
 * For additional control over security, you can encrypt your data using a <b>customer-managed key</b> for Step
 * Functions state machines and activities. You can configure a symmetric KMS key and data key reuse period when
 * creating or updating a <b>State Machine</b>, and when creating an <b>Activity</b>. The execution history and state
 * machine definition will be encrypted with the key applied to the State Machine. Activity inputs will be encrypted
 * with the key applied to the Activity.
 * </p>
 * <note>
 * <p>
 * Step Functions automatically enables encryption at rest using Amazon Web Services owned keys at no charge. However,
 * KMS charges apply when using a customer managed key. For more information about pricing, see <a
 * href="https://aws.amazon.com/kms/pricing/">Key Management Service pricing</a>.
 * </p>
 * </note>
 * <p>
 * For more information on KMS, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/overview.html">What
 * is Key Management Service?</a>
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/states-2016-11-23/EncryptionConfiguration" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class EncryptionConfiguration implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * An alias, alias ARN, key ID, or key ARN of a symmetric encryption KMS key to encrypt data. To specify a KMS key
     * in a different Amazon Web Services account, you must use the key ARN or alias ARN.
     * </p>
     */
    private String kmsKeyId;
    /**
     * <p>
     * Maximum duration that Step Functions will reuse data keys. When the period expires, Step Functions will call
     * <code>GenerateDataKey</code>. Only applies to customer managed keys.
     * </p>
     */
    private Integer kmsDataKeyReusePeriodSeconds;
    /**
     * <p>
     * Encryption type
     * </p>
     */
    private String type;

    /**
     * <p>
     * An alias, alias ARN, key ID, or key ARN of a symmetric encryption KMS key to encrypt data. To specify a KMS key
     * in a different Amazon Web Services account, you must use the key ARN or alias ARN.
     * </p>
     * 
     * @param kmsKeyId
     *        An alias, alias ARN, key ID, or key ARN of a symmetric encryption KMS key to encrypt data. To specify a
     *        KMS key in a different Amazon Web Services account, you must use the key ARN or alias ARN.
     */

    public void setKmsKeyId(String kmsKeyId) {
        this.kmsKeyId = kmsKeyId;
    }

    /**
     * <p>
     * An alias, alias ARN, key ID, or key ARN of a symmetric encryption KMS key to encrypt data. To specify a KMS key
     * in a different Amazon Web Services account, you must use the key ARN or alias ARN.
     * </p>
     * 
     * @return An alias, alias ARN, key ID, or key ARN of a symmetric encryption KMS key to encrypt data. To specify a
     *         KMS key in a different Amazon Web Services account, you must use the key ARN or alias ARN.
     */

    public String getKmsKeyId() {
        return this.kmsKeyId;
    }

    /**
     * <p>
     * An alias, alias ARN, key ID, or key ARN of a symmetric encryption KMS key to encrypt data. To specify a KMS key
     * in a different Amazon Web Services account, you must use the key ARN or alias ARN.
     * </p>
     * 
     * @param kmsKeyId
     *        An alias, alias ARN, key ID, or key ARN of a symmetric encryption KMS key to encrypt data. To specify a
     *        KMS key in a different Amazon Web Services account, you must use the key ARN or alias ARN.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public EncryptionConfiguration withKmsKeyId(String kmsKeyId) {
        setKmsKeyId(kmsKeyId);
        return this;
    }

    /**
     * <p>
     * Maximum duration that Step Functions will reuse data keys. When the period expires, Step Functions will call
     * <code>GenerateDataKey</code>. Only applies to customer managed keys.
     * </p>
     * 
     * @param kmsDataKeyReusePeriodSeconds
     *        Maximum duration that Step Functions will reuse data keys. When the period expires, Step Functions will
     *        call <code>GenerateDataKey</code>. Only applies to customer managed keys.
     */

    public void setKmsDataKeyReusePeriodSeconds(Integer kmsDataKeyReusePeriodSeconds) {
        this.kmsDataKeyReusePeriodSeconds = kmsDataKeyReusePeriodSeconds;
    }

    /**
     * <p>
     * Maximum duration that Step Functions will reuse data keys. When the period expires, Step Functions will call
     * <code>GenerateDataKey</code>. Only applies to customer managed keys.
     * </p>
     * 
     * @return Maximum duration that Step Functions will reuse data keys. When the period expires, Step Functions will
     *         call <code>GenerateDataKey</code>. Only applies to customer managed keys.
     */

    public Integer getKmsDataKeyReusePeriodSeconds() {
        return this.kmsDataKeyReusePeriodSeconds;
    }

    /**
     * <p>
     * Maximum duration that Step Functions will reuse data keys. When the period expires, Step Functions will call
     * <code>GenerateDataKey</code>. Only applies to customer managed keys.
     * </p>
     * 
     * @param kmsDataKeyReusePeriodSeconds
     *        Maximum duration that Step Functions will reuse data keys. When the period expires, Step Functions will
     *        call <code>GenerateDataKey</code>. Only applies to customer managed keys.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public EncryptionConfiguration withKmsDataKeyReusePeriodSeconds(Integer kmsDataKeyReusePeriodSeconds) {
        setKmsDataKeyReusePeriodSeconds(kmsDataKeyReusePeriodSeconds);
        return this;
    }

    /**
     * <p>
     * Encryption type
     * </p>
     * 
     * @param type
     *        Encryption type
     * @see EncryptionType
     */

    public void setType(String type) {
        this.type = type;
    }

    /**
     * <p>
     * Encryption type
     * </p>
     * 
     * @return Encryption type
     * @see EncryptionType
     */

    public String getType() {
        return this.type;
    }

    /**
     * <p>
     * Encryption type
     * </p>
     * 
     * @param type
     *        Encryption type
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see EncryptionType
     */

    public EncryptionConfiguration withType(String type) {
        setType(type);
        return this;
    }

    /**
     * <p>
     * Encryption type
     * </p>
     * 
     * @param type
     *        Encryption type
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see EncryptionType
     */

    public EncryptionConfiguration withType(EncryptionType type) {
        this.type = type.toString();
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
            sb.append("KmsKeyId: ").append(getKmsKeyId()).append(",");
        if (getKmsDataKeyReusePeriodSeconds() != null)
            sb.append("KmsDataKeyReusePeriodSeconds: ").append(getKmsDataKeyReusePeriodSeconds()).append(",");
        if (getType() != null)
            sb.append("Type: ").append(getType());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof EncryptionConfiguration == false)
            return false;
        EncryptionConfiguration other = (EncryptionConfiguration) obj;
        if (other.getKmsKeyId() == null ^ this.getKmsKeyId() == null)
            return false;
        if (other.getKmsKeyId() != null && other.getKmsKeyId().equals(this.getKmsKeyId()) == false)
            return false;
        if (other.getKmsDataKeyReusePeriodSeconds() == null ^ this.getKmsDataKeyReusePeriodSeconds() == null)
            return false;
        if (other.getKmsDataKeyReusePeriodSeconds() != null && other.getKmsDataKeyReusePeriodSeconds().equals(this.getKmsDataKeyReusePeriodSeconds()) == false)
            return false;
        if (other.getType() == null ^ this.getType() == null)
            return false;
        if (other.getType() != null && other.getType().equals(this.getType()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getKmsKeyId() == null) ? 0 : getKmsKeyId().hashCode());
        hashCode = prime * hashCode + ((getKmsDataKeyReusePeriodSeconds() == null) ? 0 : getKmsDataKeyReusePeriodSeconds().hashCode());
        hashCode = prime * hashCode + ((getType() == null) ? 0 : getType().hashCode());
        return hashCode;
    }

    @Override
    public EncryptionConfiguration clone() {
        try {
            return (EncryptionConfiguration) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.stepfunctions.model.transform.EncryptionConfigurationMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
