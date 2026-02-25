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
package com.amazonaws.services.medialive.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * The decryption settings for the SRT caller source. Present only if the source has decryption enabled.
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/medialive-2017-10-14/SrtCallerDecryption" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class SrtCallerDecryption implements Serializable, Cloneable, StructuredPojo {

    /** The algorithm used to encrypt content. */
    private String algorithm;
    /**
     * The ARN for the secret in Secrets Manager. Someone in your organization must create a secret and provide you with
     * its ARN. The secret holds the passphrase that MediaLive uses to decrypt the source content.
     */
    private String passphraseSecretArn;

    /**
     * The algorithm used to encrypt content.
     * 
     * @param algorithm
     *        The algorithm used to encrypt content.
     * @see Algorithm
     */

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * The algorithm used to encrypt content.
     * 
     * @return The algorithm used to encrypt content.
     * @see Algorithm
     */

    public String getAlgorithm() {
        return this.algorithm;
    }

    /**
     * The algorithm used to encrypt content.
     * 
     * @param algorithm
     *        The algorithm used to encrypt content.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see Algorithm
     */

    public SrtCallerDecryption withAlgorithm(String algorithm) {
        setAlgorithm(algorithm);
        return this;
    }

    /**
     * The algorithm used to encrypt content.
     * 
     * @param algorithm
     *        The algorithm used to encrypt content.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see Algorithm
     */

    public SrtCallerDecryption withAlgorithm(Algorithm algorithm) {
        this.algorithm = algorithm.toString();
        return this;
    }

    /**
     * The ARN for the secret in Secrets Manager. Someone in your organization must create a secret and provide you with
     * its ARN. The secret holds the passphrase that MediaLive uses to decrypt the source content.
     * 
     * @param passphraseSecretArn
     *        The ARN for the secret in Secrets Manager. Someone in your organization must create a secret and provide
     *        you with its ARN. The secret holds the passphrase that MediaLive uses to decrypt the source content.
     */

    public void setPassphraseSecretArn(String passphraseSecretArn) {
        this.passphraseSecretArn = passphraseSecretArn;
    }

    /**
     * The ARN for the secret in Secrets Manager. Someone in your organization must create a secret and provide you with
     * its ARN. The secret holds the passphrase that MediaLive uses to decrypt the source content.
     * 
     * @return The ARN for the secret in Secrets Manager. Someone in your organization must create a secret and provide
     *         you with its ARN. The secret holds the passphrase that MediaLive uses to decrypt the source content.
     */

    public String getPassphraseSecretArn() {
        return this.passphraseSecretArn;
    }

    /**
     * The ARN for the secret in Secrets Manager. Someone in your organization must create a secret and provide you with
     * its ARN. The secret holds the passphrase that MediaLive uses to decrypt the source content.
     * 
     * @param passphraseSecretArn
     *        The ARN for the secret in Secrets Manager. Someone in your organization must create a secret and provide
     *        you with its ARN. The secret holds the passphrase that MediaLive uses to decrypt the source content.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public SrtCallerDecryption withPassphraseSecretArn(String passphraseSecretArn) {
        setPassphraseSecretArn(passphraseSecretArn);
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
        if (getAlgorithm() != null)
            sb.append("Algorithm: ").append(getAlgorithm()).append(",");
        if (getPassphraseSecretArn() != null)
            sb.append("PassphraseSecretArn: ").append(getPassphraseSecretArn());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof SrtCallerDecryption == false)
            return false;
        SrtCallerDecryption other = (SrtCallerDecryption) obj;
        if (other.getAlgorithm() == null ^ this.getAlgorithm() == null)
            return false;
        if (other.getAlgorithm() != null && other.getAlgorithm().equals(this.getAlgorithm()) == false)
            return false;
        if (other.getPassphraseSecretArn() == null ^ this.getPassphraseSecretArn() == null)
            return false;
        if (other.getPassphraseSecretArn() != null && other.getPassphraseSecretArn().equals(this.getPassphraseSecretArn()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getAlgorithm() == null) ? 0 : getAlgorithm().hashCode());
        hashCode = prime * hashCode + ((getPassphraseSecretArn() == null) ? 0 : getPassphraseSecretArn().hashCode());
        return hashCode;
    }

    @Override
    public SrtCallerDecryption clone() {
        try {
            return (SrtCallerDecryption) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.medialive.model.transform.SrtCallerDecryptionMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
