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
package com.amazonaws.services.paymentcryptographydata.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * Parameter information of a WrappedKeyBlock for encryption key exchange.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/payment-cryptography-data-2022-02-03/WrappedKey"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class WrappedKey implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * Parameter information of a WrappedKeyBlock for encryption key exchange.
     * </p>
     */
    private WrappedKeyMaterial wrappedKeyMaterial;
    /**
     * <p>
     * The algorithm that Amazon Web Services Payment Cryptography uses to calculate the key check value (KCV). It is
     * used to validate the key integrity.
     * </p>
     * <p>
     * For TDES keys, the KCV is computed by encrypting 8 bytes, each with value of zero, with the key to be checked and
     * retaining the 3 highest order bytes of the encrypted result. For AES keys, the KCV is computed using a CMAC
     * algorithm where the input data is 16 bytes of zero and retaining the 3 highest order bytes of the encrypted
     * result.
     * </p>
     */
    private String keyCheckValueAlgorithm;

    /**
     * <p>
     * Parameter information of a WrappedKeyBlock for encryption key exchange.
     * </p>
     * 
     * @param wrappedKeyMaterial
     *        Parameter information of a WrappedKeyBlock for encryption key exchange.
     */

    public void setWrappedKeyMaterial(WrappedKeyMaterial wrappedKeyMaterial) {
        this.wrappedKeyMaterial = wrappedKeyMaterial;
    }

    /**
     * <p>
     * Parameter information of a WrappedKeyBlock for encryption key exchange.
     * </p>
     * 
     * @return Parameter information of a WrappedKeyBlock for encryption key exchange.
     */

    public WrappedKeyMaterial getWrappedKeyMaterial() {
        return this.wrappedKeyMaterial;
    }

    /**
     * <p>
     * Parameter information of a WrappedKeyBlock for encryption key exchange.
     * </p>
     * 
     * @param wrappedKeyMaterial
     *        Parameter information of a WrappedKeyBlock for encryption key exchange.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public WrappedKey withWrappedKeyMaterial(WrappedKeyMaterial wrappedKeyMaterial) {
        setWrappedKeyMaterial(wrappedKeyMaterial);
        return this;
    }

    /**
     * <p>
     * The algorithm that Amazon Web Services Payment Cryptography uses to calculate the key check value (KCV). It is
     * used to validate the key integrity.
     * </p>
     * <p>
     * For TDES keys, the KCV is computed by encrypting 8 bytes, each with value of zero, with the key to be checked and
     * retaining the 3 highest order bytes of the encrypted result. For AES keys, the KCV is computed using a CMAC
     * algorithm where the input data is 16 bytes of zero and retaining the 3 highest order bytes of the encrypted
     * result.
     * </p>
     * 
     * @param keyCheckValueAlgorithm
     *        The algorithm that Amazon Web Services Payment Cryptography uses to calculate the key check value (KCV).
     *        It is used to validate the key integrity.</p>
     *        <p>
     *        For TDES keys, the KCV is computed by encrypting 8 bytes, each with value of zero, with the key to be
     *        checked and retaining the 3 highest order bytes of the encrypted result. For AES keys, the KCV is computed
     *        using a CMAC algorithm where the input data is 16 bytes of zero and retaining the 3 highest order bytes of
     *        the encrypted result.
     * @see KeyCheckValueAlgorithm
     */

    public void setKeyCheckValueAlgorithm(String keyCheckValueAlgorithm) {
        this.keyCheckValueAlgorithm = keyCheckValueAlgorithm;
    }

    /**
     * <p>
     * The algorithm that Amazon Web Services Payment Cryptography uses to calculate the key check value (KCV). It is
     * used to validate the key integrity.
     * </p>
     * <p>
     * For TDES keys, the KCV is computed by encrypting 8 bytes, each with value of zero, with the key to be checked and
     * retaining the 3 highest order bytes of the encrypted result. For AES keys, the KCV is computed using a CMAC
     * algorithm where the input data is 16 bytes of zero and retaining the 3 highest order bytes of the encrypted
     * result.
     * </p>
     * 
     * @return The algorithm that Amazon Web Services Payment Cryptography uses to calculate the key check value (KCV).
     *         It is used to validate the key integrity.</p>
     *         <p>
     *         For TDES keys, the KCV is computed by encrypting 8 bytes, each with value of zero, with the key to be
     *         checked and retaining the 3 highest order bytes of the encrypted result. For AES keys, the KCV is
     *         computed using a CMAC algorithm where the input data is 16 bytes of zero and retaining the 3 highest
     *         order bytes of the encrypted result.
     * @see KeyCheckValueAlgorithm
     */

    public String getKeyCheckValueAlgorithm() {
        return this.keyCheckValueAlgorithm;
    }

    /**
     * <p>
     * The algorithm that Amazon Web Services Payment Cryptography uses to calculate the key check value (KCV). It is
     * used to validate the key integrity.
     * </p>
     * <p>
     * For TDES keys, the KCV is computed by encrypting 8 bytes, each with value of zero, with the key to be checked and
     * retaining the 3 highest order bytes of the encrypted result. For AES keys, the KCV is computed using a CMAC
     * algorithm where the input data is 16 bytes of zero and retaining the 3 highest order bytes of the encrypted
     * result.
     * </p>
     * 
     * @param keyCheckValueAlgorithm
     *        The algorithm that Amazon Web Services Payment Cryptography uses to calculate the key check value (KCV).
     *        It is used to validate the key integrity.</p>
     *        <p>
     *        For TDES keys, the KCV is computed by encrypting 8 bytes, each with value of zero, with the key to be
     *        checked and retaining the 3 highest order bytes of the encrypted result. For AES keys, the KCV is computed
     *        using a CMAC algorithm where the input data is 16 bytes of zero and retaining the 3 highest order bytes of
     *        the encrypted result.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see KeyCheckValueAlgorithm
     */

    public WrappedKey withKeyCheckValueAlgorithm(String keyCheckValueAlgorithm) {
        setKeyCheckValueAlgorithm(keyCheckValueAlgorithm);
        return this;
    }

    /**
     * <p>
     * The algorithm that Amazon Web Services Payment Cryptography uses to calculate the key check value (KCV). It is
     * used to validate the key integrity.
     * </p>
     * <p>
     * For TDES keys, the KCV is computed by encrypting 8 bytes, each with value of zero, with the key to be checked and
     * retaining the 3 highest order bytes of the encrypted result. For AES keys, the KCV is computed using a CMAC
     * algorithm where the input data is 16 bytes of zero and retaining the 3 highest order bytes of the encrypted
     * result.
     * </p>
     * 
     * @param keyCheckValueAlgorithm
     *        The algorithm that Amazon Web Services Payment Cryptography uses to calculate the key check value (KCV).
     *        It is used to validate the key integrity.</p>
     *        <p>
     *        For TDES keys, the KCV is computed by encrypting 8 bytes, each with value of zero, with the key to be
     *        checked and retaining the 3 highest order bytes of the encrypted result. For AES keys, the KCV is computed
     *        using a CMAC algorithm where the input data is 16 bytes of zero and retaining the 3 highest order bytes of
     *        the encrypted result.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see KeyCheckValueAlgorithm
     */

    public WrappedKey withKeyCheckValueAlgorithm(KeyCheckValueAlgorithm keyCheckValueAlgorithm) {
        this.keyCheckValueAlgorithm = keyCheckValueAlgorithm.toString();
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
        if (getWrappedKeyMaterial() != null)
            sb.append("WrappedKeyMaterial: ").append(getWrappedKeyMaterial()).append(",");
        if (getKeyCheckValueAlgorithm() != null)
            sb.append("KeyCheckValueAlgorithm: ").append(getKeyCheckValueAlgorithm());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof WrappedKey == false)
            return false;
        WrappedKey other = (WrappedKey) obj;
        if (other.getWrappedKeyMaterial() == null ^ this.getWrappedKeyMaterial() == null)
            return false;
        if (other.getWrappedKeyMaterial() != null && other.getWrappedKeyMaterial().equals(this.getWrappedKeyMaterial()) == false)
            return false;
        if (other.getKeyCheckValueAlgorithm() == null ^ this.getKeyCheckValueAlgorithm() == null)
            return false;
        if (other.getKeyCheckValueAlgorithm() != null && other.getKeyCheckValueAlgorithm().equals(this.getKeyCheckValueAlgorithm()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getWrappedKeyMaterial() == null) ? 0 : getWrappedKeyMaterial().hashCode());
        hashCode = prime * hashCode + ((getKeyCheckValueAlgorithm() == null) ? 0 : getKeyCheckValueAlgorithm().hashCode());
        return hashCode;
    }

    @Override
    public WrappedKey clone() {
        try {
            return (WrappedKey) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.paymentcryptographydata.model.transform.WrappedKeyMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
