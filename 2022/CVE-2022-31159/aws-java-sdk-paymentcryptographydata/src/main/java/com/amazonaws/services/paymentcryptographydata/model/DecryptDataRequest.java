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

import com.amazonaws.AmazonWebServiceRequest;

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/payment-cryptography-data-2022-02-03/DecryptData"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class DecryptDataRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The <code>keyARN</code> of the encryption key that Amazon Web Services Payment Cryptography uses for ciphertext
     * decryption.
     * </p>
     * <p>
     * When a WrappedKeyBlock is provided, this value will be the identifier to the key wrapping key. Otherwise, it is
     * the key identifier used to perform the operation.
     * </p>
     */
    private String keyIdentifier;
    /**
     * <p>
     * The ciphertext to decrypt.
     * </p>
     */
    private String cipherText;
    /**
     * <p>
     * The encryption key type and attributes for ciphertext decryption.
     * </p>
     */
    private EncryptionDecryptionAttributes decryptionAttributes;
    /**
     * <p>
     * The WrappedKeyBlock containing the encryption key for ciphertext decryption.
     * </p>
     */
    private WrappedKey wrappedKey;

    /**
     * <p>
     * The <code>keyARN</code> of the encryption key that Amazon Web Services Payment Cryptography uses for ciphertext
     * decryption.
     * </p>
     * <p>
     * When a WrappedKeyBlock is provided, this value will be the identifier to the key wrapping key. Otherwise, it is
     * the key identifier used to perform the operation.
     * </p>
     * 
     * @param keyIdentifier
     *        The <code>keyARN</code> of the encryption key that Amazon Web Services Payment Cryptography uses for
     *        ciphertext decryption.</p>
     *        <p>
     *        When a WrappedKeyBlock is provided, this value will be the identifier to the key wrapping key. Otherwise,
     *        it is the key identifier used to perform the operation.
     */

    public void setKeyIdentifier(String keyIdentifier) {
        this.keyIdentifier = keyIdentifier;
    }

    /**
     * <p>
     * The <code>keyARN</code> of the encryption key that Amazon Web Services Payment Cryptography uses for ciphertext
     * decryption.
     * </p>
     * <p>
     * When a WrappedKeyBlock is provided, this value will be the identifier to the key wrapping key. Otherwise, it is
     * the key identifier used to perform the operation.
     * </p>
     * 
     * @return The <code>keyARN</code> of the encryption key that Amazon Web Services Payment Cryptography uses for
     *         ciphertext decryption.</p>
     *         <p>
     *         When a WrappedKeyBlock is provided, this value will be the identifier to the key wrapping key. Otherwise,
     *         it is the key identifier used to perform the operation.
     */

    public String getKeyIdentifier() {
        return this.keyIdentifier;
    }

    /**
     * <p>
     * The <code>keyARN</code> of the encryption key that Amazon Web Services Payment Cryptography uses for ciphertext
     * decryption.
     * </p>
     * <p>
     * When a WrappedKeyBlock is provided, this value will be the identifier to the key wrapping key. Otherwise, it is
     * the key identifier used to perform the operation.
     * </p>
     * 
     * @param keyIdentifier
     *        The <code>keyARN</code> of the encryption key that Amazon Web Services Payment Cryptography uses for
     *        ciphertext decryption.</p>
     *        <p>
     *        When a WrappedKeyBlock is provided, this value will be the identifier to the key wrapping key. Otherwise,
     *        it is the key identifier used to perform the operation.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DecryptDataRequest withKeyIdentifier(String keyIdentifier) {
        setKeyIdentifier(keyIdentifier);
        return this;
    }

    /**
     * <p>
     * The ciphertext to decrypt.
     * </p>
     * 
     * @param cipherText
     *        The ciphertext to decrypt.
     */

    public void setCipherText(String cipherText) {
        this.cipherText = cipherText;
    }

    /**
     * <p>
     * The ciphertext to decrypt.
     * </p>
     * 
     * @return The ciphertext to decrypt.
     */

    public String getCipherText() {
        return this.cipherText;
    }

    /**
     * <p>
     * The ciphertext to decrypt.
     * </p>
     * 
     * @param cipherText
     *        The ciphertext to decrypt.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DecryptDataRequest withCipherText(String cipherText) {
        setCipherText(cipherText);
        return this;
    }

    /**
     * <p>
     * The encryption key type and attributes for ciphertext decryption.
     * </p>
     * 
     * @param decryptionAttributes
     *        The encryption key type and attributes for ciphertext decryption.
     */

    public void setDecryptionAttributes(EncryptionDecryptionAttributes decryptionAttributes) {
        this.decryptionAttributes = decryptionAttributes;
    }

    /**
     * <p>
     * The encryption key type and attributes for ciphertext decryption.
     * </p>
     * 
     * @return The encryption key type and attributes for ciphertext decryption.
     */

    public EncryptionDecryptionAttributes getDecryptionAttributes() {
        return this.decryptionAttributes;
    }

    /**
     * <p>
     * The encryption key type and attributes for ciphertext decryption.
     * </p>
     * 
     * @param decryptionAttributes
     *        The encryption key type and attributes for ciphertext decryption.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DecryptDataRequest withDecryptionAttributes(EncryptionDecryptionAttributes decryptionAttributes) {
        setDecryptionAttributes(decryptionAttributes);
        return this;
    }

    /**
     * <p>
     * The WrappedKeyBlock containing the encryption key for ciphertext decryption.
     * </p>
     * 
     * @param wrappedKey
     *        The WrappedKeyBlock containing the encryption key for ciphertext decryption.
     */

    public void setWrappedKey(WrappedKey wrappedKey) {
        this.wrappedKey = wrappedKey;
    }

    /**
     * <p>
     * The WrappedKeyBlock containing the encryption key for ciphertext decryption.
     * </p>
     * 
     * @return The WrappedKeyBlock containing the encryption key for ciphertext decryption.
     */

    public WrappedKey getWrappedKey() {
        return this.wrappedKey;
    }

    /**
     * <p>
     * The WrappedKeyBlock containing the encryption key for ciphertext decryption.
     * </p>
     * 
     * @param wrappedKey
     *        The WrappedKeyBlock containing the encryption key for ciphertext decryption.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DecryptDataRequest withWrappedKey(WrappedKey wrappedKey) {
        setWrappedKey(wrappedKey);
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
        if (getKeyIdentifier() != null)
            sb.append("KeyIdentifier: ").append(getKeyIdentifier()).append(",");
        if (getCipherText() != null)
            sb.append("CipherText: ").append("***Sensitive Data Redacted***").append(",");
        if (getDecryptionAttributes() != null)
            sb.append("DecryptionAttributes: ").append(getDecryptionAttributes()).append(",");
        if (getWrappedKey() != null)
            sb.append("WrappedKey: ").append(getWrappedKey());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof DecryptDataRequest == false)
            return false;
        DecryptDataRequest other = (DecryptDataRequest) obj;
        if (other.getKeyIdentifier() == null ^ this.getKeyIdentifier() == null)
            return false;
        if (other.getKeyIdentifier() != null && other.getKeyIdentifier().equals(this.getKeyIdentifier()) == false)
            return false;
        if (other.getCipherText() == null ^ this.getCipherText() == null)
            return false;
        if (other.getCipherText() != null && other.getCipherText().equals(this.getCipherText()) == false)
            return false;
        if (other.getDecryptionAttributes() == null ^ this.getDecryptionAttributes() == null)
            return false;
        if (other.getDecryptionAttributes() != null && other.getDecryptionAttributes().equals(this.getDecryptionAttributes()) == false)
            return false;
        if (other.getWrappedKey() == null ^ this.getWrappedKey() == null)
            return false;
        if (other.getWrappedKey() != null && other.getWrappedKey().equals(this.getWrappedKey()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getKeyIdentifier() == null) ? 0 : getKeyIdentifier().hashCode());
        hashCode = prime * hashCode + ((getCipherText() == null) ? 0 : getCipherText().hashCode());
        hashCode = prime * hashCode + ((getDecryptionAttributes() == null) ? 0 : getDecryptionAttributes().hashCode());
        hashCode = prime * hashCode + ((getWrappedKey() == null) ? 0 : getWrappedKey().hashCode());
        return hashCode;
    }

    @Override
    public DecryptDataRequest clone() {
        return (DecryptDataRequest) super.clone();
    }

}
