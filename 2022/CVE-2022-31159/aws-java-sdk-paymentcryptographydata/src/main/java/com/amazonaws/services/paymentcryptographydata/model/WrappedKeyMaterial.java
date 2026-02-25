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
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/payment-cryptography-data-2022-02-03/WrappedKeyMaterial"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class WrappedKeyMaterial implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The TR-31 wrapped key block.
     * </p>
     */
    private String tr31KeyBlock;

    /**
     * <p>
     * The TR-31 wrapped key block.
     * </p>
     * 
     * @param tr31KeyBlock
     *        The TR-31 wrapped key block.
     */

    public void setTr31KeyBlock(String tr31KeyBlock) {
        this.tr31KeyBlock = tr31KeyBlock;
    }

    /**
     * <p>
     * The TR-31 wrapped key block.
     * </p>
     * 
     * @return The TR-31 wrapped key block.
     */

    public String getTr31KeyBlock() {
        return this.tr31KeyBlock;
    }

    /**
     * <p>
     * The TR-31 wrapped key block.
     * </p>
     * 
     * @param tr31KeyBlock
     *        The TR-31 wrapped key block.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public WrappedKeyMaterial withTr31KeyBlock(String tr31KeyBlock) {
        setTr31KeyBlock(tr31KeyBlock);
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
        if (getTr31KeyBlock() != null)
            sb.append("Tr31KeyBlock: ").append("***Sensitive Data Redacted***");
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof WrappedKeyMaterial == false)
            return false;
        WrappedKeyMaterial other = (WrappedKeyMaterial) obj;
        if (other.getTr31KeyBlock() == null ^ this.getTr31KeyBlock() == null)
            return false;
        if (other.getTr31KeyBlock() != null && other.getTr31KeyBlock().equals(this.getTr31KeyBlock()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getTr31KeyBlock() == null) ? 0 : getTr31KeyBlock().hashCode());
        return hashCode;
    }

    @Override
    public WrappedKeyMaterial clone() {
        try {
            return (WrappedKeyMaterial) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.paymentcryptographydata.model.transform.WrappedKeyMaterialMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
