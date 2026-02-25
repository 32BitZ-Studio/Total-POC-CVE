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
package com.amazonaws.services.taxsettings.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * Additional tax information in India.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/IndiaAdditionalInfo" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class IndiaAdditionalInfo implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * India pan information associated with the account.
     * </p>
     */
    private String pan;

    /**
     * <p>
     * India pan information associated with the account.
     * </p>
     * 
     * @param pan
     *        India pan information associated with the account.
     */

    public void setPan(String pan) {
        this.pan = pan;
    }

    /**
     * <p>
     * India pan information associated with the account.
     * </p>
     * 
     * @return India pan information associated with the account.
     */

    public String getPan() {
        return this.pan;
    }

    /**
     * <p>
     * India pan information associated with the account.
     * </p>
     * 
     * @param pan
     *        India pan information associated with the account.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public IndiaAdditionalInfo withPan(String pan) {
        setPan(pan);
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
        if (getPan() != null)
            sb.append("Pan: ").append(getPan());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof IndiaAdditionalInfo == false)
            return false;
        IndiaAdditionalInfo other = (IndiaAdditionalInfo) obj;
        if (other.getPan() == null ^ this.getPan() == null)
            return false;
        if (other.getPan() != null && other.getPan().equals(this.getPan()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getPan() == null) ? 0 : getPan().hashCode());
        return hashCode;
    }

    @Override
    public IndiaAdditionalInfo clone() {
        try {
            return (IndiaAdditionalInfo) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.taxsettings.model.transform.IndiaAdditionalInfoMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
