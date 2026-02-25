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
package com.amazonaws.services.medicalimaging.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * Contains copiable <code>Attributes</code> structure and wraps information related to specific copy use cases. For
 * example, when copying subsets.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/medical-imaging-2023-07-19/MetadataCopies" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class MetadataCopies implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The JSON string used to specify a subset of SOP Instances to copy from source to destination image set.
     * </p>
     */
    private String copiableAttributes;

    /**
     * <p>
     * The JSON string used to specify a subset of SOP Instances to copy from source to destination image set.
     * </p>
     * 
     * @param copiableAttributes
     *        The JSON string used to specify a subset of SOP Instances to copy from source to destination image set.
     */

    public void setCopiableAttributes(String copiableAttributes) {
        this.copiableAttributes = copiableAttributes;
    }

    /**
     * <p>
     * The JSON string used to specify a subset of SOP Instances to copy from source to destination image set.
     * </p>
     * 
     * @return The JSON string used to specify a subset of SOP Instances to copy from source to destination image set.
     */

    public String getCopiableAttributes() {
        return this.copiableAttributes;
    }

    /**
     * <p>
     * The JSON string used to specify a subset of SOP Instances to copy from source to destination image set.
     * </p>
     * 
     * @param copiableAttributes
     *        The JSON string used to specify a subset of SOP Instances to copy from source to destination image set.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public MetadataCopies withCopiableAttributes(String copiableAttributes) {
        setCopiableAttributes(copiableAttributes);
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
        if (getCopiableAttributes() != null)
            sb.append("CopiableAttributes: ").append("***Sensitive Data Redacted***");
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof MetadataCopies == false)
            return false;
        MetadataCopies other = (MetadataCopies) obj;
        if (other.getCopiableAttributes() == null ^ this.getCopiableAttributes() == null)
            return false;
        if (other.getCopiableAttributes() != null && other.getCopiableAttributes().equals(this.getCopiableAttributes()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getCopiableAttributes() == null) ? 0 : getCopiableAttributes().hashCode());
        return hashCode;
    }

    @Override
    public MetadataCopies clone() {
        try {
            return (MetadataCopies) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.medicalimaging.model.transform.MetadataCopiesMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
