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
 * Specifies the overrides used in image set modification calls to <code>CopyImageSet</code> and
 * <code>UpdateImageSetMetadata</code>.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/medical-imaging-2023-07-19/Overrides" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class Overrides implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * Setting this flag will force the <code>CopyImageSet</code> and <code>UpdateImageSetMetadata</code> operations,
     * even if Patient, Study, or Series level metadata are mismatched.
     * </p>
     */
    private Boolean forced;

    /**
     * <p>
     * Setting this flag will force the <code>CopyImageSet</code> and <code>UpdateImageSetMetadata</code> operations,
     * even if Patient, Study, or Series level metadata are mismatched.
     * </p>
     * 
     * @param forced
     *        Setting this flag will force the <code>CopyImageSet</code> and <code>UpdateImageSetMetadata</code>
     *        operations, even if Patient, Study, or Series level metadata are mismatched.
     */

    public void setForced(Boolean forced) {
        this.forced = forced;
    }

    /**
     * <p>
     * Setting this flag will force the <code>CopyImageSet</code> and <code>UpdateImageSetMetadata</code> operations,
     * even if Patient, Study, or Series level metadata are mismatched.
     * </p>
     * 
     * @return Setting this flag will force the <code>CopyImageSet</code> and <code>UpdateImageSetMetadata</code>
     *         operations, even if Patient, Study, or Series level metadata are mismatched.
     */

    public Boolean getForced() {
        return this.forced;
    }

    /**
     * <p>
     * Setting this flag will force the <code>CopyImageSet</code> and <code>UpdateImageSetMetadata</code> operations,
     * even if Patient, Study, or Series level metadata are mismatched.
     * </p>
     * 
     * @param forced
     *        Setting this flag will force the <code>CopyImageSet</code> and <code>UpdateImageSetMetadata</code>
     *        operations, even if Patient, Study, or Series level metadata are mismatched.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Overrides withForced(Boolean forced) {
        setForced(forced);
        return this;
    }

    /**
     * <p>
     * Setting this flag will force the <code>CopyImageSet</code> and <code>UpdateImageSetMetadata</code> operations,
     * even if Patient, Study, or Series level metadata are mismatched.
     * </p>
     * 
     * @return Setting this flag will force the <code>CopyImageSet</code> and <code>UpdateImageSetMetadata</code>
     *         operations, even if Patient, Study, or Series level metadata are mismatched.
     */

    public Boolean isForced() {
        return this.forced;
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
        if (getForced() != null)
            sb.append("Forced: ").append(getForced());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof Overrides == false)
            return false;
        Overrides other = (Overrides) obj;
        if (other.getForced() == null ^ this.getForced() == null)
            return false;
        if (other.getForced() != null && other.getForced().equals(this.getForced()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getForced() == null) ? 0 : getForced().hashCode());
        return hashCode;
    }

    @Override
    public Overrides clone() {
        try {
            return (Overrides) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.medicalimaging.model.transform.OverridesMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
