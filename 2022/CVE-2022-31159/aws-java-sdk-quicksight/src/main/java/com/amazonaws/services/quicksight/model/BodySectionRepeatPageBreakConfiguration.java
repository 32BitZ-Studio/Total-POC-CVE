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
package com.amazonaws.services.quicksight.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * The page break configuration to apply for each repeating instance.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/quicksight-2018-04-01/BodySectionRepeatPageBreakConfiguration"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class BodySectionRepeatPageBreakConfiguration implements Serializable, Cloneable, StructuredPojo {

    private SectionAfterPageBreak after;

    /**
     * @param after
     */

    public void setAfter(SectionAfterPageBreak after) {
        this.after = after;
    }

    /**
     * @return
     */

    public SectionAfterPageBreak getAfter() {
        return this.after;
    }

    /**
     * @param after
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public BodySectionRepeatPageBreakConfiguration withAfter(SectionAfterPageBreak after) {
        setAfter(after);
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
        if (getAfter() != null)
            sb.append("After: ").append(getAfter());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof BodySectionRepeatPageBreakConfiguration == false)
            return false;
        BodySectionRepeatPageBreakConfiguration other = (BodySectionRepeatPageBreakConfiguration) obj;
        if (other.getAfter() == null ^ this.getAfter() == null)
            return false;
        if (other.getAfter() != null && other.getAfter().equals(this.getAfter()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getAfter() == null) ? 0 : getAfter().hashCode());
        return hashCode;
    }

    @Override
    public BodySectionRepeatPageBreakConfiguration clone() {
        try {
            return (BodySectionRepeatPageBreakConfiguration) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.quicksight.model.transform.BodySectionRepeatPageBreakConfigurationMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
