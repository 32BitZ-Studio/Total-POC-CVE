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
 * The definition of the Anchor.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/quicksight-2018-04-01/Anchor" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class Anchor implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The <code>AnchorType</code> for the Anchor.
     * </p>
     */
    private String anchorType;
    /**
     * <p>
     * The <code>TimeGranularity</code> of the Anchor.
     * </p>
     */
    private String timeGranularity;
    /**
     * <p>
     * The offset of the Anchor.
     * </p>
     */
    private Integer offset;

    /**
     * <p>
     * The <code>AnchorType</code> for the Anchor.
     * </p>
     * 
     * @param anchorType
     *        The <code>AnchorType</code> for the Anchor.
     * @see AnchorType
     */

    public void setAnchorType(String anchorType) {
        this.anchorType = anchorType;
    }

    /**
     * <p>
     * The <code>AnchorType</code> for the Anchor.
     * </p>
     * 
     * @return The <code>AnchorType</code> for the Anchor.
     * @see AnchorType
     */

    public String getAnchorType() {
        return this.anchorType;
    }

    /**
     * <p>
     * The <code>AnchorType</code> for the Anchor.
     * </p>
     * 
     * @param anchorType
     *        The <code>AnchorType</code> for the Anchor.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see AnchorType
     */

    public Anchor withAnchorType(String anchorType) {
        setAnchorType(anchorType);
        return this;
    }

    /**
     * <p>
     * The <code>AnchorType</code> for the Anchor.
     * </p>
     * 
     * @param anchorType
     *        The <code>AnchorType</code> for the Anchor.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see AnchorType
     */

    public Anchor withAnchorType(AnchorType anchorType) {
        this.anchorType = anchorType.toString();
        return this;
    }

    /**
     * <p>
     * The <code>TimeGranularity</code> of the Anchor.
     * </p>
     * 
     * @param timeGranularity
     *        The <code>TimeGranularity</code> of the Anchor.
     * @see TimeGranularity
     */

    public void setTimeGranularity(String timeGranularity) {
        this.timeGranularity = timeGranularity;
    }

    /**
     * <p>
     * The <code>TimeGranularity</code> of the Anchor.
     * </p>
     * 
     * @return The <code>TimeGranularity</code> of the Anchor.
     * @see TimeGranularity
     */

    public String getTimeGranularity() {
        return this.timeGranularity;
    }

    /**
     * <p>
     * The <code>TimeGranularity</code> of the Anchor.
     * </p>
     * 
     * @param timeGranularity
     *        The <code>TimeGranularity</code> of the Anchor.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TimeGranularity
     */

    public Anchor withTimeGranularity(String timeGranularity) {
        setTimeGranularity(timeGranularity);
        return this;
    }

    /**
     * <p>
     * The <code>TimeGranularity</code> of the Anchor.
     * </p>
     * 
     * @param timeGranularity
     *        The <code>TimeGranularity</code> of the Anchor.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TimeGranularity
     */

    public Anchor withTimeGranularity(TimeGranularity timeGranularity) {
        this.timeGranularity = timeGranularity.toString();
        return this;
    }

    /**
     * <p>
     * The offset of the Anchor.
     * </p>
     * 
     * @param offset
     *        The offset of the Anchor.
     */

    public void setOffset(Integer offset) {
        this.offset = offset;
    }

    /**
     * <p>
     * The offset of the Anchor.
     * </p>
     * 
     * @return The offset of the Anchor.
     */

    public Integer getOffset() {
        return this.offset;
    }

    /**
     * <p>
     * The offset of the Anchor.
     * </p>
     * 
     * @param offset
     *        The offset of the Anchor.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Anchor withOffset(Integer offset) {
        setOffset(offset);
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
        if (getAnchorType() != null)
            sb.append("AnchorType: ").append(getAnchorType()).append(",");
        if (getTimeGranularity() != null)
            sb.append("TimeGranularity: ").append(getTimeGranularity()).append(",");
        if (getOffset() != null)
            sb.append("Offset: ").append(getOffset());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof Anchor == false)
            return false;
        Anchor other = (Anchor) obj;
        if (other.getAnchorType() == null ^ this.getAnchorType() == null)
            return false;
        if (other.getAnchorType() != null && other.getAnchorType().equals(this.getAnchorType()) == false)
            return false;
        if (other.getTimeGranularity() == null ^ this.getTimeGranularity() == null)
            return false;
        if (other.getTimeGranularity() != null && other.getTimeGranularity().equals(this.getTimeGranularity()) == false)
            return false;
        if (other.getOffset() == null ^ this.getOffset() == null)
            return false;
        if (other.getOffset() != null && other.getOffset().equals(this.getOffset()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getAnchorType() == null) ? 0 : getAnchorType().hashCode());
        hashCode = prime * hashCode + ((getTimeGranularity() == null) ? 0 : getTimeGranularity().hashCode());
        hashCode = prime * hashCode + ((getOffset() == null) ? 0 : getOffset().hashCode());
        return hashCode;
    }

    @Override
    public Anchor clone() {
        try {
            return (Anchor) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.quicksight.model.transform.AnchorMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
