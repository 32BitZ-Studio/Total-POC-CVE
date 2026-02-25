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
 * The definition for a <code>TopicSortClause</code>.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/quicksight-2018-04-01/TopicSortClause" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class TopicSortClause implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The operand for a <code>TopicSortClause</code>.
     * </p>
     */
    private Identifier operand;
    /**
     * <p>
     * The sort direction for the <code>TopicSortClause</code>.
     * </p>
     */
    private String sortDirection;

    /**
     * <p>
     * The operand for a <code>TopicSortClause</code>.
     * </p>
     * 
     * @param operand
     *        The operand for a <code>TopicSortClause</code>.
     */

    public void setOperand(Identifier operand) {
        this.operand = operand;
    }

    /**
     * <p>
     * The operand for a <code>TopicSortClause</code>.
     * </p>
     * 
     * @return The operand for a <code>TopicSortClause</code>.
     */

    public Identifier getOperand() {
        return this.operand;
    }

    /**
     * <p>
     * The operand for a <code>TopicSortClause</code>.
     * </p>
     * 
     * @param operand
     *        The operand for a <code>TopicSortClause</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public TopicSortClause withOperand(Identifier operand) {
        setOperand(operand);
        return this;
    }

    /**
     * <p>
     * The sort direction for the <code>TopicSortClause</code>.
     * </p>
     * 
     * @param sortDirection
     *        The sort direction for the <code>TopicSortClause</code>.
     * @see TopicSortDirection
     */

    public void setSortDirection(String sortDirection) {
        this.sortDirection = sortDirection;
    }

    /**
     * <p>
     * The sort direction for the <code>TopicSortClause</code>.
     * </p>
     * 
     * @return The sort direction for the <code>TopicSortClause</code>.
     * @see TopicSortDirection
     */

    public String getSortDirection() {
        return this.sortDirection;
    }

    /**
     * <p>
     * The sort direction for the <code>TopicSortClause</code>.
     * </p>
     * 
     * @param sortDirection
     *        The sort direction for the <code>TopicSortClause</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TopicSortDirection
     */

    public TopicSortClause withSortDirection(String sortDirection) {
        setSortDirection(sortDirection);
        return this;
    }

    /**
     * <p>
     * The sort direction for the <code>TopicSortClause</code>.
     * </p>
     * 
     * @param sortDirection
     *        The sort direction for the <code>TopicSortClause</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TopicSortDirection
     */

    public TopicSortClause withSortDirection(TopicSortDirection sortDirection) {
        this.sortDirection = sortDirection.toString();
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
        if (getOperand() != null)
            sb.append("Operand: ").append(getOperand()).append(",");
        if (getSortDirection() != null)
            sb.append("SortDirection: ").append(getSortDirection());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof TopicSortClause == false)
            return false;
        TopicSortClause other = (TopicSortClause) obj;
        if (other.getOperand() == null ^ this.getOperand() == null)
            return false;
        if (other.getOperand() != null && other.getOperand().equals(this.getOperand()) == false)
            return false;
        if (other.getSortDirection() == null ^ this.getSortDirection() == null)
            return false;
        if (other.getSortDirection() != null && other.getSortDirection().equals(this.getSortDirection()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getOperand() == null) ? 0 : getOperand().hashCode());
        hashCode = prime * hashCode + ((getSortDirection() == null) ? 0 : getSortDirection().hashCode());
        return hashCode;
    }

    @Override
    public TopicSortClause clone() {
        try {
            return (TopicSortClause) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.quicksight.model.transform.TopicSortClauseMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
