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
package com.amazonaws.services.opensearch.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * Container for parameters required to enable the natural language query generation feature.
 * </p>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class NaturalLanguageQueryGenerationOptionsInput implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The desired state of the natural language query generation feature. Valid values are ENABLED and DISABLED.
     * </p>
     */
    private String desiredState;

    /**
     * <p>
     * The desired state of the natural language query generation feature. Valid values are ENABLED and DISABLED.
     * </p>
     * 
     * @param desiredState
     *        The desired state of the natural language query generation feature. Valid values are ENABLED and DISABLED.
     * @see NaturalLanguageQueryGenerationDesiredState
     */

    public void setDesiredState(String desiredState) {
        this.desiredState = desiredState;
    }

    /**
     * <p>
     * The desired state of the natural language query generation feature. Valid values are ENABLED and DISABLED.
     * </p>
     * 
     * @return The desired state of the natural language query generation feature. Valid values are ENABLED and
     *         DISABLED.
     * @see NaturalLanguageQueryGenerationDesiredState
     */

    public String getDesiredState() {
        return this.desiredState;
    }

    /**
     * <p>
     * The desired state of the natural language query generation feature. Valid values are ENABLED and DISABLED.
     * </p>
     * 
     * @param desiredState
     *        The desired state of the natural language query generation feature. Valid values are ENABLED and DISABLED.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see NaturalLanguageQueryGenerationDesiredState
     */

    public NaturalLanguageQueryGenerationOptionsInput withDesiredState(String desiredState) {
        setDesiredState(desiredState);
        return this;
    }

    /**
     * <p>
     * The desired state of the natural language query generation feature. Valid values are ENABLED and DISABLED.
     * </p>
     * 
     * @param desiredState
     *        The desired state of the natural language query generation feature. Valid values are ENABLED and DISABLED.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see NaturalLanguageQueryGenerationDesiredState
     */

    public NaturalLanguageQueryGenerationOptionsInput withDesiredState(NaturalLanguageQueryGenerationDesiredState desiredState) {
        this.desiredState = desiredState.toString();
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
        if (getDesiredState() != null)
            sb.append("DesiredState: ").append(getDesiredState());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof NaturalLanguageQueryGenerationOptionsInput == false)
            return false;
        NaturalLanguageQueryGenerationOptionsInput other = (NaturalLanguageQueryGenerationOptionsInput) obj;
        if (other.getDesiredState() == null ^ this.getDesiredState() == null)
            return false;
        if (other.getDesiredState() != null && other.getDesiredState().equals(this.getDesiredState()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getDesiredState() == null) ? 0 : getDesiredState().hashCode());
        return hashCode;
    }

    @Override
    public NaturalLanguageQueryGenerationOptionsInput clone() {
        try {
            return (NaturalLanguageQueryGenerationOptionsInput) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.opensearch.model.transform.NaturalLanguageQueryGenerationOptionsInputMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
