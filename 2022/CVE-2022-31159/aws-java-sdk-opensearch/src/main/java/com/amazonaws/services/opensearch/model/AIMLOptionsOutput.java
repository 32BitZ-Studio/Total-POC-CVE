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
 * Container for parameters representing the state of machine learning features on the specified domain.
 * </p>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class AIMLOptionsOutput implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * Container for parameters required for natural language query generation on the specified domain.
     * </p>
     */
    private NaturalLanguageQueryGenerationOptionsOutput naturalLanguageQueryGenerationOptions;

    /**
     * <p>
     * Container for parameters required for natural language query generation on the specified domain.
     * </p>
     * 
     * @param naturalLanguageQueryGenerationOptions
     *        Container for parameters required for natural language query generation on the specified domain.
     */

    public void setNaturalLanguageQueryGenerationOptions(NaturalLanguageQueryGenerationOptionsOutput naturalLanguageQueryGenerationOptions) {
        this.naturalLanguageQueryGenerationOptions = naturalLanguageQueryGenerationOptions;
    }

    /**
     * <p>
     * Container for parameters required for natural language query generation on the specified domain.
     * </p>
     * 
     * @return Container for parameters required for natural language query generation on the specified domain.
     */

    public NaturalLanguageQueryGenerationOptionsOutput getNaturalLanguageQueryGenerationOptions() {
        return this.naturalLanguageQueryGenerationOptions;
    }

    /**
     * <p>
     * Container for parameters required for natural language query generation on the specified domain.
     * </p>
     * 
     * @param naturalLanguageQueryGenerationOptions
     *        Container for parameters required for natural language query generation on the specified domain.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public AIMLOptionsOutput withNaturalLanguageQueryGenerationOptions(NaturalLanguageQueryGenerationOptionsOutput naturalLanguageQueryGenerationOptions) {
        setNaturalLanguageQueryGenerationOptions(naturalLanguageQueryGenerationOptions);
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
        if (getNaturalLanguageQueryGenerationOptions() != null)
            sb.append("NaturalLanguageQueryGenerationOptions: ").append(getNaturalLanguageQueryGenerationOptions());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof AIMLOptionsOutput == false)
            return false;
        AIMLOptionsOutput other = (AIMLOptionsOutput) obj;
        if (other.getNaturalLanguageQueryGenerationOptions() == null ^ this.getNaturalLanguageQueryGenerationOptions() == null)
            return false;
        if (other.getNaturalLanguageQueryGenerationOptions() != null
                && other.getNaturalLanguageQueryGenerationOptions().equals(this.getNaturalLanguageQueryGenerationOptions()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getNaturalLanguageQueryGenerationOptions() == null) ? 0 : getNaturalLanguageQueryGenerationOptions().hashCode());
        return hashCode;
    }

    @Override
    public AIMLOptionsOutput clone() {
        try {
            return (AIMLOptionsOutput) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.opensearch.model.transform.AIMLOptionsOutputMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
