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
package com.amazonaws.services.qbusiness.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * Configuration information about chat response personalization. For more information, see <a
 * href="https://docs.aws.amazon.com/amazonq/latest/qbusiness-ug/personalizing-chat-responses.html">Personalizing chat
 * responses</a>.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qbusiness-2023-11-27/PersonalizationConfiguration"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class PersonalizationConfiguration implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * An option to allow Amazon Q Business to customize chat responses using user specific metadata—specifically,
     * location and job information—in your IAM Identity Center instance.
     * </p>
     */
    private String personalizationControlMode;

    /**
     * <p>
     * An option to allow Amazon Q Business to customize chat responses using user specific metadata—specifically,
     * location and job information—in your IAM Identity Center instance.
     * </p>
     * 
     * @param personalizationControlMode
     *        An option to allow Amazon Q Business to customize chat responses using user specific
     *        metadata—specifically, location and job information—in your IAM Identity Center instance.
     * @see PersonalizationControlMode
     */

    public void setPersonalizationControlMode(String personalizationControlMode) {
        this.personalizationControlMode = personalizationControlMode;
    }

    /**
     * <p>
     * An option to allow Amazon Q Business to customize chat responses using user specific metadata—specifically,
     * location and job information—in your IAM Identity Center instance.
     * </p>
     * 
     * @return An option to allow Amazon Q Business to customize chat responses using user specific
     *         metadata—specifically, location and job information—in your IAM Identity Center instance.
     * @see PersonalizationControlMode
     */

    public String getPersonalizationControlMode() {
        return this.personalizationControlMode;
    }

    /**
     * <p>
     * An option to allow Amazon Q Business to customize chat responses using user specific metadata—specifically,
     * location and job information—in your IAM Identity Center instance.
     * </p>
     * 
     * @param personalizationControlMode
     *        An option to allow Amazon Q Business to customize chat responses using user specific
     *        metadata—specifically, location and job information—in your IAM Identity Center instance.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see PersonalizationControlMode
     */

    public PersonalizationConfiguration withPersonalizationControlMode(String personalizationControlMode) {
        setPersonalizationControlMode(personalizationControlMode);
        return this;
    }

    /**
     * <p>
     * An option to allow Amazon Q Business to customize chat responses using user specific metadata—specifically,
     * location and job information—in your IAM Identity Center instance.
     * </p>
     * 
     * @param personalizationControlMode
     *        An option to allow Amazon Q Business to customize chat responses using user specific
     *        metadata—specifically, location and job information—in your IAM Identity Center instance.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see PersonalizationControlMode
     */

    public PersonalizationConfiguration withPersonalizationControlMode(PersonalizationControlMode personalizationControlMode) {
        this.personalizationControlMode = personalizationControlMode.toString();
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
        if (getPersonalizationControlMode() != null)
            sb.append("PersonalizationControlMode: ").append(getPersonalizationControlMode());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof PersonalizationConfiguration == false)
            return false;
        PersonalizationConfiguration other = (PersonalizationConfiguration) obj;
        if (other.getPersonalizationControlMode() == null ^ this.getPersonalizationControlMode() == null)
            return false;
        if (other.getPersonalizationControlMode() != null && other.getPersonalizationControlMode().equals(this.getPersonalizationControlMode()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getPersonalizationControlMode() == null) ? 0 : getPersonalizationControlMode().hashCode());
        return hashCode;
    }

    @Override
    public PersonalizationConfiguration clone() {
        try {
            return (PersonalizationConfiguration) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.qbusiness.model.transform.PersonalizationConfigurationMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
