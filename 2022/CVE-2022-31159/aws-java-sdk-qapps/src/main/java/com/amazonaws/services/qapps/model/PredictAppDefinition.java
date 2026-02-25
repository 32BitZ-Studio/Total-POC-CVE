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
package com.amazonaws.services.qapps.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * The definition of an Amazon Q App generated based on input such as a conversation or problem statement.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/PredictAppDefinition" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class PredictAppDefinition implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The title of the generated Q App definition.
     * </p>
     */
    private String title;
    /**
     * <p>
     * The description of the generated Q App definition.
     * </p>
     */
    private String description;
    /**
     * <p>
     * The definition specifying the cards and flow of the generated Q App.
     * </p>
     */
    private AppDefinitionInput appDefinition;

    /**
     * <p>
     * The title of the generated Q App definition.
     * </p>
     * 
     * @param title
     *        The title of the generated Q App definition.
     */

    public void setTitle(String title) {
        this.title = title;
    }

    /**
     * <p>
     * The title of the generated Q App definition.
     * </p>
     * 
     * @return The title of the generated Q App definition.
     */

    public String getTitle() {
        return this.title;
    }

    /**
     * <p>
     * The title of the generated Q App definition.
     * </p>
     * 
     * @param title
     *        The title of the generated Q App definition.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public PredictAppDefinition withTitle(String title) {
        setTitle(title);
        return this;
    }

    /**
     * <p>
     * The description of the generated Q App definition.
     * </p>
     * 
     * @param description
     *        The description of the generated Q App definition.
     */

    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * <p>
     * The description of the generated Q App definition.
     * </p>
     * 
     * @return The description of the generated Q App definition.
     */

    public String getDescription() {
        return this.description;
    }

    /**
     * <p>
     * The description of the generated Q App definition.
     * </p>
     * 
     * @param description
     *        The description of the generated Q App definition.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public PredictAppDefinition withDescription(String description) {
        setDescription(description);
        return this;
    }

    /**
     * <p>
     * The definition specifying the cards and flow of the generated Q App.
     * </p>
     * 
     * @param appDefinition
     *        The definition specifying the cards and flow of the generated Q App.
     */

    public void setAppDefinition(AppDefinitionInput appDefinition) {
        this.appDefinition = appDefinition;
    }

    /**
     * <p>
     * The definition specifying the cards and flow of the generated Q App.
     * </p>
     * 
     * @return The definition specifying the cards and flow of the generated Q App.
     */

    public AppDefinitionInput getAppDefinition() {
        return this.appDefinition;
    }

    /**
     * <p>
     * The definition specifying the cards and flow of the generated Q App.
     * </p>
     * 
     * @param appDefinition
     *        The definition specifying the cards and flow of the generated Q App.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public PredictAppDefinition withAppDefinition(AppDefinitionInput appDefinition) {
        setAppDefinition(appDefinition);
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
        if (getTitle() != null)
            sb.append("Title: ").append(getTitle()).append(",");
        if (getDescription() != null)
            sb.append("Description: ").append(getDescription()).append(",");
        if (getAppDefinition() != null)
            sb.append("AppDefinition: ").append(getAppDefinition());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof PredictAppDefinition == false)
            return false;
        PredictAppDefinition other = (PredictAppDefinition) obj;
        if (other.getTitle() == null ^ this.getTitle() == null)
            return false;
        if (other.getTitle() != null && other.getTitle().equals(this.getTitle()) == false)
            return false;
        if (other.getDescription() == null ^ this.getDescription() == null)
            return false;
        if (other.getDescription() != null && other.getDescription().equals(this.getDescription()) == false)
            return false;
        if (other.getAppDefinition() == null ^ this.getAppDefinition() == null)
            return false;
        if (other.getAppDefinition() != null && other.getAppDefinition().equals(this.getAppDefinition()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getTitle() == null) ? 0 : getTitle().hashCode());
        hashCode = prime * hashCode + ((getDescription() == null) ? 0 : getDescription().hashCode());
        hashCode = prime * hashCode + ((getAppDefinition() == null) ? 0 : getAppDefinition().hashCode());
        return hashCode;
    }

    @Override
    public PredictAppDefinition clone() {
        try {
            return (PredictAppDefinition) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.qapps.model.transform.PredictAppDefinitionMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
