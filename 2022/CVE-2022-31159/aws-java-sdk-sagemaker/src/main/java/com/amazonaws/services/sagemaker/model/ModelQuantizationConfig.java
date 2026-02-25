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
package com.amazonaws.services.sagemaker.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * Settings for the model quantization technique that's applied by a model optimization job.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/sagemaker-2017-07-24/ModelQuantizationConfig" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ModelQuantizationConfig implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The URI of an LMI DLC in Amazon ECR. SageMaker uses this image to run the optimization.
     * </p>
     */
    private String image;
    /**
     * <p>
     * Environment variables that override the default ones in the model container.
     * </p>
     */
    private java.util.Map<String, String> overrideEnvironment;

    /**
     * <p>
     * The URI of an LMI DLC in Amazon ECR. SageMaker uses this image to run the optimization.
     * </p>
     * 
     * @param image
     *        The URI of an LMI DLC in Amazon ECR. SageMaker uses this image to run the optimization.
     */

    public void setImage(String image) {
        this.image = image;
    }

    /**
     * <p>
     * The URI of an LMI DLC in Amazon ECR. SageMaker uses this image to run the optimization.
     * </p>
     * 
     * @return The URI of an LMI DLC in Amazon ECR. SageMaker uses this image to run the optimization.
     */

    public String getImage() {
        return this.image;
    }

    /**
     * <p>
     * The URI of an LMI DLC in Amazon ECR. SageMaker uses this image to run the optimization.
     * </p>
     * 
     * @param image
     *        The URI of an LMI DLC in Amazon ECR. SageMaker uses this image to run the optimization.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ModelQuantizationConfig withImage(String image) {
        setImage(image);
        return this;
    }

    /**
     * <p>
     * Environment variables that override the default ones in the model container.
     * </p>
     * 
     * @return Environment variables that override the default ones in the model container.
     */

    public java.util.Map<String, String> getOverrideEnvironment() {
        return overrideEnvironment;
    }

    /**
     * <p>
     * Environment variables that override the default ones in the model container.
     * </p>
     * 
     * @param overrideEnvironment
     *        Environment variables that override the default ones in the model container.
     */

    public void setOverrideEnvironment(java.util.Map<String, String> overrideEnvironment) {
        this.overrideEnvironment = overrideEnvironment;
    }

    /**
     * <p>
     * Environment variables that override the default ones in the model container.
     * </p>
     * 
     * @param overrideEnvironment
     *        Environment variables that override the default ones in the model container.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ModelQuantizationConfig withOverrideEnvironment(java.util.Map<String, String> overrideEnvironment) {
        setOverrideEnvironment(overrideEnvironment);
        return this;
    }

    /**
     * Add a single OverrideEnvironment entry
     *
     * @see ModelQuantizationConfig#withOverrideEnvironment
     * @returns a reference to this object so that method calls can be chained together.
     */

    public ModelQuantizationConfig addOverrideEnvironmentEntry(String key, String value) {
        if (null == this.overrideEnvironment) {
            this.overrideEnvironment = new java.util.HashMap<String, String>();
        }
        if (this.overrideEnvironment.containsKey(key))
            throw new IllegalArgumentException("Duplicated keys (" + key.toString() + ") are provided.");
        this.overrideEnvironment.put(key, value);
        return this;
    }

    /**
     * Removes all the entries added into OverrideEnvironment.
     *
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ModelQuantizationConfig clearOverrideEnvironmentEntries() {
        this.overrideEnvironment = null;
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
        if (getImage() != null)
            sb.append("Image: ").append(getImage()).append(",");
        if (getOverrideEnvironment() != null)
            sb.append("OverrideEnvironment: ").append(getOverrideEnvironment());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ModelQuantizationConfig == false)
            return false;
        ModelQuantizationConfig other = (ModelQuantizationConfig) obj;
        if (other.getImage() == null ^ this.getImage() == null)
            return false;
        if (other.getImage() != null && other.getImage().equals(this.getImage()) == false)
            return false;
        if (other.getOverrideEnvironment() == null ^ this.getOverrideEnvironment() == null)
            return false;
        if (other.getOverrideEnvironment() != null && other.getOverrideEnvironment().equals(this.getOverrideEnvironment()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getImage() == null) ? 0 : getImage().hashCode());
        hashCode = prime * hashCode + ((getOverrideEnvironment() == null) ? 0 : getOverrideEnvironment().hashCode());
        return hashCode;
    }

    @Override
    public ModelQuantizationConfig clone() {
        try {
            return (ModelQuantizationConfig) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.sagemaker.model.transform.ModelQuantizationConfigMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
