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
 * Settings for an optimization technique that you apply with a model optimization job.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/sagemaker-2017-07-24/OptimizationConfig" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class OptimizationConfig implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * Settings for the model quantization technique that's applied by a model optimization job.
     * </p>
     */
    private ModelQuantizationConfig modelQuantizationConfig;
    /**
     * <p>
     * Settings for the model compilation technique that's applied by a model optimization job.
     * </p>
     */
    private ModelCompilationConfig modelCompilationConfig;

    /**
     * <p>
     * Settings for the model quantization technique that's applied by a model optimization job.
     * </p>
     * 
     * @param modelQuantizationConfig
     *        Settings for the model quantization technique that's applied by a model optimization job.
     */

    public void setModelQuantizationConfig(ModelQuantizationConfig modelQuantizationConfig) {
        this.modelQuantizationConfig = modelQuantizationConfig;
    }

    /**
     * <p>
     * Settings for the model quantization technique that's applied by a model optimization job.
     * </p>
     * 
     * @return Settings for the model quantization technique that's applied by a model optimization job.
     */

    public ModelQuantizationConfig getModelQuantizationConfig() {
        return this.modelQuantizationConfig;
    }

    /**
     * <p>
     * Settings for the model quantization technique that's applied by a model optimization job.
     * </p>
     * 
     * @param modelQuantizationConfig
     *        Settings for the model quantization technique that's applied by a model optimization job.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public OptimizationConfig withModelQuantizationConfig(ModelQuantizationConfig modelQuantizationConfig) {
        setModelQuantizationConfig(modelQuantizationConfig);
        return this;
    }

    /**
     * <p>
     * Settings for the model compilation technique that's applied by a model optimization job.
     * </p>
     * 
     * @param modelCompilationConfig
     *        Settings for the model compilation technique that's applied by a model optimization job.
     */

    public void setModelCompilationConfig(ModelCompilationConfig modelCompilationConfig) {
        this.modelCompilationConfig = modelCompilationConfig;
    }

    /**
     * <p>
     * Settings for the model compilation technique that's applied by a model optimization job.
     * </p>
     * 
     * @return Settings for the model compilation technique that's applied by a model optimization job.
     */

    public ModelCompilationConfig getModelCompilationConfig() {
        return this.modelCompilationConfig;
    }

    /**
     * <p>
     * Settings for the model compilation technique that's applied by a model optimization job.
     * </p>
     * 
     * @param modelCompilationConfig
     *        Settings for the model compilation technique that's applied by a model optimization job.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public OptimizationConfig withModelCompilationConfig(ModelCompilationConfig modelCompilationConfig) {
        setModelCompilationConfig(modelCompilationConfig);
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
        if (getModelQuantizationConfig() != null)
            sb.append("ModelQuantizationConfig: ").append(getModelQuantizationConfig()).append(",");
        if (getModelCompilationConfig() != null)
            sb.append("ModelCompilationConfig: ").append(getModelCompilationConfig());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof OptimizationConfig == false)
            return false;
        OptimizationConfig other = (OptimizationConfig) obj;
        if (other.getModelQuantizationConfig() == null ^ this.getModelQuantizationConfig() == null)
            return false;
        if (other.getModelQuantizationConfig() != null && other.getModelQuantizationConfig().equals(this.getModelQuantizationConfig()) == false)
            return false;
        if (other.getModelCompilationConfig() == null ^ this.getModelCompilationConfig() == null)
            return false;
        if (other.getModelCompilationConfig() != null && other.getModelCompilationConfig().equals(this.getModelCompilationConfig()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getModelQuantizationConfig() == null) ? 0 : getModelQuantizationConfig().hashCode());
        hashCode = prime * hashCode + ((getModelCompilationConfig() == null) ? 0 : getModelCompilationConfig().hashCode());
        return hashCode;
    }

    @Override
    public OptimizationConfig clone() {
        try {
            return (OptimizationConfig) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.sagemaker.model.transform.OptimizationConfigMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
