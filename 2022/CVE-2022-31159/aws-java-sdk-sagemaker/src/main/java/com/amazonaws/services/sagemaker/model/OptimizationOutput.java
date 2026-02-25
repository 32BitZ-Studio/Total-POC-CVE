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
 * Output values produced by an optimization job.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/sagemaker-2017-07-24/OptimizationOutput" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class OptimizationOutput implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The image that SageMaker recommends that you use to host the optimized model that you created with an
     * optimization job.
     * </p>
     */
    private String recommendedInferenceImage;

    /**
     * <p>
     * The image that SageMaker recommends that you use to host the optimized model that you created with an
     * optimization job.
     * </p>
     * 
     * @param recommendedInferenceImage
     *        The image that SageMaker recommends that you use to host the optimized model that you created with an
     *        optimization job.
     */

    public void setRecommendedInferenceImage(String recommendedInferenceImage) {
        this.recommendedInferenceImage = recommendedInferenceImage;
    }

    /**
     * <p>
     * The image that SageMaker recommends that you use to host the optimized model that you created with an
     * optimization job.
     * </p>
     * 
     * @return The image that SageMaker recommends that you use to host the optimized model that you created with an
     *         optimization job.
     */

    public String getRecommendedInferenceImage() {
        return this.recommendedInferenceImage;
    }

    /**
     * <p>
     * The image that SageMaker recommends that you use to host the optimized model that you created with an
     * optimization job.
     * </p>
     * 
     * @param recommendedInferenceImage
     *        The image that SageMaker recommends that you use to host the optimized model that you created with an
     *        optimization job.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public OptimizationOutput withRecommendedInferenceImage(String recommendedInferenceImage) {
        setRecommendedInferenceImage(recommendedInferenceImage);
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
        if (getRecommendedInferenceImage() != null)
            sb.append("RecommendedInferenceImage: ").append(getRecommendedInferenceImage());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof OptimizationOutput == false)
            return false;
        OptimizationOutput other = (OptimizationOutput) obj;
        if (other.getRecommendedInferenceImage() == null ^ this.getRecommendedInferenceImage() == null)
            return false;
        if (other.getRecommendedInferenceImage() != null && other.getRecommendedInferenceImage().equals(this.getRecommendedInferenceImage()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getRecommendedInferenceImage() == null) ? 0 : getRecommendedInferenceImage().hashCode());
        return hashCode;
    }

    @Override
    public OptimizationOutput clone() {
        try {
            return (OptimizationOutput) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.sagemaker.model.transform.OptimizationOutputMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
