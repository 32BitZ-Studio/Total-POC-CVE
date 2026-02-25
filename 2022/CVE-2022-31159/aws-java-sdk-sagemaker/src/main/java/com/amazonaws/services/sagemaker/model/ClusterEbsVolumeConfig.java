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
 * Defines the configuration for attaching an additional Amazon Elastic Block Store (EBS) volume to each instance of the
 * SageMaker HyperPod cluster instance group. To learn more, see <a href=
 * "https://docs.aws.amazon.com/sagemaker/latest/dg/sagemaker-hyperpod-release-notes.html#sagemaker-hyperpod-release-notes-20240620"
 * >SageMaker HyperPod release notes: June 20, 2024</a>.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/sagemaker-2017-07-24/ClusterEbsVolumeConfig" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ClusterEbsVolumeConfig implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The size in gigabytes (GB) of the additional EBS volume to be attached to the instances in the SageMaker HyperPod
     * cluster instance group. The additional EBS volume is attached to each instance within the SageMaker HyperPod
     * cluster instance group and mounted to <code>/opt/sagemaker</code>.
     * </p>
     */
    private Integer volumeSizeInGB;

    /**
     * <p>
     * The size in gigabytes (GB) of the additional EBS volume to be attached to the instances in the SageMaker HyperPod
     * cluster instance group. The additional EBS volume is attached to each instance within the SageMaker HyperPod
     * cluster instance group and mounted to <code>/opt/sagemaker</code>.
     * </p>
     * 
     * @param volumeSizeInGB
     *        The size in gigabytes (GB) of the additional EBS volume to be attached to the instances in the SageMaker
     *        HyperPod cluster instance group. The additional EBS volume is attached to each instance within the
     *        SageMaker HyperPod cluster instance group and mounted to <code>/opt/sagemaker</code>.
     */

    public void setVolumeSizeInGB(Integer volumeSizeInGB) {
        this.volumeSizeInGB = volumeSizeInGB;
    }

    /**
     * <p>
     * The size in gigabytes (GB) of the additional EBS volume to be attached to the instances in the SageMaker HyperPod
     * cluster instance group. The additional EBS volume is attached to each instance within the SageMaker HyperPod
     * cluster instance group and mounted to <code>/opt/sagemaker</code>.
     * </p>
     * 
     * @return The size in gigabytes (GB) of the additional EBS volume to be attached to the instances in the SageMaker
     *         HyperPod cluster instance group. The additional EBS volume is attached to each instance within the
     *         SageMaker HyperPod cluster instance group and mounted to <code>/opt/sagemaker</code>.
     */

    public Integer getVolumeSizeInGB() {
        return this.volumeSizeInGB;
    }

    /**
     * <p>
     * The size in gigabytes (GB) of the additional EBS volume to be attached to the instances in the SageMaker HyperPod
     * cluster instance group. The additional EBS volume is attached to each instance within the SageMaker HyperPod
     * cluster instance group and mounted to <code>/opt/sagemaker</code>.
     * </p>
     * 
     * @param volumeSizeInGB
     *        The size in gigabytes (GB) of the additional EBS volume to be attached to the instances in the SageMaker
     *        HyperPod cluster instance group. The additional EBS volume is attached to each instance within the
     *        SageMaker HyperPod cluster instance group and mounted to <code>/opt/sagemaker</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ClusterEbsVolumeConfig withVolumeSizeInGB(Integer volumeSizeInGB) {
        setVolumeSizeInGB(volumeSizeInGB);
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
        if (getVolumeSizeInGB() != null)
            sb.append("VolumeSizeInGB: ").append(getVolumeSizeInGB());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ClusterEbsVolumeConfig == false)
            return false;
        ClusterEbsVolumeConfig other = (ClusterEbsVolumeConfig) obj;
        if (other.getVolumeSizeInGB() == null ^ this.getVolumeSizeInGB() == null)
            return false;
        if (other.getVolumeSizeInGB() != null && other.getVolumeSizeInGB().equals(this.getVolumeSizeInGB()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getVolumeSizeInGB() == null) ? 0 : getVolumeSizeInGB().hashCode());
        return hashCode;
    }

    @Override
    public ClusterEbsVolumeConfig clone() {
        try {
            return (ClusterEbsVolumeConfig) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.sagemaker.model.transform.ClusterEbsVolumeConfigMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
