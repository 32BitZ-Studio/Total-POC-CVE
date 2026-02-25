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
 * Defines the configuration for attaching additional storage to the instances in the SageMaker HyperPod cluster
 * instance group. To learn more, see <a href=
 * "https://docs.aws.amazon.com/sagemaker/latest/dg/sagemaker-hyperpod-release-notes.html#sagemaker-hyperpod-release-notes-20240620"
 * >SageMaker HyperPod release notes: June 20, 2024</a>.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/sagemaker-2017-07-24/ClusterInstanceStorageConfig"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ClusterInstanceStorageConfig implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * Defines the configuration for attaching additional Amazon Elastic Block Store (EBS) volumes to the instances in
     * the SageMaker HyperPod cluster instance group. The additional EBS volume is attached to each instance within the
     * SageMaker HyperPod cluster instance group and mounted to <code>/opt/sagemaker</code>.
     * </p>
     */
    private ClusterEbsVolumeConfig ebsVolumeConfig;

    /**
     * <p>
     * Defines the configuration for attaching additional Amazon Elastic Block Store (EBS) volumes to the instances in
     * the SageMaker HyperPod cluster instance group. The additional EBS volume is attached to each instance within the
     * SageMaker HyperPod cluster instance group and mounted to <code>/opt/sagemaker</code>.
     * </p>
     * 
     * @param ebsVolumeConfig
     *        Defines the configuration for attaching additional Amazon Elastic Block Store (EBS) volumes to the
     *        instances in the SageMaker HyperPod cluster instance group. The additional EBS volume is attached to each
     *        instance within the SageMaker HyperPod cluster instance group and mounted to <code>/opt/sagemaker</code>.
     */

    public void setEbsVolumeConfig(ClusterEbsVolumeConfig ebsVolumeConfig) {
        this.ebsVolumeConfig = ebsVolumeConfig;
    }

    /**
     * <p>
     * Defines the configuration for attaching additional Amazon Elastic Block Store (EBS) volumes to the instances in
     * the SageMaker HyperPod cluster instance group. The additional EBS volume is attached to each instance within the
     * SageMaker HyperPod cluster instance group and mounted to <code>/opt/sagemaker</code>.
     * </p>
     * 
     * @return Defines the configuration for attaching additional Amazon Elastic Block Store (EBS) volumes to the
     *         instances in the SageMaker HyperPod cluster instance group. The additional EBS volume is attached to each
     *         instance within the SageMaker HyperPod cluster instance group and mounted to <code>/opt/sagemaker</code>.
     */

    public ClusterEbsVolumeConfig getEbsVolumeConfig() {
        return this.ebsVolumeConfig;
    }

    /**
     * <p>
     * Defines the configuration for attaching additional Amazon Elastic Block Store (EBS) volumes to the instances in
     * the SageMaker HyperPod cluster instance group. The additional EBS volume is attached to each instance within the
     * SageMaker HyperPod cluster instance group and mounted to <code>/opt/sagemaker</code>.
     * </p>
     * 
     * @param ebsVolumeConfig
     *        Defines the configuration for attaching additional Amazon Elastic Block Store (EBS) volumes to the
     *        instances in the SageMaker HyperPod cluster instance group. The additional EBS volume is attached to each
     *        instance within the SageMaker HyperPod cluster instance group and mounted to <code>/opt/sagemaker</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ClusterInstanceStorageConfig withEbsVolumeConfig(ClusterEbsVolumeConfig ebsVolumeConfig) {
        setEbsVolumeConfig(ebsVolumeConfig);
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
        if (getEbsVolumeConfig() != null)
            sb.append("EbsVolumeConfig: ").append(getEbsVolumeConfig());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ClusterInstanceStorageConfig == false)
            return false;
        ClusterInstanceStorageConfig other = (ClusterInstanceStorageConfig) obj;
        if (other.getEbsVolumeConfig() == null ^ this.getEbsVolumeConfig() == null)
            return false;
        if (other.getEbsVolumeConfig() != null && other.getEbsVolumeConfig().equals(this.getEbsVolumeConfig()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getEbsVolumeConfig() == null) ? 0 : getEbsVolumeConfig().hashCode());
        return hashCode;
    }

    @Override
    public ClusterInstanceStorageConfig clone() {
        try {
            return (ClusterInstanceStorageConfig) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.sagemaker.model.transform.ClusterInstanceStorageConfigMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
