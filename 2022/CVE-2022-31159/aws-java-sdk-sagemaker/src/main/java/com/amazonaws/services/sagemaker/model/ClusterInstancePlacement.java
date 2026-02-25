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
 * Specifies the placement details for the node in the SageMaker HyperPod cluster, including the Availability Zone and
 * the unique identifier (ID) of the Availability Zone.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/sagemaker-2017-07-24/ClusterInstancePlacement" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ClusterInstancePlacement implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The Availability Zone where the node in the SageMaker HyperPod cluster is launched.
     * </p>
     */
    private String availabilityZone;
    /**
     * <p>
     * The unique identifier (ID) of the Availability Zone where the node in the SageMaker HyperPod cluster is launched.
     * </p>
     */
    private String availabilityZoneId;

    /**
     * <p>
     * The Availability Zone where the node in the SageMaker HyperPod cluster is launched.
     * </p>
     * 
     * @param availabilityZone
     *        The Availability Zone where the node in the SageMaker HyperPod cluster is launched.
     */

    public void setAvailabilityZone(String availabilityZone) {
        this.availabilityZone = availabilityZone;
    }

    /**
     * <p>
     * The Availability Zone where the node in the SageMaker HyperPod cluster is launched.
     * </p>
     * 
     * @return The Availability Zone where the node in the SageMaker HyperPod cluster is launched.
     */

    public String getAvailabilityZone() {
        return this.availabilityZone;
    }

    /**
     * <p>
     * The Availability Zone where the node in the SageMaker HyperPod cluster is launched.
     * </p>
     * 
     * @param availabilityZone
     *        The Availability Zone where the node in the SageMaker HyperPod cluster is launched.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ClusterInstancePlacement withAvailabilityZone(String availabilityZone) {
        setAvailabilityZone(availabilityZone);
        return this;
    }

    /**
     * <p>
     * The unique identifier (ID) of the Availability Zone where the node in the SageMaker HyperPod cluster is launched.
     * </p>
     * 
     * @param availabilityZoneId
     *        The unique identifier (ID) of the Availability Zone where the node in the SageMaker HyperPod cluster is
     *        launched.
     */

    public void setAvailabilityZoneId(String availabilityZoneId) {
        this.availabilityZoneId = availabilityZoneId;
    }

    /**
     * <p>
     * The unique identifier (ID) of the Availability Zone where the node in the SageMaker HyperPod cluster is launched.
     * </p>
     * 
     * @return The unique identifier (ID) of the Availability Zone where the node in the SageMaker HyperPod cluster is
     *         launched.
     */

    public String getAvailabilityZoneId() {
        return this.availabilityZoneId;
    }

    /**
     * <p>
     * The unique identifier (ID) of the Availability Zone where the node in the SageMaker HyperPod cluster is launched.
     * </p>
     * 
     * @param availabilityZoneId
     *        The unique identifier (ID) of the Availability Zone where the node in the SageMaker HyperPod cluster is
     *        launched.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ClusterInstancePlacement withAvailabilityZoneId(String availabilityZoneId) {
        setAvailabilityZoneId(availabilityZoneId);
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
        if (getAvailabilityZone() != null)
            sb.append("AvailabilityZone: ").append(getAvailabilityZone()).append(",");
        if (getAvailabilityZoneId() != null)
            sb.append("AvailabilityZoneId: ").append(getAvailabilityZoneId());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ClusterInstancePlacement == false)
            return false;
        ClusterInstancePlacement other = (ClusterInstancePlacement) obj;
        if (other.getAvailabilityZone() == null ^ this.getAvailabilityZone() == null)
            return false;
        if (other.getAvailabilityZone() != null && other.getAvailabilityZone().equals(this.getAvailabilityZone()) == false)
            return false;
        if (other.getAvailabilityZoneId() == null ^ this.getAvailabilityZoneId() == null)
            return false;
        if (other.getAvailabilityZoneId() != null && other.getAvailabilityZoneId().equals(this.getAvailabilityZoneId()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getAvailabilityZone() == null) ? 0 : getAvailabilityZone().hashCode());
        hashCode = prime * hashCode + ((getAvailabilityZoneId() == null) ? 0 : getAvailabilityZoneId().hashCode());
        return hashCode;
    }

    @Override
    public ClusterInstancePlacement clone() {
        try {
            return (ClusterInstancePlacement) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.sagemaker.model.transform.ClusterInstancePlacementMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
