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
 * Details of an instance (also called a <i>node</i> interchangeably) in a SageMaker HyperPod cluster.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/sagemaker-2017-07-24/ClusterNodeDetails" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ClusterNodeDetails implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The instance group name in which the instance is.
     * </p>
     */
    private String instanceGroupName;
    /**
     * <p>
     * The ID of the instance.
     * </p>
     */
    private String instanceId;
    /**
     * <p>
     * The status of the instance.
     * </p>
     */
    private ClusterInstanceStatusDetails instanceStatus;
    /**
     * <p>
     * The type of the instance.
     * </p>
     */
    private String instanceType;
    /**
     * <p>
     * The time when the instance is launched.
     * </p>
     */
    private java.util.Date launchTime;
    /**
     * <p>
     * The LifeCycle configuration applied to the instance.
     * </p>
     */
    private ClusterLifeCycleConfig lifeCycleConfig;
    /**
     * <p>
     * The number of threads per CPU core you specified under <code>CreateCluster</code>.
     * </p>
     */
    private Integer threadsPerCore;
    /**
     * <p>
     * The configurations of additional storage specified to the instance group where the instance (node) is launched.
     * </p>
     */
    private java.util.List<ClusterInstanceStorageConfig> instanceStorageConfigs;
    /**
     * <p>
     * The private primary IP address of the SageMaker HyperPod cluster node.
     * </p>
     */
    private String privatePrimaryIp;
    /**
     * <p>
     * The private DNS hostname of the SageMaker HyperPod cluster node.
     * </p>
     */
    private String privateDnsHostname;
    /**
     * <p>
     * The placement details of the SageMaker HyperPod cluster node.
     * </p>
     */
    private ClusterInstancePlacement placement;

    /**
     * <p>
     * The instance group name in which the instance is.
     * </p>
     * 
     * @param instanceGroupName
     *        The instance group name in which the instance is.
     */

    public void setInstanceGroupName(String instanceGroupName) {
        this.instanceGroupName = instanceGroupName;
    }

    /**
     * <p>
     * The instance group name in which the instance is.
     * </p>
     * 
     * @return The instance group name in which the instance is.
     */

    public String getInstanceGroupName() {
        return this.instanceGroupName;
    }

    /**
     * <p>
     * The instance group name in which the instance is.
     * </p>
     * 
     * @param instanceGroupName
     *        The instance group name in which the instance is.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ClusterNodeDetails withInstanceGroupName(String instanceGroupName) {
        setInstanceGroupName(instanceGroupName);
        return this;
    }

    /**
     * <p>
     * The ID of the instance.
     * </p>
     * 
     * @param instanceId
     *        The ID of the instance.
     */

    public void setInstanceId(String instanceId) {
        this.instanceId = instanceId;
    }

    /**
     * <p>
     * The ID of the instance.
     * </p>
     * 
     * @return The ID of the instance.
     */

    public String getInstanceId() {
        return this.instanceId;
    }

    /**
     * <p>
     * The ID of the instance.
     * </p>
     * 
     * @param instanceId
     *        The ID of the instance.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ClusterNodeDetails withInstanceId(String instanceId) {
        setInstanceId(instanceId);
        return this;
    }

    /**
     * <p>
     * The status of the instance.
     * </p>
     * 
     * @param instanceStatus
     *        The status of the instance.
     */

    public void setInstanceStatus(ClusterInstanceStatusDetails instanceStatus) {
        this.instanceStatus = instanceStatus;
    }

    /**
     * <p>
     * The status of the instance.
     * </p>
     * 
     * @return The status of the instance.
     */

    public ClusterInstanceStatusDetails getInstanceStatus() {
        return this.instanceStatus;
    }

    /**
     * <p>
     * The status of the instance.
     * </p>
     * 
     * @param instanceStatus
     *        The status of the instance.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ClusterNodeDetails withInstanceStatus(ClusterInstanceStatusDetails instanceStatus) {
        setInstanceStatus(instanceStatus);
        return this;
    }

    /**
     * <p>
     * The type of the instance.
     * </p>
     * 
     * @param instanceType
     *        The type of the instance.
     * @see ClusterInstanceType
     */

    public void setInstanceType(String instanceType) {
        this.instanceType = instanceType;
    }

    /**
     * <p>
     * The type of the instance.
     * </p>
     * 
     * @return The type of the instance.
     * @see ClusterInstanceType
     */

    public String getInstanceType() {
        return this.instanceType;
    }

    /**
     * <p>
     * The type of the instance.
     * </p>
     * 
     * @param instanceType
     *        The type of the instance.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ClusterInstanceType
     */

    public ClusterNodeDetails withInstanceType(String instanceType) {
        setInstanceType(instanceType);
        return this;
    }

    /**
     * <p>
     * The type of the instance.
     * </p>
     * 
     * @param instanceType
     *        The type of the instance.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ClusterInstanceType
     */

    public ClusterNodeDetails withInstanceType(ClusterInstanceType instanceType) {
        this.instanceType = instanceType.toString();
        return this;
    }

    /**
     * <p>
     * The time when the instance is launched.
     * </p>
     * 
     * @param launchTime
     *        The time when the instance is launched.
     */

    public void setLaunchTime(java.util.Date launchTime) {
        this.launchTime = launchTime;
    }

    /**
     * <p>
     * The time when the instance is launched.
     * </p>
     * 
     * @return The time when the instance is launched.
     */

    public java.util.Date getLaunchTime() {
        return this.launchTime;
    }

    /**
     * <p>
     * The time when the instance is launched.
     * </p>
     * 
     * @param launchTime
     *        The time when the instance is launched.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ClusterNodeDetails withLaunchTime(java.util.Date launchTime) {
        setLaunchTime(launchTime);
        return this;
    }

    /**
     * <p>
     * The LifeCycle configuration applied to the instance.
     * </p>
     * 
     * @param lifeCycleConfig
     *        The LifeCycle configuration applied to the instance.
     */

    public void setLifeCycleConfig(ClusterLifeCycleConfig lifeCycleConfig) {
        this.lifeCycleConfig = lifeCycleConfig;
    }

    /**
     * <p>
     * The LifeCycle configuration applied to the instance.
     * </p>
     * 
     * @return The LifeCycle configuration applied to the instance.
     */

    public ClusterLifeCycleConfig getLifeCycleConfig() {
        return this.lifeCycleConfig;
    }

    /**
     * <p>
     * The LifeCycle configuration applied to the instance.
     * </p>
     * 
     * @param lifeCycleConfig
     *        The LifeCycle configuration applied to the instance.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ClusterNodeDetails withLifeCycleConfig(ClusterLifeCycleConfig lifeCycleConfig) {
        setLifeCycleConfig(lifeCycleConfig);
        return this;
    }

    /**
     * <p>
     * The number of threads per CPU core you specified under <code>CreateCluster</code>.
     * </p>
     * 
     * @param threadsPerCore
     *        The number of threads per CPU core you specified under <code>CreateCluster</code>.
     */

    public void setThreadsPerCore(Integer threadsPerCore) {
        this.threadsPerCore = threadsPerCore;
    }

    /**
     * <p>
     * The number of threads per CPU core you specified under <code>CreateCluster</code>.
     * </p>
     * 
     * @return The number of threads per CPU core you specified under <code>CreateCluster</code>.
     */

    public Integer getThreadsPerCore() {
        return this.threadsPerCore;
    }

    /**
     * <p>
     * The number of threads per CPU core you specified under <code>CreateCluster</code>.
     * </p>
     * 
     * @param threadsPerCore
     *        The number of threads per CPU core you specified under <code>CreateCluster</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ClusterNodeDetails withThreadsPerCore(Integer threadsPerCore) {
        setThreadsPerCore(threadsPerCore);
        return this;
    }

    /**
     * <p>
     * The configurations of additional storage specified to the instance group where the instance (node) is launched.
     * </p>
     * 
     * @return The configurations of additional storage specified to the instance group where the instance (node) is
     *         launched.
     */

    public java.util.List<ClusterInstanceStorageConfig> getInstanceStorageConfigs() {
        return instanceStorageConfigs;
    }

    /**
     * <p>
     * The configurations of additional storage specified to the instance group where the instance (node) is launched.
     * </p>
     * 
     * @param instanceStorageConfigs
     *        The configurations of additional storage specified to the instance group where the instance (node) is
     *        launched.
     */

    public void setInstanceStorageConfigs(java.util.Collection<ClusterInstanceStorageConfig> instanceStorageConfigs) {
        if (instanceStorageConfigs == null) {
            this.instanceStorageConfigs = null;
            return;
        }

        this.instanceStorageConfigs = new java.util.ArrayList<ClusterInstanceStorageConfig>(instanceStorageConfigs);
    }

    /**
     * <p>
     * The configurations of additional storage specified to the instance group where the instance (node) is launched.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setInstanceStorageConfigs(java.util.Collection)} or
     * {@link #withInstanceStorageConfigs(java.util.Collection)} if you want to override the existing values.
     * </p>
     * 
     * @param instanceStorageConfigs
     *        The configurations of additional storage specified to the instance group where the instance (node) is
     *        launched.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ClusterNodeDetails withInstanceStorageConfigs(ClusterInstanceStorageConfig... instanceStorageConfigs) {
        if (this.instanceStorageConfigs == null) {
            setInstanceStorageConfigs(new java.util.ArrayList<ClusterInstanceStorageConfig>(instanceStorageConfigs.length));
        }
        for (ClusterInstanceStorageConfig ele : instanceStorageConfigs) {
            this.instanceStorageConfigs.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The configurations of additional storage specified to the instance group where the instance (node) is launched.
     * </p>
     * 
     * @param instanceStorageConfigs
     *        The configurations of additional storage specified to the instance group where the instance (node) is
     *        launched.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ClusterNodeDetails withInstanceStorageConfigs(java.util.Collection<ClusterInstanceStorageConfig> instanceStorageConfigs) {
        setInstanceStorageConfigs(instanceStorageConfigs);
        return this;
    }

    /**
     * <p>
     * The private primary IP address of the SageMaker HyperPod cluster node.
     * </p>
     * 
     * @param privatePrimaryIp
     *        The private primary IP address of the SageMaker HyperPod cluster node.
     */

    public void setPrivatePrimaryIp(String privatePrimaryIp) {
        this.privatePrimaryIp = privatePrimaryIp;
    }

    /**
     * <p>
     * The private primary IP address of the SageMaker HyperPod cluster node.
     * </p>
     * 
     * @return The private primary IP address of the SageMaker HyperPod cluster node.
     */

    public String getPrivatePrimaryIp() {
        return this.privatePrimaryIp;
    }

    /**
     * <p>
     * The private primary IP address of the SageMaker HyperPod cluster node.
     * </p>
     * 
     * @param privatePrimaryIp
     *        The private primary IP address of the SageMaker HyperPod cluster node.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ClusterNodeDetails withPrivatePrimaryIp(String privatePrimaryIp) {
        setPrivatePrimaryIp(privatePrimaryIp);
        return this;
    }

    /**
     * <p>
     * The private DNS hostname of the SageMaker HyperPod cluster node.
     * </p>
     * 
     * @param privateDnsHostname
     *        The private DNS hostname of the SageMaker HyperPod cluster node.
     */

    public void setPrivateDnsHostname(String privateDnsHostname) {
        this.privateDnsHostname = privateDnsHostname;
    }

    /**
     * <p>
     * The private DNS hostname of the SageMaker HyperPod cluster node.
     * </p>
     * 
     * @return The private DNS hostname of the SageMaker HyperPod cluster node.
     */

    public String getPrivateDnsHostname() {
        return this.privateDnsHostname;
    }

    /**
     * <p>
     * The private DNS hostname of the SageMaker HyperPod cluster node.
     * </p>
     * 
     * @param privateDnsHostname
     *        The private DNS hostname of the SageMaker HyperPod cluster node.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ClusterNodeDetails withPrivateDnsHostname(String privateDnsHostname) {
        setPrivateDnsHostname(privateDnsHostname);
        return this;
    }

    /**
     * <p>
     * The placement details of the SageMaker HyperPod cluster node.
     * </p>
     * 
     * @param placement
     *        The placement details of the SageMaker HyperPod cluster node.
     */

    public void setPlacement(ClusterInstancePlacement placement) {
        this.placement = placement;
    }

    /**
     * <p>
     * The placement details of the SageMaker HyperPod cluster node.
     * </p>
     * 
     * @return The placement details of the SageMaker HyperPod cluster node.
     */

    public ClusterInstancePlacement getPlacement() {
        return this.placement;
    }

    /**
     * <p>
     * The placement details of the SageMaker HyperPod cluster node.
     * </p>
     * 
     * @param placement
     *        The placement details of the SageMaker HyperPod cluster node.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ClusterNodeDetails withPlacement(ClusterInstancePlacement placement) {
        setPlacement(placement);
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
        if (getInstanceGroupName() != null)
            sb.append("InstanceGroupName: ").append(getInstanceGroupName()).append(",");
        if (getInstanceId() != null)
            sb.append("InstanceId: ").append(getInstanceId()).append(",");
        if (getInstanceStatus() != null)
            sb.append("InstanceStatus: ").append(getInstanceStatus()).append(",");
        if (getInstanceType() != null)
            sb.append("InstanceType: ").append(getInstanceType()).append(",");
        if (getLaunchTime() != null)
            sb.append("LaunchTime: ").append(getLaunchTime()).append(",");
        if (getLifeCycleConfig() != null)
            sb.append("LifeCycleConfig: ").append(getLifeCycleConfig()).append(",");
        if (getThreadsPerCore() != null)
            sb.append("ThreadsPerCore: ").append(getThreadsPerCore()).append(",");
        if (getInstanceStorageConfigs() != null)
            sb.append("InstanceStorageConfigs: ").append(getInstanceStorageConfigs()).append(",");
        if (getPrivatePrimaryIp() != null)
            sb.append("PrivatePrimaryIp: ").append(getPrivatePrimaryIp()).append(",");
        if (getPrivateDnsHostname() != null)
            sb.append("PrivateDnsHostname: ").append(getPrivateDnsHostname()).append(",");
        if (getPlacement() != null)
            sb.append("Placement: ").append(getPlacement());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ClusterNodeDetails == false)
            return false;
        ClusterNodeDetails other = (ClusterNodeDetails) obj;
        if (other.getInstanceGroupName() == null ^ this.getInstanceGroupName() == null)
            return false;
        if (other.getInstanceGroupName() != null && other.getInstanceGroupName().equals(this.getInstanceGroupName()) == false)
            return false;
        if (other.getInstanceId() == null ^ this.getInstanceId() == null)
            return false;
        if (other.getInstanceId() != null && other.getInstanceId().equals(this.getInstanceId()) == false)
            return false;
        if (other.getInstanceStatus() == null ^ this.getInstanceStatus() == null)
            return false;
        if (other.getInstanceStatus() != null && other.getInstanceStatus().equals(this.getInstanceStatus()) == false)
            return false;
        if (other.getInstanceType() == null ^ this.getInstanceType() == null)
            return false;
        if (other.getInstanceType() != null && other.getInstanceType().equals(this.getInstanceType()) == false)
            return false;
        if (other.getLaunchTime() == null ^ this.getLaunchTime() == null)
            return false;
        if (other.getLaunchTime() != null && other.getLaunchTime().equals(this.getLaunchTime()) == false)
            return false;
        if (other.getLifeCycleConfig() == null ^ this.getLifeCycleConfig() == null)
            return false;
        if (other.getLifeCycleConfig() != null && other.getLifeCycleConfig().equals(this.getLifeCycleConfig()) == false)
            return false;
        if (other.getThreadsPerCore() == null ^ this.getThreadsPerCore() == null)
            return false;
        if (other.getThreadsPerCore() != null && other.getThreadsPerCore().equals(this.getThreadsPerCore()) == false)
            return false;
        if (other.getInstanceStorageConfigs() == null ^ this.getInstanceStorageConfigs() == null)
            return false;
        if (other.getInstanceStorageConfigs() != null && other.getInstanceStorageConfigs().equals(this.getInstanceStorageConfigs()) == false)
            return false;
        if (other.getPrivatePrimaryIp() == null ^ this.getPrivatePrimaryIp() == null)
            return false;
        if (other.getPrivatePrimaryIp() != null && other.getPrivatePrimaryIp().equals(this.getPrivatePrimaryIp()) == false)
            return false;
        if (other.getPrivateDnsHostname() == null ^ this.getPrivateDnsHostname() == null)
            return false;
        if (other.getPrivateDnsHostname() != null && other.getPrivateDnsHostname().equals(this.getPrivateDnsHostname()) == false)
            return false;
        if (other.getPlacement() == null ^ this.getPlacement() == null)
            return false;
        if (other.getPlacement() != null && other.getPlacement().equals(this.getPlacement()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getInstanceGroupName() == null) ? 0 : getInstanceGroupName().hashCode());
        hashCode = prime * hashCode + ((getInstanceId() == null) ? 0 : getInstanceId().hashCode());
        hashCode = prime * hashCode + ((getInstanceStatus() == null) ? 0 : getInstanceStatus().hashCode());
        hashCode = prime * hashCode + ((getInstanceType() == null) ? 0 : getInstanceType().hashCode());
        hashCode = prime * hashCode + ((getLaunchTime() == null) ? 0 : getLaunchTime().hashCode());
        hashCode = prime * hashCode + ((getLifeCycleConfig() == null) ? 0 : getLifeCycleConfig().hashCode());
        hashCode = prime * hashCode + ((getThreadsPerCore() == null) ? 0 : getThreadsPerCore().hashCode());
        hashCode = prime * hashCode + ((getInstanceStorageConfigs() == null) ? 0 : getInstanceStorageConfigs().hashCode());
        hashCode = prime * hashCode + ((getPrivatePrimaryIp() == null) ? 0 : getPrivatePrimaryIp().hashCode());
        hashCode = prime * hashCode + ((getPrivateDnsHostname() == null) ? 0 : getPrivateDnsHostname().hashCode());
        hashCode = prime * hashCode + ((getPlacement() == null) ? 0 : getPlacement().hashCode());
        return hashCode;
    }

    @Override
    public ClusterNodeDetails clone() {
        try {
            return (ClusterNodeDetails) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.sagemaker.model.transform.ClusterNodeDetailsMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
