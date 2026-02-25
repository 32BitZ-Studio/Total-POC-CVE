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
 * Summarizes an optimization job by providing some of its key properties.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/sagemaker-2017-07-24/OptimizationJobSummary" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class OptimizationJobSummary implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The name that you assigned to the optimization job.
     * </p>
     */
    private String optimizationJobName;
    /**
     * <p>
     * The Amazon Resource Name (ARN) of the optimization job.
     * </p>
     */
    private String optimizationJobArn;
    /**
     * <p>
     * The time when you created the optimization job.
     * </p>
     */
    private java.util.Date creationTime;
    /**
     * <p>
     * The current status of the optimization job.
     * </p>
     */
    private String optimizationJobStatus;
    /**
     * <p>
     * The time when the optimization job started.
     * </p>
     */
    private java.util.Date optimizationStartTime;
    /**
     * <p>
     * The time when the optimization job finished processing.
     * </p>
     */
    private java.util.Date optimizationEndTime;
    /**
     * <p>
     * The time when the optimization job was last updated.
     * </p>
     */
    private java.util.Date lastModifiedTime;
    /**
     * <p>
     * The type of instance that hosts the optimized model that you create with the optimization job.
     * </p>
     */
    private String deploymentInstanceType;
    /**
     * <p>
     * The optimization techniques that are applied by the optimization job.
     * </p>
     */
    private java.util.List<String> optimizationTypes;

    /**
     * <p>
     * The name that you assigned to the optimization job.
     * </p>
     * 
     * @param optimizationJobName
     *        The name that you assigned to the optimization job.
     */

    public void setOptimizationJobName(String optimizationJobName) {
        this.optimizationJobName = optimizationJobName;
    }

    /**
     * <p>
     * The name that you assigned to the optimization job.
     * </p>
     * 
     * @return The name that you assigned to the optimization job.
     */

    public String getOptimizationJobName() {
        return this.optimizationJobName;
    }

    /**
     * <p>
     * The name that you assigned to the optimization job.
     * </p>
     * 
     * @param optimizationJobName
     *        The name that you assigned to the optimization job.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public OptimizationJobSummary withOptimizationJobName(String optimizationJobName) {
        setOptimizationJobName(optimizationJobName);
        return this;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the optimization job.
     * </p>
     * 
     * @param optimizationJobArn
     *        The Amazon Resource Name (ARN) of the optimization job.
     */

    public void setOptimizationJobArn(String optimizationJobArn) {
        this.optimizationJobArn = optimizationJobArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the optimization job.
     * </p>
     * 
     * @return The Amazon Resource Name (ARN) of the optimization job.
     */

    public String getOptimizationJobArn() {
        return this.optimizationJobArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the optimization job.
     * </p>
     * 
     * @param optimizationJobArn
     *        The Amazon Resource Name (ARN) of the optimization job.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public OptimizationJobSummary withOptimizationJobArn(String optimizationJobArn) {
        setOptimizationJobArn(optimizationJobArn);
        return this;
    }

    /**
     * <p>
     * The time when you created the optimization job.
     * </p>
     * 
     * @param creationTime
     *        The time when you created the optimization job.
     */

    public void setCreationTime(java.util.Date creationTime) {
        this.creationTime = creationTime;
    }

    /**
     * <p>
     * The time when you created the optimization job.
     * </p>
     * 
     * @return The time when you created the optimization job.
     */

    public java.util.Date getCreationTime() {
        return this.creationTime;
    }

    /**
     * <p>
     * The time when you created the optimization job.
     * </p>
     * 
     * @param creationTime
     *        The time when you created the optimization job.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public OptimizationJobSummary withCreationTime(java.util.Date creationTime) {
        setCreationTime(creationTime);
        return this;
    }

    /**
     * <p>
     * The current status of the optimization job.
     * </p>
     * 
     * @param optimizationJobStatus
     *        The current status of the optimization job.
     * @see OptimizationJobStatus
     */

    public void setOptimizationJobStatus(String optimizationJobStatus) {
        this.optimizationJobStatus = optimizationJobStatus;
    }

    /**
     * <p>
     * The current status of the optimization job.
     * </p>
     * 
     * @return The current status of the optimization job.
     * @see OptimizationJobStatus
     */

    public String getOptimizationJobStatus() {
        return this.optimizationJobStatus;
    }

    /**
     * <p>
     * The current status of the optimization job.
     * </p>
     * 
     * @param optimizationJobStatus
     *        The current status of the optimization job.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see OptimizationJobStatus
     */

    public OptimizationJobSummary withOptimizationJobStatus(String optimizationJobStatus) {
        setOptimizationJobStatus(optimizationJobStatus);
        return this;
    }

    /**
     * <p>
     * The current status of the optimization job.
     * </p>
     * 
     * @param optimizationJobStatus
     *        The current status of the optimization job.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see OptimizationJobStatus
     */

    public OptimizationJobSummary withOptimizationJobStatus(OptimizationJobStatus optimizationJobStatus) {
        this.optimizationJobStatus = optimizationJobStatus.toString();
        return this;
    }

    /**
     * <p>
     * The time when the optimization job started.
     * </p>
     * 
     * @param optimizationStartTime
     *        The time when the optimization job started.
     */

    public void setOptimizationStartTime(java.util.Date optimizationStartTime) {
        this.optimizationStartTime = optimizationStartTime;
    }

    /**
     * <p>
     * The time when the optimization job started.
     * </p>
     * 
     * @return The time when the optimization job started.
     */

    public java.util.Date getOptimizationStartTime() {
        return this.optimizationStartTime;
    }

    /**
     * <p>
     * The time when the optimization job started.
     * </p>
     * 
     * @param optimizationStartTime
     *        The time when the optimization job started.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public OptimizationJobSummary withOptimizationStartTime(java.util.Date optimizationStartTime) {
        setOptimizationStartTime(optimizationStartTime);
        return this;
    }

    /**
     * <p>
     * The time when the optimization job finished processing.
     * </p>
     * 
     * @param optimizationEndTime
     *        The time when the optimization job finished processing.
     */

    public void setOptimizationEndTime(java.util.Date optimizationEndTime) {
        this.optimizationEndTime = optimizationEndTime;
    }

    /**
     * <p>
     * The time when the optimization job finished processing.
     * </p>
     * 
     * @return The time when the optimization job finished processing.
     */

    public java.util.Date getOptimizationEndTime() {
        return this.optimizationEndTime;
    }

    /**
     * <p>
     * The time when the optimization job finished processing.
     * </p>
     * 
     * @param optimizationEndTime
     *        The time when the optimization job finished processing.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public OptimizationJobSummary withOptimizationEndTime(java.util.Date optimizationEndTime) {
        setOptimizationEndTime(optimizationEndTime);
        return this;
    }

    /**
     * <p>
     * The time when the optimization job was last updated.
     * </p>
     * 
     * @param lastModifiedTime
     *        The time when the optimization job was last updated.
     */

    public void setLastModifiedTime(java.util.Date lastModifiedTime) {
        this.lastModifiedTime = lastModifiedTime;
    }

    /**
     * <p>
     * The time when the optimization job was last updated.
     * </p>
     * 
     * @return The time when the optimization job was last updated.
     */

    public java.util.Date getLastModifiedTime() {
        return this.lastModifiedTime;
    }

    /**
     * <p>
     * The time when the optimization job was last updated.
     * </p>
     * 
     * @param lastModifiedTime
     *        The time when the optimization job was last updated.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public OptimizationJobSummary withLastModifiedTime(java.util.Date lastModifiedTime) {
        setLastModifiedTime(lastModifiedTime);
        return this;
    }

    /**
     * <p>
     * The type of instance that hosts the optimized model that you create with the optimization job.
     * </p>
     * 
     * @param deploymentInstanceType
     *        The type of instance that hosts the optimized model that you create with the optimization job.
     * @see OptimizationJobDeploymentInstanceType
     */

    public void setDeploymentInstanceType(String deploymentInstanceType) {
        this.deploymentInstanceType = deploymentInstanceType;
    }

    /**
     * <p>
     * The type of instance that hosts the optimized model that you create with the optimization job.
     * </p>
     * 
     * @return The type of instance that hosts the optimized model that you create with the optimization job.
     * @see OptimizationJobDeploymentInstanceType
     */

    public String getDeploymentInstanceType() {
        return this.deploymentInstanceType;
    }

    /**
     * <p>
     * The type of instance that hosts the optimized model that you create with the optimization job.
     * </p>
     * 
     * @param deploymentInstanceType
     *        The type of instance that hosts the optimized model that you create with the optimization job.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see OptimizationJobDeploymentInstanceType
     */

    public OptimizationJobSummary withDeploymentInstanceType(String deploymentInstanceType) {
        setDeploymentInstanceType(deploymentInstanceType);
        return this;
    }

    /**
     * <p>
     * The type of instance that hosts the optimized model that you create with the optimization job.
     * </p>
     * 
     * @param deploymentInstanceType
     *        The type of instance that hosts the optimized model that you create with the optimization job.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see OptimizationJobDeploymentInstanceType
     */

    public OptimizationJobSummary withDeploymentInstanceType(OptimizationJobDeploymentInstanceType deploymentInstanceType) {
        this.deploymentInstanceType = deploymentInstanceType.toString();
        return this;
    }

    /**
     * <p>
     * The optimization techniques that are applied by the optimization job.
     * </p>
     * 
     * @return The optimization techniques that are applied by the optimization job.
     */

    public java.util.List<String> getOptimizationTypes() {
        return optimizationTypes;
    }

    /**
     * <p>
     * The optimization techniques that are applied by the optimization job.
     * </p>
     * 
     * @param optimizationTypes
     *        The optimization techniques that are applied by the optimization job.
     */

    public void setOptimizationTypes(java.util.Collection<String> optimizationTypes) {
        if (optimizationTypes == null) {
            this.optimizationTypes = null;
            return;
        }

        this.optimizationTypes = new java.util.ArrayList<String>(optimizationTypes);
    }

    /**
     * <p>
     * The optimization techniques that are applied by the optimization job.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setOptimizationTypes(java.util.Collection)} or {@link #withOptimizationTypes(java.util.Collection)} if
     * you want to override the existing values.
     * </p>
     * 
     * @param optimizationTypes
     *        The optimization techniques that are applied by the optimization job.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public OptimizationJobSummary withOptimizationTypes(String... optimizationTypes) {
        if (this.optimizationTypes == null) {
            setOptimizationTypes(new java.util.ArrayList<String>(optimizationTypes.length));
        }
        for (String ele : optimizationTypes) {
            this.optimizationTypes.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The optimization techniques that are applied by the optimization job.
     * </p>
     * 
     * @param optimizationTypes
     *        The optimization techniques that are applied by the optimization job.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public OptimizationJobSummary withOptimizationTypes(java.util.Collection<String> optimizationTypes) {
        setOptimizationTypes(optimizationTypes);
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
        if (getOptimizationJobName() != null)
            sb.append("OptimizationJobName: ").append(getOptimizationJobName()).append(",");
        if (getOptimizationJobArn() != null)
            sb.append("OptimizationJobArn: ").append(getOptimizationJobArn()).append(",");
        if (getCreationTime() != null)
            sb.append("CreationTime: ").append(getCreationTime()).append(",");
        if (getOptimizationJobStatus() != null)
            sb.append("OptimizationJobStatus: ").append(getOptimizationJobStatus()).append(",");
        if (getOptimizationStartTime() != null)
            sb.append("OptimizationStartTime: ").append(getOptimizationStartTime()).append(",");
        if (getOptimizationEndTime() != null)
            sb.append("OptimizationEndTime: ").append(getOptimizationEndTime()).append(",");
        if (getLastModifiedTime() != null)
            sb.append("LastModifiedTime: ").append(getLastModifiedTime()).append(",");
        if (getDeploymentInstanceType() != null)
            sb.append("DeploymentInstanceType: ").append(getDeploymentInstanceType()).append(",");
        if (getOptimizationTypes() != null)
            sb.append("OptimizationTypes: ").append(getOptimizationTypes());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof OptimizationJobSummary == false)
            return false;
        OptimizationJobSummary other = (OptimizationJobSummary) obj;
        if (other.getOptimizationJobName() == null ^ this.getOptimizationJobName() == null)
            return false;
        if (other.getOptimizationJobName() != null && other.getOptimizationJobName().equals(this.getOptimizationJobName()) == false)
            return false;
        if (other.getOptimizationJobArn() == null ^ this.getOptimizationJobArn() == null)
            return false;
        if (other.getOptimizationJobArn() != null && other.getOptimizationJobArn().equals(this.getOptimizationJobArn()) == false)
            return false;
        if (other.getCreationTime() == null ^ this.getCreationTime() == null)
            return false;
        if (other.getCreationTime() != null && other.getCreationTime().equals(this.getCreationTime()) == false)
            return false;
        if (other.getOptimizationJobStatus() == null ^ this.getOptimizationJobStatus() == null)
            return false;
        if (other.getOptimizationJobStatus() != null && other.getOptimizationJobStatus().equals(this.getOptimizationJobStatus()) == false)
            return false;
        if (other.getOptimizationStartTime() == null ^ this.getOptimizationStartTime() == null)
            return false;
        if (other.getOptimizationStartTime() != null && other.getOptimizationStartTime().equals(this.getOptimizationStartTime()) == false)
            return false;
        if (other.getOptimizationEndTime() == null ^ this.getOptimizationEndTime() == null)
            return false;
        if (other.getOptimizationEndTime() != null && other.getOptimizationEndTime().equals(this.getOptimizationEndTime()) == false)
            return false;
        if (other.getLastModifiedTime() == null ^ this.getLastModifiedTime() == null)
            return false;
        if (other.getLastModifiedTime() != null && other.getLastModifiedTime().equals(this.getLastModifiedTime()) == false)
            return false;
        if (other.getDeploymentInstanceType() == null ^ this.getDeploymentInstanceType() == null)
            return false;
        if (other.getDeploymentInstanceType() != null && other.getDeploymentInstanceType().equals(this.getDeploymentInstanceType()) == false)
            return false;
        if (other.getOptimizationTypes() == null ^ this.getOptimizationTypes() == null)
            return false;
        if (other.getOptimizationTypes() != null && other.getOptimizationTypes().equals(this.getOptimizationTypes()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getOptimizationJobName() == null) ? 0 : getOptimizationJobName().hashCode());
        hashCode = prime * hashCode + ((getOptimizationJobArn() == null) ? 0 : getOptimizationJobArn().hashCode());
        hashCode = prime * hashCode + ((getCreationTime() == null) ? 0 : getCreationTime().hashCode());
        hashCode = prime * hashCode + ((getOptimizationJobStatus() == null) ? 0 : getOptimizationJobStatus().hashCode());
        hashCode = prime * hashCode + ((getOptimizationStartTime() == null) ? 0 : getOptimizationStartTime().hashCode());
        hashCode = prime * hashCode + ((getOptimizationEndTime() == null) ? 0 : getOptimizationEndTime().hashCode());
        hashCode = prime * hashCode + ((getLastModifiedTime() == null) ? 0 : getLastModifiedTime().hashCode());
        hashCode = prime * hashCode + ((getDeploymentInstanceType() == null) ? 0 : getDeploymentInstanceType().hashCode());
        hashCode = prime * hashCode + ((getOptimizationTypes() == null) ? 0 : getOptimizationTypes().hashCode());
        return hashCode;
    }

    @Override
    public OptimizationJobSummary clone() {
        try {
            return (OptimizationJobSummary) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.sagemaker.model.transform.OptimizationJobSummaryMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
