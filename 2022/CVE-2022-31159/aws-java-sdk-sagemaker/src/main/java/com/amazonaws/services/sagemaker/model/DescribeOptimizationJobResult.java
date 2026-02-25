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

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/sagemaker-2017-07-24/DescribeOptimizationJob" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class DescribeOptimizationJobResult extends com.amazonaws.AmazonWebServiceResult<com.amazonaws.ResponseMetadata> implements Serializable, Cloneable {

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the optimization job.
     * </p>
     */
    private String optimizationJobArn;
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
     * The time when you created the optimization job.
     * </p>
     */
    private java.util.Date creationTime;
    /**
     * <p>
     * The time when the optimization job was last updated.
     * </p>
     */
    private java.util.Date lastModifiedTime;
    /**
     * <p>
     * If the optimization job status is <code>FAILED</code>, the reason for the failure.
     * </p>
     */
    private String failureReason;
    /**
     * <p>
     * The name that you assigned to the optimization job.
     * </p>
     */
    private String optimizationJobName;
    /**
     * <p>
     * The location of the source model to optimize with an optimization job.
     * </p>
     */
    private OptimizationJobModelSource modelSource;
    /**
     * <p>
     * The environment variables to set in the model container.
     * </p>
     */
    private java.util.Map<String, String> optimizationEnvironment;
    /**
     * <p>
     * The type of instance that hosts the optimized model that you create with the optimization job.
     * </p>
     */
    private String deploymentInstanceType;
    /**
     * <p>
     * Settings for each of the optimization techniques that the job applies.
     * </p>
     */
    private java.util.List<OptimizationConfig> optimizationConfigs;
    /**
     * <p>
     * Details for where to store the optimized model that you create with the optimization job.
     * </p>
     */
    private OptimizationJobOutputConfig outputConfig;
    /**
     * <p>
     * Output values produced by an optimization job.
     * </p>
     */
    private OptimizationOutput optimizationOutput;
    /**
     * <p>
     * The ARN of the IAM role that you assigned to the optimization job.
     * </p>
     */
    private String roleArn;

    private StoppingCondition stoppingCondition;
    /**
     * <p>
     * A VPC in Amazon VPC that your optimized model has access to.
     * </p>
     */
    private OptimizationVpcConfig vpcConfig;

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

    public DescribeOptimizationJobResult withOptimizationJobArn(String optimizationJobArn) {
        setOptimizationJobArn(optimizationJobArn);
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

    public DescribeOptimizationJobResult withOptimizationJobStatus(String optimizationJobStatus) {
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

    public DescribeOptimizationJobResult withOptimizationJobStatus(OptimizationJobStatus optimizationJobStatus) {
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

    public DescribeOptimizationJobResult withOptimizationStartTime(java.util.Date optimizationStartTime) {
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

    public DescribeOptimizationJobResult withOptimizationEndTime(java.util.Date optimizationEndTime) {
        setOptimizationEndTime(optimizationEndTime);
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

    public DescribeOptimizationJobResult withCreationTime(java.util.Date creationTime) {
        setCreationTime(creationTime);
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

    public DescribeOptimizationJobResult withLastModifiedTime(java.util.Date lastModifiedTime) {
        setLastModifiedTime(lastModifiedTime);
        return this;
    }

    /**
     * <p>
     * If the optimization job status is <code>FAILED</code>, the reason for the failure.
     * </p>
     * 
     * @param failureReason
     *        If the optimization job status is <code>FAILED</code>, the reason for the failure.
     */

    public void setFailureReason(String failureReason) {
        this.failureReason = failureReason;
    }

    /**
     * <p>
     * If the optimization job status is <code>FAILED</code>, the reason for the failure.
     * </p>
     * 
     * @return If the optimization job status is <code>FAILED</code>, the reason for the failure.
     */

    public String getFailureReason() {
        return this.failureReason;
    }

    /**
     * <p>
     * If the optimization job status is <code>FAILED</code>, the reason for the failure.
     * </p>
     * 
     * @param failureReason
     *        If the optimization job status is <code>FAILED</code>, the reason for the failure.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeOptimizationJobResult withFailureReason(String failureReason) {
        setFailureReason(failureReason);
        return this;
    }

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

    public DescribeOptimizationJobResult withOptimizationJobName(String optimizationJobName) {
        setOptimizationJobName(optimizationJobName);
        return this;
    }

    /**
     * <p>
     * The location of the source model to optimize with an optimization job.
     * </p>
     * 
     * @param modelSource
     *        The location of the source model to optimize with an optimization job.
     */

    public void setModelSource(OptimizationJobModelSource modelSource) {
        this.modelSource = modelSource;
    }

    /**
     * <p>
     * The location of the source model to optimize with an optimization job.
     * </p>
     * 
     * @return The location of the source model to optimize with an optimization job.
     */

    public OptimizationJobModelSource getModelSource() {
        return this.modelSource;
    }

    /**
     * <p>
     * The location of the source model to optimize with an optimization job.
     * </p>
     * 
     * @param modelSource
     *        The location of the source model to optimize with an optimization job.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeOptimizationJobResult withModelSource(OptimizationJobModelSource modelSource) {
        setModelSource(modelSource);
        return this;
    }

    /**
     * <p>
     * The environment variables to set in the model container.
     * </p>
     * 
     * @return The environment variables to set in the model container.
     */

    public java.util.Map<String, String> getOptimizationEnvironment() {
        return optimizationEnvironment;
    }

    /**
     * <p>
     * The environment variables to set in the model container.
     * </p>
     * 
     * @param optimizationEnvironment
     *        The environment variables to set in the model container.
     */

    public void setOptimizationEnvironment(java.util.Map<String, String> optimizationEnvironment) {
        this.optimizationEnvironment = optimizationEnvironment;
    }

    /**
     * <p>
     * The environment variables to set in the model container.
     * </p>
     * 
     * @param optimizationEnvironment
     *        The environment variables to set in the model container.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeOptimizationJobResult withOptimizationEnvironment(java.util.Map<String, String> optimizationEnvironment) {
        setOptimizationEnvironment(optimizationEnvironment);
        return this;
    }

    /**
     * Add a single OptimizationEnvironment entry
     *
     * @see DescribeOptimizationJobResult#withOptimizationEnvironment
     * @returns a reference to this object so that method calls can be chained together.
     */

    public DescribeOptimizationJobResult addOptimizationEnvironmentEntry(String key, String value) {
        if (null == this.optimizationEnvironment) {
            this.optimizationEnvironment = new java.util.HashMap<String, String>();
        }
        if (this.optimizationEnvironment.containsKey(key))
            throw new IllegalArgumentException("Duplicated keys (" + key.toString() + ") are provided.");
        this.optimizationEnvironment.put(key, value);
        return this;
    }

    /**
     * Removes all the entries added into OptimizationEnvironment.
     *
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeOptimizationJobResult clearOptimizationEnvironmentEntries() {
        this.optimizationEnvironment = null;
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

    public DescribeOptimizationJobResult withDeploymentInstanceType(String deploymentInstanceType) {
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

    public DescribeOptimizationJobResult withDeploymentInstanceType(OptimizationJobDeploymentInstanceType deploymentInstanceType) {
        this.deploymentInstanceType = deploymentInstanceType.toString();
        return this;
    }

    /**
     * <p>
     * Settings for each of the optimization techniques that the job applies.
     * </p>
     * 
     * @return Settings for each of the optimization techniques that the job applies.
     */

    public java.util.List<OptimizationConfig> getOptimizationConfigs() {
        return optimizationConfigs;
    }

    /**
     * <p>
     * Settings for each of the optimization techniques that the job applies.
     * </p>
     * 
     * @param optimizationConfigs
     *        Settings for each of the optimization techniques that the job applies.
     */

    public void setOptimizationConfigs(java.util.Collection<OptimizationConfig> optimizationConfigs) {
        if (optimizationConfigs == null) {
            this.optimizationConfigs = null;
            return;
        }

        this.optimizationConfigs = new java.util.ArrayList<OptimizationConfig>(optimizationConfigs);
    }

    /**
     * <p>
     * Settings for each of the optimization techniques that the job applies.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setOptimizationConfigs(java.util.Collection)} or {@link #withOptimizationConfigs(java.util.Collection)}
     * if you want to override the existing values.
     * </p>
     * 
     * @param optimizationConfigs
     *        Settings for each of the optimization techniques that the job applies.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeOptimizationJobResult withOptimizationConfigs(OptimizationConfig... optimizationConfigs) {
        if (this.optimizationConfigs == null) {
            setOptimizationConfigs(new java.util.ArrayList<OptimizationConfig>(optimizationConfigs.length));
        }
        for (OptimizationConfig ele : optimizationConfigs) {
            this.optimizationConfigs.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * Settings for each of the optimization techniques that the job applies.
     * </p>
     * 
     * @param optimizationConfigs
     *        Settings for each of the optimization techniques that the job applies.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeOptimizationJobResult withOptimizationConfigs(java.util.Collection<OptimizationConfig> optimizationConfigs) {
        setOptimizationConfigs(optimizationConfigs);
        return this;
    }

    /**
     * <p>
     * Details for where to store the optimized model that you create with the optimization job.
     * </p>
     * 
     * @param outputConfig
     *        Details for where to store the optimized model that you create with the optimization job.
     */

    public void setOutputConfig(OptimizationJobOutputConfig outputConfig) {
        this.outputConfig = outputConfig;
    }

    /**
     * <p>
     * Details for where to store the optimized model that you create with the optimization job.
     * </p>
     * 
     * @return Details for where to store the optimized model that you create with the optimization job.
     */

    public OptimizationJobOutputConfig getOutputConfig() {
        return this.outputConfig;
    }

    /**
     * <p>
     * Details for where to store the optimized model that you create with the optimization job.
     * </p>
     * 
     * @param outputConfig
     *        Details for where to store the optimized model that you create with the optimization job.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeOptimizationJobResult withOutputConfig(OptimizationJobOutputConfig outputConfig) {
        setOutputConfig(outputConfig);
        return this;
    }

    /**
     * <p>
     * Output values produced by an optimization job.
     * </p>
     * 
     * @param optimizationOutput
     *        Output values produced by an optimization job.
     */

    public void setOptimizationOutput(OptimizationOutput optimizationOutput) {
        this.optimizationOutput = optimizationOutput;
    }

    /**
     * <p>
     * Output values produced by an optimization job.
     * </p>
     * 
     * @return Output values produced by an optimization job.
     */

    public OptimizationOutput getOptimizationOutput() {
        return this.optimizationOutput;
    }

    /**
     * <p>
     * Output values produced by an optimization job.
     * </p>
     * 
     * @param optimizationOutput
     *        Output values produced by an optimization job.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeOptimizationJobResult withOptimizationOutput(OptimizationOutput optimizationOutput) {
        setOptimizationOutput(optimizationOutput);
        return this;
    }

    /**
     * <p>
     * The ARN of the IAM role that you assigned to the optimization job.
     * </p>
     * 
     * @param roleArn
     *        The ARN of the IAM role that you assigned to the optimization job.
     */

    public void setRoleArn(String roleArn) {
        this.roleArn = roleArn;
    }

    /**
     * <p>
     * The ARN of the IAM role that you assigned to the optimization job.
     * </p>
     * 
     * @return The ARN of the IAM role that you assigned to the optimization job.
     */

    public String getRoleArn() {
        return this.roleArn;
    }

    /**
     * <p>
     * The ARN of the IAM role that you assigned to the optimization job.
     * </p>
     * 
     * @param roleArn
     *        The ARN of the IAM role that you assigned to the optimization job.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeOptimizationJobResult withRoleArn(String roleArn) {
        setRoleArn(roleArn);
        return this;
    }

    /**
     * @param stoppingCondition
     */

    public void setStoppingCondition(StoppingCondition stoppingCondition) {
        this.stoppingCondition = stoppingCondition;
    }

    /**
     * @return
     */

    public StoppingCondition getStoppingCondition() {
        return this.stoppingCondition;
    }

    /**
     * @param stoppingCondition
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeOptimizationJobResult withStoppingCondition(StoppingCondition stoppingCondition) {
        setStoppingCondition(stoppingCondition);
        return this;
    }

    /**
     * <p>
     * A VPC in Amazon VPC that your optimized model has access to.
     * </p>
     * 
     * @param vpcConfig
     *        A VPC in Amazon VPC that your optimized model has access to.
     */

    public void setVpcConfig(OptimizationVpcConfig vpcConfig) {
        this.vpcConfig = vpcConfig;
    }

    /**
     * <p>
     * A VPC in Amazon VPC that your optimized model has access to.
     * </p>
     * 
     * @return A VPC in Amazon VPC that your optimized model has access to.
     */

    public OptimizationVpcConfig getVpcConfig() {
        return this.vpcConfig;
    }

    /**
     * <p>
     * A VPC in Amazon VPC that your optimized model has access to.
     * </p>
     * 
     * @param vpcConfig
     *        A VPC in Amazon VPC that your optimized model has access to.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeOptimizationJobResult withVpcConfig(OptimizationVpcConfig vpcConfig) {
        setVpcConfig(vpcConfig);
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
        if (getOptimizationJobArn() != null)
            sb.append("OptimizationJobArn: ").append(getOptimizationJobArn()).append(",");
        if (getOptimizationJobStatus() != null)
            sb.append("OptimizationJobStatus: ").append(getOptimizationJobStatus()).append(",");
        if (getOptimizationStartTime() != null)
            sb.append("OptimizationStartTime: ").append(getOptimizationStartTime()).append(",");
        if (getOptimizationEndTime() != null)
            sb.append("OptimizationEndTime: ").append(getOptimizationEndTime()).append(",");
        if (getCreationTime() != null)
            sb.append("CreationTime: ").append(getCreationTime()).append(",");
        if (getLastModifiedTime() != null)
            sb.append("LastModifiedTime: ").append(getLastModifiedTime()).append(",");
        if (getFailureReason() != null)
            sb.append("FailureReason: ").append(getFailureReason()).append(",");
        if (getOptimizationJobName() != null)
            sb.append("OptimizationJobName: ").append(getOptimizationJobName()).append(",");
        if (getModelSource() != null)
            sb.append("ModelSource: ").append(getModelSource()).append(",");
        if (getOptimizationEnvironment() != null)
            sb.append("OptimizationEnvironment: ").append(getOptimizationEnvironment()).append(",");
        if (getDeploymentInstanceType() != null)
            sb.append("DeploymentInstanceType: ").append(getDeploymentInstanceType()).append(",");
        if (getOptimizationConfigs() != null)
            sb.append("OptimizationConfigs: ").append(getOptimizationConfigs()).append(",");
        if (getOutputConfig() != null)
            sb.append("OutputConfig: ").append(getOutputConfig()).append(",");
        if (getOptimizationOutput() != null)
            sb.append("OptimizationOutput: ").append(getOptimizationOutput()).append(",");
        if (getRoleArn() != null)
            sb.append("RoleArn: ").append(getRoleArn()).append(",");
        if (getStoppingCondition() != null)
            sb.append("StoppingCondition: ").append(getStoppingCondition()).append(",");
        if (getVpcConfig() != null)
            sb.append("VpcConfig: ").append(getVpcConfig());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof DescribeOptimizationJobResult == false)
            return false;
        DescribeOptimizationJobResult other = (DescribeOptimizationJobResult) obj;
        if (other.getOptimizationJobArn() == null ^ this.getOptimizationJobArn() == null)
            return false;
        if (other.getOptimizationJobArn() != null && other.getOptimizationJobArn().equals(this.getOptimizationJobArn()) == false)
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
        if (other.getCreationTime() == null ^ this.getCreationTime() == null)
            return false;
        if (other.getCreationTime() != null && other.getCreationTime().equals(this.getCreationTime()) == false)
            return false;
        if (other.getLastModifiedTime() == null ^ this.getLastModifiedTime() == null)
            return false;
        if (other.getLastModifiedTime() != null && other.getLastModifiedTime().equals(this.getLastModifiedTime()) == false)
            return false;
        if (other.getFailureReason() == null ^ this.getFailureReason() == null)
            return false;
        if (other.getFailureReason() != null && other.getFailureReason().equals(this.getFailureReason()) == false)
            return false;
        if (other.getOptimizationJobName() == null ^ this.getOptimizationJobName() == null)
            return false;
        if (other.getOptimizationJobName() != null && other.getOptimizationJobName().equals(this.getOptimizationJobName()) == false)
            return false;
        if (other.getModelSource() == null ^ this.getModelSource() == null)
            return false;
        if (other.getModelSource() != null && other.getModelSource().equals(this.getModelSource()) == false)
            return false;
        if (other.getOptimizationEnvironment() == null ^ this.getOptimizationEnvironment() == null)
            return false;
        if (other.getOptimizationEnvironment() != null && other.getOptimizationEnvironment().equals(this.getOptimizationEnvironment()) == false)
            return false;
        if (other.getDeploymentInstanceType() == null ^ this.getDeploymentInstanceType() == null)
            return false;
        if (other.getDeploymentInstanceType() != null && other.getDeploymentInstanceType().equals(this.getDeploymentInstanceType()) == false)
            return false;
        if (other.getOptimizationConfigs() == null ^ this.getOptimizationConfigs() == null)
            return false;
        if (other.getOptimizationConfigs() != null && other.getOptimizationConfigs().equals(this.getOptimizationConfigs()) == false)
            return false;
        if (other.getOutputConfig() == null ^ this.getOutputConfig() == null)
            return false;
        if (other.getOutputConfig() != null && other.getOutputConfig().equals(this.getOutputConfig()) == false)
            return false;
        if (other.getOptimizationOutput() == null ^ this.getOptimizationOutput() == null)
            return false;
        if (other.getOptimizationOutput() != null && other.getOptimizationOutput().equals(this.getOptimizationOutput()) == false)
            return false;
        if (other.getRoleArn() == null ^ this.getRoleArn() == null)
            return false;
        if (other.getRoleArn() != null && other.getRoleArn().equals(this.getRoleArn()) == false)
            return false;
        if (other.getStoppingCondition() == null ^ this.getStoppingCondition() == null)
            return false;
        if (other.getStoppingCondition() != null && other.getStoppingCondition().equals(this.getStoppingCondition()) == false)
            return false;
        if (other.getVpcConfig() == null ^ this.getVpcConfig() == null)
            return false;
        if (other.getVpcConfig() != null && other.getVpcConfig().equals(this.getVpcConfig()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getOptimizationJobArn() == null) ? 0 : getOptimizationJobArn().hashCode());
        hashCode = prime * hashCode + ((getOptimizationJobStatus() == null) ? 0 : getOptimizationJobStatus().hashCode());
        hashCode = prime * hashCode + ((getOptimizationStartTime() == null) ? 0 : getOptimizationStartTime().hashCode());
        hashCode = prime * hashCode + ((getOptimizationEndTime() == null) ? 0 : getOptimizationEndTime().hashCode());
        hashCode = prime * hashCode + ((getCreationTime() == null) ? 0 : getCreationTime().hashCode());
        hashCode = prime * hashCode + ((getLastModifiedTime() == null) ? 0 : getLastModifiedTime().hashCode());
        hashCode = prime * hashCode + ((getFailureReason() == null) ? 0 : getFailureReason().hashCode());
        hashCode = prime * hashCode + ((getOptimizationJobName() == null) ? 0 : getOptimizationJobName().hashCode());
        hashCode = prime * hashCode + ((getModelSource() == null) ? 0 : getModelSource().hashCode());
        hashCode = prime * hashCode + ((getOptimizationEnvironment() == null) ? 0 : getOptimizationEnvironment().hashCode());
        hashCode = prime * hashCode + ((getDeploymentInstanceType() == null) ? 0 : getDeploymentInstanceType().hashCode());
        hashCode = prime * hashCode + ((getOptimizationConfigs() == null) ? 0 : getOptimizationConfigs().hashCode());
        hashCode = prime * hashCode + ((getOutputConfig() == null) ? 0 : getOutputConfig().hashCode());
        hashCode = prime * hashCode + ((getOptimizationOutput() == null) ? 0 : getOptimizationOutput().hashCode());
        hashCode = prime * hashCode + ((getRoleArn() == null) ? 0 : getRoleArn().hashCode());
        hashCode = prime * hashCode + ((getStoppingCondition() == null) ? 0 : getStoppingCondition().hashCode());
        hashCode = prime * hashCode + ((getVpcConfig() == null) ? 0 : getVpcConfig().hashCode());
        return hashCode;
    }

    @Override
    public DescribeOptimizationJobResult clone() {
        try {
            return (DescribeOptimizationJobResult) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

}
