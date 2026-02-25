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

import com.amazonaws.AmazonWebServiceRequest;

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/sagemaker-2017-07-24/CreateOptimizationJob" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class CreateOptimizationJobRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * A custom name for the new optimization job.
     * </p>
     */
    private String optimizationJobName;
    /**
     * <p>
     * The Amazon Resource Name (ARN) of an IAM role that enables Amazon SageMaker to perform tasks on your behalf.
     * </p>
     * <p>
     * During model optimization, Amazon SageMaker needs your permission to:
     * </p>
     * <ul>
     * <li>
     * <p>
     * Read input data from an S3 bucket
     * </p>
     * </li>
     * <li>
     * <p>
     * Write model artifacts to an S3 bucket
     * </p>
     * </li>
     * <li>
     * <p>
     * Write logs to Amazon CloudWatch Logs
     * </p>
     * </li>
     * <li>
     * <p>
     * Publish metrics to Amazon CloudWatch
     * </p>
     * </li>
     * </ul>
     * <p>
     * You grant permissions for all of these tasks to an IAM role. To pass this role to Amazon SageMaker, the caller of
     * this API must have the <code>iam:PassRole</code> permission. For more information, see <a
     * href="https://docs.aws.amazon.com/sagemaker/latest/dg/sagemaker-roles.html">Amazon SageMaker Roles.</a>
     * </p>
     */
    private String roleArn;
    /**
     * <p>
     * The location of the source model to optimize with an optimization job.
     * </p>
     */
    private OptimizationJobModelSource modelSource;
    /**
     * <p>
     * The type of instance that hosts the optimized model that you create with the optimization job.
     * </p>
     */
    private String deploymentInstanceType;
    /**
     * <p>
     * The environment variables to set in the model container.
     * </p>
     */
    private java.util.Map<String, String> optimizationEnvironment;
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

    private StoppingCondition stoppingCondition;
    /**
     * <p>
     * A list of key-value pairs associated with the optimization job. For more information, see <a
     * href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a>
     * in the <i>Amazon Web Services General Reference Guide</i>.
     * </p>
     */
    private java.util.List<Tag> tags;
    /**
     * <p>
     * A VPC in Amazon VPC that your optimized model has access to.
     * </p>
     */
    private OptimizationVpcConfig vpcConfig;

    /**
     * <p>
     * A custom name for the new optimization job.
     * </p>
     * 
     * @param optimizationJobName
     *        A custom name for the new optimization job.
     */

    public void setOptimizationJobName(String optimizationJobName) {
        this.optimizationJobName = optimizationJobName;
    }

    /**
     * <p>
     * A custom name for the new optimization job.
     * </p>
     * 
     * @return A custom name for the new optimization job.
     */

    public String getOptimizationJobName() {
        return this.optimizationJobName;
    }

    /**
     * <p>
     * A custom name for the new optimization job.
     * </p>
     * 
     * @param optimizationJobName
     *        A custom name for the new optimization job.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateOptimizationJobRequest withOptimizationJobName(String optimizationJobName) {
        setOptimizationJobName(optimizationJobName);
        return this;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of an IAM role that enables Amazon SageMaker to perform tasks on your behalf.
     * </p>
     * <p>
     * During model optimization, Amazon SageMaker needs your permission to:
     * </p>
     * <ul>
     * <li>
     * <p>
     * Read input data from an S3 bucket
     * </p>
     * </li>
     * <li>
     * <p>
     * Write model artifacts to an S3 bucket
     * </p>
     * </li>
     * <li>
     * <p>
     * Write logs to Amazon CloudWatch Logs
     * </p>
     * </li>
     * <li>
     * <p>
     * Publish metrics to Amazon CloudWatch
     * </p>
     * </li>
     * </ul>
     * <p>
     * You grant permissions for all of these tasks to an IAM role. To pass this role to Amazon SageMaker, the caller of
     * this API must have the <code>iam:PassRole</code> permission. For more information, see <a
     * href="https://docs.aws.amazon.com/sagemaker/latest/dg/sagemaker-roles.html">Amazon SageMaker Roles.</a>
     * </p>
     * 
     * @param roleArn
     *        The Amazon Resource Name (ARN) of an IAM role that enables Amazon SageMaker to perform tasks on your
     *        behalf. </p>
     *        <p>
     *        During model optimization, Amazon SageMaker needs your permission to:
     *        </p>
     *        <ul>
     *        <li>
     *        <p>
     *        Read input data from an S3 bucket
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        Write model artifacts to an S3 bucket
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        Write logs to Amazon CloudWatch Logs
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        Publish metrics to Amazon CloudWatch
     *        </p>
     *        </li>
     *        </ul>
     *        <p>
     *        You grant permissions for all of these tasks to an IAM role. To pass this role to Amazon SageMaker, the
     *        caller of this API must have the <code>iam:PassRole</code> permission. For more information, see <a
     *        href="https://docs.aws.amazon.com/sagemaker/latest/dg/sagemaker-roles.html">Amazon SageMaker Roles.</a>
     */

    public void setRoleArn(String roleArn) {
        this.roleArn = roleArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of an IAM role that enables Amazon SageMaker to perform tasks on your behalf.
     * </p>
     * <p>
     * During model optimization, Amazon SageMaker needs your permission to:
     * </p>
     * <ul>
     * <li>
     * <p>
     * Read input data from an S3 bucket
     * </p>
     * </li>
     * <li>
     * <p>
     * Write model artifacts to an S3 bucket
     * </p>
     * </li>
     * <li>
     * <p>
     * Write logs to Amazon CloudWatch Logs
     * </p>
     * </li>
     * <li>
     * <p>
     * Publish metrics to Amazon CloudWatch
     * </p>
     * </li>
     * </ul>
     * <p>
     * You grant permissions for all of these tasks to an IAM role. To pass this role to Amazon SageMaker, the caller of
     * this API must have the <code>iam:PassRole</code> permission. For more information, see <a
     * href="https://docs.aws.amazon.com/sagemaker/latest/dg/sagemaker-roles.html">Amazon SageMaker Roles.</a>
     * </p>
     * 
     * @return The Amazon Resource Name (ARN) of an IAM role that enables Amazon SageMaker to perform tasks on your
     *         behalf. </p>
     *         <p>
     *         During model optimization, Amazon SageMaker needs your permission to:
     *         </p>
     *         <ul>
     *         <li>
     *         <p>
     *         Read input data from an S3 bucket
     *         </p>
     *         </li>
     *         <li>
     *         <p>
     *         Write model artifacts to an S3 bucket
     *         </p>
     *         </li>
     *         <li>
     *         <p>
     *         Write logs to Amazon CloudWatch Logs
     *         </p>
     *         </li>
     *         <li>
     *         <p>
     *         Publish metrics to Amazon CloudWatch
     *         </p>
     *         </li>
     *         </ul>
     *         <p>
     *         You grant permissions for all of these tasks to an IAM role. To pass this role to Amazon SageMaker, the
     *         caller of this API must have the <code>iam:PassRole</code> permission. For more information, see <a
     *         href="https://docs.aws.amazon.com/sagemaker/latest/dg/sagemaker-roles.html">Amazon SageMaker Roles.</a>
     */

    public String getRoleArn() {
        return this.roleArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of an IAM role that enables Amazon SageMaker to perform tasks on your behalf.
     * </p>
     * <p>
     * During model optimization, Amazon SageMaker needs your permission to:
     * </p>
     * <ul>
     * <li>
     * <p>
     * Read input data from an S3 bucket
     * </p>
     * </li>
     * <li>
     * <p>
     * Write model artifacts to an S3 bucket
     * </p>
     * </li>
     * <li>
     * <p>
     * Write logs to Amazon CloudWatch Logs
     * </p>
     * </li>
     * <li>
     * <p>
     * Publish metrics to Amazon CloudWatch
     * </p>
     * </li>
     * </ul>
     * <p>
     * You grant permissions for all of these tasks to an IAM role. To pass this role to Amazon SageMaker, the caller of
     * this API must have the <code>iam:PassRole</code> permission. For more information, see <a
     * href="https://docs.aws.amazon.com/sagemaker/latest/dg/sagemaker-roles.html">Amazon SageMaker Roles.</a>
     * </p>
     * 
     * @param roleArn
     *        The Amazon Resource Name (ARN) of an IAM role that enables Amazon SageMaker to perform tasks on your
     *        behalf. </p>
     *        <p>
     *        During model optimization, Amazon SageMaker needs your permission to:
     *        </p>
     *        <ul>
     *        <li>
     *        <p>
     *        Read input data from an S3 bucket
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        Write model artifacts to an S3 bucket
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        Write logs to Amazon CloudWatch Logs
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        Publish metrics to Amazon CloudWatch
     *        </p>
     *        </li>
     *        </ul>
     *        <p>
     *        You grant permissions for all of these tasks to an IAM role. To pass this role to Amazon SageMaker, the
     *        caller of this API must have the <code>iam:PassRole</code> permission. For more information, see <a
     *        href="https://docs.aws.amazon.com/sagemaker/latest/dg/sagemaker-roles.html">Amazon SageMaker Roles.</a>
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateOptimizationJobRequest withRoleArn(String roleArn) {
        setRoleArn(roleArn);
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

    public CreateOptimizationJobRequest withModelSource(OptimizationJobModelSource modelSource) {
        setModelSource(modelSource);
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

    public CreateOptimizationJobRequest withDeploymentInstanceType(String deploymentInstanceType) {
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

    public CreateOptimizationJobRequest withDeploymentInstanceType(OptimizationJobDeploymentInstanceType deploymentInstanceType) {
        this.deploymentInstanceType = deploymentInstanceType.toString();
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

    public CreateOptimizationJobRequest withOptimizationEnvironment(java.util.Map<String, String> optimizationEnvironment) {
        setOptimizationEnvironment(optimizationEnvironment);
        return this;
    }

    /**
     * Add a single OptimizationEnvironment entry
     *
     * @see CreateOptimizationJobRequest#withOptimizationEnvironment
     * @returns a reference to this object so that method calls can be chained together.
     */

    public CreateOptimizationJobRequest addOptimizationEnvironmentEntry(String key, String value) {
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

    public CreateOptimizationJobRequest clearOptimizationEnvironmentEntries() {
        this.optimizationEnvironment = null;
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

    public CreateOptimizationJobRequest withOptimizationConfigs(OptimizationConfig... optimizationConfigs) {
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

    public CreateOptimizationJobRequest withOptimizationConfigs(java.util.Collection<OptimizationConfig> optimizationConfigs) {
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

    public CreateOptimizationJobRequest withOutputConfig(OptimizationJobOutputConfig outputConfig) {
        setOutputConfig(outputConfig);
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

    public CreateOptimizationJobRequest withStoppingCondition(StoppingCondition stoppingCondition) {
        setStoppingCondition(stoppingCondition);
        return this;
    }

    /**
     * <p>
     * A list of key-value pairs associated with the optimization job. For more information, see <a
     * href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a>
     * in the <i>Amazon Web Services General Reference Guide</i>.
     * </p>
     * 
     * @return A list of key-value pairs associated with the optimization job. For more information, see <a
     *         href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services
     *         resources</a> in the <i>Amazon Web Services General Reference Guide</i>.
     */

    public java.util.List<Tag> getTags() {
        return tags;
    }

    /**
     * <p>
     * A list of key-value pairs associated with the optimization job. For more information, see <a
     * href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a>
     * in the <i>Amazon Web Services General Reference Guide</i>.
     * </p>
     * 
     * @param tags
     *        A list of key-value pairs associated with the optimization job. For more information, see <a
     *        href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services
     *        resources</a> in the <i>Amazon Web Services General Reference Guide</i>.
     */

    public void setTags(java.util.Collection<Tag> tags) {
        if (tags == null) {
            this.tags = null;
            return;
        }

        this.tags = new java.util.ArrayList<Tag>(tags);
    }

    /**
     * <p>
     * A list of key-value pairs associated with the optimization job. For more information, see <a
     * href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a>
     * in the <i>Amazon Web Services General Reference Guide</i>.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setTags(java.util.Collection)} or {@link #withTags(java.util.Collection)} if you want to override the
     * existing values.
     * </p>
     * 
     * @param tags
     *        A list of key-value pairs associated with the optimization job. For more information, see <a
     *        href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services
     *        resources</a> in the <i>Amazon Web Services General Reference Guide</i>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateOptimizationJobRequest withTags(Tag... tags) {
        if (this.tags == null) {
            setTags(new java.util.ArrayList<Tag>(tags.length));
        }
        for (Tag ele : tags) {
            this.tags.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * A list of key-value pairs associated with the optimization job. For more information, see <a
     * href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a>
     * in the <i>Amazon Web Services General Reference Guide</i>.
     * </p>
     * 
     * @param tags
     *        A list of key-value pairs associated with the optimization job. For more information, see <a
     *        href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services
     *        resources</a> in the <i>Amazon Web Services General Reference Guide</i>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CreateOptimizationJobRequest withTags(java.util.Collection<Tag> tags) {
        setTags(tags);
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

    public CreateOptimizationJobRequest withVpcConfig(OptimizationVpcConfig vpcConfig) {
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
        if (getOptimizationJobName() != null)
            sb.append("OptimizationJobName: ").append(getOptimizationJobName()).append(",");
        if (getRoleArn() != null)
            sb.append("RoleArn: ").append(getRoleArn()).append(",");
        if (getModelSource() != null)
            sb.append("ModelSource: ").append(getModelSource()).append(",");
        if (getDeploymentInstanceType() != null)
            sb.append("DeploymentInstanceType: ").append(getDeploymentInstanceType()).append(",");
        if (getOptimizationEnvironment() != null)
            sb.append("OptimizationEnvironment: ").append(getOptimizationEnvironment()).append(",");
        if (getOptimizationConfigs() != null)
            sb.append("OptimizationConfigs: ").append(getOptimizationConfigs()).append(",");
        if (getOutputConfig() != null)
            sb.append("OutputConfig: ").append(getOutputConfig()).append(",");
        if (getStoppingCondition() != null)
            sb.append("StoppingCondition: ").append(getStoppingCondition()).append(",");
        if (getTags() != null)
            sb.append("Tags: ").append(getTags()).append(",");
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

        if (obj instanceof CreateOptimizationJobRequest == false)
            return false;
        CreateOptimizationJobRequest other = (CreateOptimizationJobRequest) obj;
        if (other.getOptimizationJobName() == null ^ this.getOptimizationJobName() == null)
            return false;
        if (other.getOptimizationJobName() != null && other.getOptimizationJobName().equals(this.getOptimizationJobName()) == false)
            return false;
        if (other.getRoleArn() == null ^ this.getRoleArn() == null)
            return false;
        if (other.getRoleArn() != null && other.getRoleArn().equals(this.getRoleArn()) == false)
            return false;
        if (other.getModelSource() == null ^ this.getModelSource() == null)
            return false;
        if (other.getModelSource() != null && other.getModelSource().equals(this.getModelSource()) == false)
            return false;
        if (other.getDeploymentInstanceType() == null ^ this.getDeploymentInstanceType() == null)
            return false;
        if (other.getDeploymentInstanceType() != null && other.getDeploymentInstanceType().equals(this.getDeploymentInstanceType()) == false)
            return false;
        if (other.getOptimizationEnvironment() == null ^ this.getOptimizationEnvironment() == null)
            return false;
        if (other.getOptimizationEnvironment() != null && other.getOptimizationEnvironment().equals(this.getOptimizationEnvironment()) == false)
            return false;
        if (other.getOptimizationConfigs() == null ^ this.getOptimizationConfigs() == null)
            return false;
        if (other.getOptimizationConfigs() != null && other.getOptimizationConfigs().equals(this.getOptimizationConfigs()) == false)
            return false;
        if (other.getOutputConfig() == null ^ this.getOutputConfig() == null)
            return false;
        if (other.getOutputConfig() != null && other.getOutputConfig().equals(this.getOutputConfig()) == false)
            return false;
        if (other.getStoppingCondition() == null ^ this.getStoppingCondition() == null)
            return false;
        if (other.getStoppingCondition() != null && other.getStoppingCondition().equals(this.getStoppingCondition()) == false)
            return false;
        if (other.getTags() == null ^ this.getTags() == null)
            return false;
        if (other.getTags() != null && other.getTags().equals(this.getTags()) == false)
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

        hashCode = prime * hashCode + ((getOptimizationJobName() == null) ? 0 : getOptimizationJobName().hashCode());
        hashCode = prime * hashCode + ((getRoleArn() == null) ? 0 : getRoleArn().hashCode());
        hashCode = prime * hashCode + ((getModelSource() == null) ? 0 : getModelSource().hashCode());
        hashCode = prime * hashCode + ((getDeploymentInstanceType() == null) ? 0 : getDeploymentInstanceType().hashCode());
        hashCode = prime * hashCode + ((getOptimizationEnvironment() == null) ? 0 : getOptimizationEnvironment().hashCode());
        hashCode = prime * hashCode + ((getOptimizationConfigs() == null) ? 0 : getOptimizationConfigs().hashCode());
        hashCode = prime * hashCode + ((getOutputConfig() == null) ? 0 : getOutputConfig().hashCode());
        hashCode = prime * hashCode + ((getStoppingCondition() == null) ? 0 : getStoppingCondition().hashCode());
        hashCode = prime * hashCode + ((getTags() == null) ? 0 : getTags().hashCode());
        hashCode = prime * hashCode + ((getVpcConfig() == null) ? 0 : getVpcConfig().hashCode());
        return hashCode;
    }

    @Override
    public CreateOptimizationJobRequest clone() {
        return (CreateOptimizationJobRequest) super.clone();
    }

}
