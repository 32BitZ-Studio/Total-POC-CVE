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
package com.amazonaws.services.stepfunctions.model;

import java.io.Serializable;
import javax.annotation.Generated;

import com.amazonaws.AmazonWebServiceRequest;

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/states-2016-11-23/DescribeStateMachineForExecution"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class DescribeStateMachineForExecutionRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the execution you want state machine information for.
     * </p>
     */
    private String executionArn;
    /**
     * <p>
     * If your state machine definition is encrypted with a KMS key, callers must have <code>kms:Decrypt</code>
     * permission to decrypt the definition. Alternatively, you can call the API with
     * <code>includedData = METADATA_ONLY</code> to get a successful response without the encrypted definition.
     * </p>
     */
    private String includedData;

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the execution you want state machine information for.
     * </p>
     * 
     * @param executionArn
     *        The Amazon Resource Name (ARN) of the execution you want state machine information for.
     */

    public void setExecutionArn(String executionArn) {
        this.executionArn = executionArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the execution you want state machine information for.
     * </p>
     * 
     * @return The Amazon Resource Name (ARN) of the execution you want state machine information for.
     */

    public String getExecutionArn() {
        return this.executionArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the execution you want state machine information for.
     * </p>
     * 
     * @param executionArn
     *        The Amazon Resource Name (ARN) of the execution you want state machine information for.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeStateMachineForExecutionRequest withExecutionArn(String executionArn) {
        setExecutionArn(executionArn);
        return this;
    }

    /**
     * <p>
     * If your state machine definition is encrypted with a KMS key, callers must have <code>kms:Decrypt</code>
     * permission to decrypt the definition. Alternatively, you can call the API with
     * <code>includedData = METADATA_ONLY</code> to get a successful response without the encrypted definition.
     * </p>
     * 
     * @param includedData
     *        If your state machine definition is encrypted with a KMS key, callers must have <code>kms:Decrypt</code>
     *        permission to decrypt the definition. Alternatively, you can call the API with
     *        <code>includedData = METADATA_ONLY</code> to get a successful response without the encrypted definition.
     * @see IncludedData
     */

    public void setIncludedData(String includedData) {
        this.includedData = includedData;
    }

    /**
     * <p>
     * If your state machine definition is encrypted with a KMS key, callers must have <code>kms:Decrypt</code>
     * permission to decrypt the definition. Alternatively, you can call the API with
     * <code>includedData = METADATA_ONLY</code> to get a successful response without the encrypted definition.
     * </p>
     * 
     * @return If your state machine definition is encrypted with a KMS key, callers must have <code>kms:Decrypt</code>
     *         permission to decrypt the definition. Alternatively, you can call the API with
     *         <code>includedData = METADATA_ONLY</code> to get a successful response without the encrypted definition.
     * @see IncludedData
     */

    public String getIncludedData() {
        return this.includedData;
    }

    /**
     * <p>
     * If your state machine definition is encrypted with a KMS key, callers must have <code>kms:Decrypt</code>
     * permission to decrypt the definition. Alternatively, you can call the API with
     * <code>includedData = METADATA_ONLY</code> to get a successful response without the encrypted definition.
     * </p>
     * 
     * @param includedData
     *        If your state machine definition is encrypted with a KMS key, callers must have <code>kms:Decrypt</code>
     *        permission to decrypt the definition. Alternatively, you can call the API with
     *        <code>includedData = METADATA_ONLY</code> to get a successful response without the encrypted definition.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see IncludedData
     */

    public DescribeStateMachineForExecutionRequest withIncludedData(String includedData) {
        setIncludedData(includedData);
        return this;
    }

    /**
     * <p>
     * If your state machine definition is encrypted with a KMS key, callers must have <code>kms:Decrypt</code>
     * permission to decrypt the definition. Alternatively, you can call the API with
     * <code>includedData = METADATA_ONLY</code> to get a successful response without the encrypted definition.
     * </p>
     * 
     * @param includedData
     *        If your state machine definition is encrypted with a KMS key, callers must have <code>kms:Decrypt</code>
     *        permission to decrypt the definition. Alternatively, you can call the API with
     *        <code>includedData = METADATA_ONLY</code> to get a successful response without the encrypted definition.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see IncludedData
     */

    public DescribeStateMachineForExecutionRequest withIncludedData(IncludedData includedData) {
        this.includedData = includedData.toString();
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
        if (getExecutionArn() != null)
            sb.append("ExecutionArn: ").append(getExecutionArn()).append(",");
        if (getIncludedData() != null)
            sb.append("IncludedData: ").append(getIncludedData());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof DescribeStateMachineForExecutionRequest == false)
            return false;
        DescribeStateMachineForExecutionRequest other = (DescribeStateMachineForExecutionRequest) obj;
        if (other.getExecutionArn() == null ^ this.getExecutionArn() == null)
            return false;
        if (other.getExecutionArn() != null && other.getExecutionArn().equals(this.getExecutionArn()) == false)
            return false;
        if (other.getIncludedData() == null ^ this.getIncludedData() == null)
            return false;
        if (other.getIncludedData() != null && other.getIncludedData().equals(this.getIncludedData()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getExecutionArn() == null) ? 0 : getExecutionArn().hashCode());
        hashCode = prime * hashCode + ((getIncludedData() == null) ? 0 : getIncludedData().hashCode());
        return hashCode;
    }

    @Override
    public DescribeStateMachineForExecutionRequest clone() {
        return (DescribeStateMachineForExecutionRequest) super.clone();
    }

}
