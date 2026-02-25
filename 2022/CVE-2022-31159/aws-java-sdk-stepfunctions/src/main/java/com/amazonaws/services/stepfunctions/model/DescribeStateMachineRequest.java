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
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/states-2016-11-23/DescribeStateMachine" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class DescribeStateMachineRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the state machine for which you want the information.
     * </p>
     * <p>
     * If you specify a state machine version ARN, this API returns details about that version. The version ARN is a
     * combination of state machine ARN and the version number separated by a colon (:). For example,
     * <code>stateMachineARN:1</code>.
     * </p>
     */
    private String stateMachineArn;
    /**
     * <p>
     * If your state machine definition is encrypted with a KMS key, callers must have <code>kms:Decrypt</code>
     * permission to decrypt the definition. Alternatively, you can call the API with
     * <code>includedData = METADATA_ONLY</code> to get a successful response without the encrypted definition.
     * </p>
     * <note>
     * <p>
     * When calling a labelled ARN for an encrypted state machine, the <code>includedData = METADATA_ONLY</code>
     * parameter will not apply because Step Functions needs to decrypt the entire state machine definition to get the
     * Distributed Map state’s definition. In this case, the API caller needs to have <code>kms:Decrypt</code>
     * permission.
     * </p>
     * </note>
     */
    private String includedData;

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the state machine for which you want the information.
     * </p>
     * <p>
     * If you specify a state machine version ARN, this API returns details about that version. The version ARN is a
     * combination of state machine ARN and the version number separated by a colon (:). For example,
     * <code>stateMachineARN:1</code>.
     * </p>
     * 
     * @param stateMachineArn
     *        The Amazon Resource Name (ARN) of the state machine for which you want the information.</p>
     *        <p>
     *        If you specify a state machine version ARN, this API returns details about that version. The version ARN
     *        is a combination of state machine ARN and the version number separated by a colon (:). For example,
     *        <code>stateMachineARN:1</code>.
     */

    public void setStateMachineArn(String stateMachineArn) {
        this.stateMachineArn = stateMachineArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the state machine for which you want the information.
     * </p>
     * <p>
     * If you specify a state machine version ARN, this API returns details about that version. The version ARN is a
     * combination of state machine ARN and the version number separated by a colon (:). For example,
     * <code>stateMachineARN:1</code>.
     * </p>
     * 
     * @return The Amazon Resource Name (ARN) of the state machine for which you want the information.</p>
     *         <p>
     *         If you specify a state machine version ARN, this API returns details about that version. The version ARN
     *         is a combination of state machine ARN and the version number separated by a colon (:). For example,
     *         <code>stateMachineARN:1</code>.
     */

    public String getStateMachineArn() {
        return this.stateMachineArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the state machine for which you want the information.
     * </p>
     * <p>
     * If you specify a state machine version ARN, this API returns details about that version. The version ARN is a
     * combination of state machine ARN and the version number separated by a colon (:). For example,
     * <code>stateMachineARN:1</code>.
     * </p>
     * 
     * @param stateMachineArn
     *        The Amazon Resource Name (ARN) of the state machine for which you want the information.</p>
     *        <p>
     *        If you specify a state machine version ARN, this API returns details about that version. The version ARN
     *        is a combination of state machine ARN and the version number separated by a colon (:). For example,
     *        <code>stateMachineARN:1</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DescribeStateMachineRequest withStateMachineArn(String stateMachineArn) {
        setStateMachineArn(stateMachineArn);
        return this;
    }

    /**
     * <p>
     * If your state machine definition is encrypted with a KMS key, callers must have <code>kms:Decrypt</code>
     * permission to decrypt the definition. Alternatively, you can call the API with
     * <code>includedData = METADATA_ONLY</code> to get a successful response without the encrypted definition.
     * </p>
     * <note>
     * <p>
     * When calling a labelled ARN for an encrypted state machine, the <code>includedData = METADATA_ONLY</code>
     * parameter will not apply because Step Functions needs to decrypt the entire state machine definition to get the
     * Distributed Map state’s definition. In this case, the API caller needs to have <code>kms:Decrypt</code>
     * permission.
     * </p>
     * </note>
     * 
     * @param includedData
     *        If your state machine definition is encrypted with a KMS key, callers must have <code>kms:Decrypt</code>
     *        permission to decrypt the definition. Alternatively, you can call the API with
     *        <code>includedData = METADATA_ONLY</code> to get a successful response without the encrypted
     *        definition.</p> <note>
     *        <p>
     *        When calling a labelled ARN for an encrypted state machine, the <code>includedData = METADATA_ONLY</code>
     *        parameter will not apply because Step Functions needs to decrypt the entire state machine definition to
     *        get the Distributed Map state’s definition. In this case, the API caller needs to have
     *        <code>kms:Decrypt</code> permission.
     *        </p>
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
     * <note>
     * <p>
     * When calling a labelled ARN for an encrypted state machine, the <code>includedData = METADATA_ONLY</code>
     * parameter will not apply because Step Functions needs to decrypt the entire state machine definition to get the
     * Distributed Map state’s definition. In this case, the API caller needs to have <code>kms:Decrypt</code>
     * permission.
     * </p>
     * </note>
     * 
     * @return If your state machine definition is encrypted with a KMS key, callers must have <code>kms:Decrypt</code>
     *         permission to decrypt the definition. Alternatively, you can call the API with
     *         <code>includedData = METADATA_ONLY</code> to get a successful response without the encrypted
     *         definition.</p> <note>
     *         <p>
     *         When calling a labelled ARN for an encrypted state machine, the <code>includedData = METADATA_ONLY</code>
     *         parameter will not apply because Step Functions needs to decrypt the entire state machine definition to
     *         get the Distributed Map state’s definition. In this case, the API caller needs to have
     *         <code>kms:Decrypt</code> permission.
     *         </p>
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
     * <note>
     * <p>
     * When calling a labelled ARN for an encrypted state machine, the <code>includedData = METADATA_ONLY</code>
     * parameter will not apply because Step Functions needs to decrypt the entire state machine definition to get the
     * Distributed Map state’s definition. In this case, the API caller needs to have <code>kms:Decrypt</code>
     * permission.
     * </p>
     * </note>
     * 
     * @param includedData
     *        If your state machine definition is encrypted with a KMS key, callers must have <code>kms:Decrypt</code>
     *        permission to decrypt the definition. Alternatively, you can call the API with
     *        <code>includedData = METADATA_ONLY</code> to get a successful response without the encrypted
     *        definition.</p> <note>
     *        <p>
     *        When calling a labelled ARN for an encrypted state machine, the <code>includedData = METADATA_ONLY</code>
     *        parameter will not apply because Step Functions needs to decrypt the entire state machine definition to
     *        get the Distributed Map state’s definition. In this case, the API caller needs to have
     *        <code>kms:Decrypt</code> permission.
     *        </p>
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see IncludedData
     */

    public DescribeStateMachineRequest withIncludedData(String includedData) {
        setIncludedData(includedData);
        return this;
    }

    /**
     * <p>
     * If your state machine definition is encrypted with a KMS key, callers must have <code>kms:Decrypt</code>
     * permission to decrypt the definition. Alternatively, you can call the API with
     * <code>includedData = METADATA_ONLY</code> to get a successful response without the encrypted definition.
     * </p>
     * <note>
     * <p>
     * When calling a labelled ARN for an encrypted state machine, the <code>includedData = METADATA_ONLY</code>
     * parameter will not apply because Step Functions needs to decrypt the entire state machine definition to get the
     * Distributed Map state’s definition. In this case, the API caller needs to have <code>kms:Decrypt</code>
     * permission.
     * </p>
     * </note>
     * 
     * @param includedData
     *        If your state machine definition is encrypted with a KMS key, callers must have <code>kms:Decrypt</code>
     *        permission to decrypt the definition. Alternatively, you can call the API with
     *        <code>includedData = METADATA_ONLY</code> to get a successful response without the encrypted
     *        definition.</p> <note>
     *        <p>
     *        When calling a labelled ARN for an encrypted state machine, the <code>includedData = METADATA_ONLY</code>
     *        parameter will not apply because Step Functions needs to decrypt the entire state machine definition to
     *        get the Distributed Map state’s definition. In this case, the API caller needs to have
     *        <code>kms:Decrypt</code> permission.
     *        </p>
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see IncludedData
     */

    public DescribeStateMachineRequest withIncludedData(IncludedData includedData) {
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
        if (getStateMachineArn() != null)
            sb.append("StateMachineArn: ").append(getStateMachineArn()).append(",");
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

        if (obj instanceof DescribeStateMachineRequest == false)
            return false;
        DescribeStateMachineRequest other = (DescribeStateMachineRequest) obj;
        if (other.getStateMachineArn() == null ^ this.getStateMachineArn() == null)
            return false;
        if (other.getStateMachineArn() != null && other.getStateMachineArn().equals(this.getStateMachineArn()) == false)
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

        hashCode = prime * hashCode + ((getStateMachineArn() == null) ? 0 : getStateMachineArn().hashCode());
        hashCode = prime * hashCode + ((getIncludedData() == null) ? 0 : getIncludedData().hashCode());
        return hashCode;
    }

    @Override
    public DescribeStateMachineRequest clone() {
        return (DescribeStateMachineRequest) super.clone();
    }

}
