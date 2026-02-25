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
package com.amazonaws.services.pcaconnectorscep.model;

import java.io.Serializable;
import javax.annotation.Generated;

import com.amazonaws.AmazonWebServiceRequest;

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/DeleteChallenge" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class DeleteChallengeRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the challenge password to delete.
     * </p>
     */
    private String challengeArn;

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the challenge password to delete.
     * </p>
     * 
     * @param challengeArn
     *        The Amazon Resource Name (ARN) of the challenge password to delete.
     */

    public void setChallengeArn(String challengeArn) {
        this.challengeArn = challengeArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the challenge password to delete.
     * </p>
     * 
     * @return The Amazon Resource Name (ARN) of the challenge password to delete.
     */

    public String getChallengeArn() {
        return this.challengeArn;
    }

    /**
     * <p>
     * The Amazon Resource Name (ARN) of the challenge password to delete.
     * </p>
     * 
     * @param challengeArn
     *        The Amazon Resource Name (ARN) of the challenge password to delete.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DeleteChallengeRequest withChallengeArn(String challengeArn) {
        setChallengeArn(challengeArn);
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
        if (getChallengeArn() != null)
            sb.append("ChallengeArn: ").append(getChallengeArn());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof DeleteChallengeRequest == false)
            return false;
        DeleteChallengeRequest other = (DeleteChallengeRequest) obj;
        if (other.getChallengeArn() == null ^ this.getChallengeArn() == null)
            return false;
        if (other.getChallengeArn() != null && other.getChallengeArn().equals(this.getChallengeArn()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getChallengeArn() == null) ? 0 : getChallengeArn().hashCode());
        return hashCode;
    }

    @Override
    public DeleteChallengeRequest clone() {
        return (DeleteChallengeRequest) super.clone();
    }

}
