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

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/GetChallengePassword"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class GetChallengePasswordResult extends com.amazonaws.AmazonWebServiceResult<com.amazonaws.ResponseMetadata> implements Serializable, Cloneable {

    /**
     * <p>
     * The SCEP challenge password.
     * </p>
     */
    private String password;

    /**
     * <p>
     * The SCEP challenge password.
     * </p>
     * 
     * @param password
     *        The SCEP challenge password.
     */

    public void setPassword(String password) {
        this.password = password;
    }

    /**
     * <p>
     * The SCEP challenge password.
     * </p>
     * 
     * @return The SCEP challenge password.
     */

    public String getPassword() {
        return this.password;
    }

    /**
     * <p>
     * The SCEP challenge password.
     * </p>
     * 
     * @param password
     *        The SCEP challenge password.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public GetChallengePasswordResult withPassword(String password) {
        setPassword(password);
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
        if (getPassword() != null)
            sb.append("Password: ").append("***Sensitive Data Redacted***");
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof GetChallengePasswordResult == false)
            return false;
        GetChallengePasswordResult other = (GetChallengePasswordResult) obj;
        if (other.getPassword() == null ^ this.getPassword() == null)
            return false;
        if (other.getPassword() != null && other.getPassword().equals(this.getPassword()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getPassword() == null) ? 0 : getPassword().hashCode());
        return hashCode;
    }

    @Override
    public GetChallengePasswordResult clone() {
        try {
            return (GetChallengePasswordResult) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

}
