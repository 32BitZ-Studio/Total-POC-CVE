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
package com.amazonaws.services.taxsettings.model;

import java.io.Serializable;
import javax.annotation.Generated;

import com.amazonaws.AmazonWebServiceRequest;

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/DeleteTaxRegistration" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class DeleteTaxRegistrationRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * Unique account identifier for the TRN information that needs to be deleted. If this isn't passed, the account ID
     * corresponding to the credentials of the API caller will be used for this parameter.
     * </p>
     */
    private String accountId;

    /**
     * <p>
     * Unique account identifier for the TRN information that needs to be deleted. If this isn't passed, the account ID
     * corresponding to the credentials of the API caller will be used for this parameter.
     * </p>
     * 
     * @param accountId
     *        Unique account identifier for the TRN information that needs to be deleted. If this isn't passed, the
     *        account ID corresponding to the credentials of the API caller will be used for this parameter.
     */

    public void setAccountId(String accountId) {
        this.accountId = accountId;
    }

    /**
     * <p>
     * Unique account identifier for the TRN information that needs to be deleted. If this isn't passed, the account ID
     * corresponding to the credentials of the API caller will be used for this parameter.
     * </p>
     * 
     * @return Unique account identifier for the TRN information that needs to be deleted. If this isn't passed, the
     *         account ID corresponding to the credentials of the API caller will be used for this parameter.
     */

    public String getAccountId() {
        return this.accountId;
    }

    /**
     * <p>
     * Unique account identifier for the TRN information that needs to be deleted. If this isn't passed, the account ID
     * corresponding to the credentials of the API caller will be used for this parameter.
     * </p>
     * 
     * @param accountId
     *        Unique account identifier for the TRN information that needs to be deleted. If this isn't passed, the
     *        account ID corresponding to the credentials of the API caller will be used for this parameter.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DeleteTaxRegistrationRequest withAccountId(String accountId) {
        setAccountId(accountId);
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
        if (getAccountId() != null)
            sb.append("AccountId: ").append(getAccountId());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof DeleteTaxRegistrationRequest == false)
            return false;
        DeleteTaxRegistrationRequest other = (DeleteTaxRegistrationRequest) obj;
        if (other.getAccountId() == null ^ this.getAccountId() == null)
            return false;
        if (other.getAccountId() != null && other.getAccountId().equals(this.getAccountId()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getAccountId() == null) ? 0 : getAccountId().hashCode());
        return hashCode;
    }

    @Override
    public DeleteTaxRegistrationRequest clone() {
        return (DeleteTaxRegistrationRequest) super.clone();
    }

}
