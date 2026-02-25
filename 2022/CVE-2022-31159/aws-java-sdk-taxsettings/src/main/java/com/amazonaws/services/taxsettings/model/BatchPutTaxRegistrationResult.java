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

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/BatchPutTaxRegistration"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class BatchPutTaxRegistrationResult extends com.amazonaws.AmazonWebServiceResult<com.amazonaws.ResponseMetadata> implements Serializable, Cloneable {

    /**
     * <p>
     * List of errors for the accounts the TRN information could not be added or updated to.
     * </p>
     */
    private java.util.List<BatchPutTaxRegistrationError> errors;
    /**
     * <p>
     * The status of your TRN stored in the system after processing. Based on the validation occurring on the TRN, the
     * status can be <code>Verified</code>, <code>Pending</code> or <code>Rejected</code>.
     * </p>
     */
    private String status;

    /**
     * <p>
     * List of errors for the accounts the TRN information could not be added or updated to.
     * </p>
     * 
     * @return List of errors for the accounts the TRN information could not be added or updated to.
     */

    public java.util.List<BatchPutTaxRegistrationError> getErrors() {
        return errors;
    }

    /**
     * <p>
     * List of errors for the accounts the TRN information could not be added or updated to.
     * </p>
     * 
     * @param errors
     *        List of errors for the accounts the TRN information could not be added or updated to.
     */

    public void setErrors(java.util.Collection<BatchPutTaxRegistrationError> errors) {
        if (errors == null) {
            this.errors = null;
            return;
        }

        this.errors = new java.util.ArrayList<BatchPutTaxRegistrationError>(errors);
    }

    /**
     * <p>
     * List of errors for the accounts the TRN information could not be added or updated to.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setErrors(java.util.Collection)} or {@link #withErrors(java.util.Collection)} if you want to override the
     * existing values.
     * </p>
     * 
     * @param errors
     *        List of errors for the accounts the TRN information could not be added or updated to.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public BatchPutTaxRegistrationResult withErrors(BatchPutTaxRegistrationError... errors) {
        if (this.errors == null) {
            setErrors(new java.util.ArrayList<BatchPutTaxRegistrationError>(errors.length));
        }
        for (BatchPutTaxRegistrationError ele : errors) {
            this.errors.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * List of errors for the accounts the TRN information could not be added or updated to.
     * </p>
     * 
     * @param errors
     *        List of errors for the accounts the TRN information could not be added or updated to.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public BatchPutTaxRegistrationResult withErrors(java.util.Collection<BatchPutTaxRegistrationError> errors) {
        setErrors(errors);
        return this;
    }

    /**
     * <p>
     * The status of your TRN stored in the system after processing. Based on the validation occurring on the TRN, the
     * status can be <code>Verified</code>, <code>Pending</code> or <code>Rejected</code>.
     * </p>
     * 
     * @param status
     *        The status of your TRN stored in the system after processing. Based on the validation occurring on the
     *        TRN, the status can be <code>Verified</code>, <code>Pending</code> or <code>Rejected</code>.
     * @see TaxRegistrationStatus
     */

    public void setStatus(String status) {
        this.status = status;
    }

    /**
     * <p>
     * The status of your TRN stored in the system after processing. Based on the validation occurring on the TRN, the
     * status can be <code>Verified</code>, <code>Pending</code> or <code>Rejected</code>.
     * </p>
     * 
     * @return The status of your TRN stored in the system after processing. Based on the validation occurring on the
     *         TRN, the status can be <code>Verified</code>, <code>Pending</code> or <code>Rejected</code>.
     * @see TaxRegistrationStatus
     */

    public String getStatus() {
        return this.status;
    }

    /**
     * <p>
     * The status of your TRN stored in the system after processing. Based on the validation occurring on the TRN, the
     * status can be <code>Verified</code>, <code>Pending</code> or <code>Rejected</code>.
     * </p>
     * 
     * @param status
     *        The status of your TRN stored in the system after processing. Based on the validation occurring on the
     *        TRN, the status can be <code>Verified</code>, <code>Pending</code> or <code>Rejected</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TaxRegistrationStatus
     */

    public BatchPutTaxRegistrationResult withStatus(String status) {
        setStatus(status);
        return this;
    }

    /**
     * <p>
     * The status of your TRN stored in the system after processing. Based on the validation occurring on the TRN, the
     * status can be <code>Verified</code>, <code>Pending</code> or <code>Rejected</code>.
     * </p>
     * 
     * @param status
     *        The status of your TRN stored in the system after processing. Based on the validation occurring on the
     *        TRN, the status can be <code>Verified</code>, <code>Pending</code> or <code>Rejected</code>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see TaxRegistrationStatus
     */

    public BatchPutTaxRegistrationResult withStatus(TaxRegistrationStatus status) {
        this.status = status.toString();
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
        if (getErrors() != null)
            sb.append("Errors: ").append(getErrors()).append(",");
        if (getStatus() != null)
            sb.append("Status: ").append(getStatus());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof BatchPutTaxRegistrationResult == false)
            return false;
        BatchPutTaxRegistrationResult other = (BatchPutTaxRegistrationResult) obj;
        if (other.getErrors() == null ^ this.getErrors() == null)
            return false;
        if (other.getErrors() != null && other.getErrors().equals(this.getErrors()) == false)
            return false;
        if (other.getStatus() == null ^ this.getStatus() == null)
            return false;
        if (other.getStatus() != null && other.getStatus().equals(this.getStatus()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getErrors() == null) ? 0 : getErrors().hashCode());
        hashCode = prime * hashCode + ((getStatus() == null) ? 0 : getStatus().hashCode());
        return hashCode;
    }

    @Override
    public BatchPutTaxRegistrationResult clone() {
        try {
            return (BatchPutTaxRegistrationResult) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

}
