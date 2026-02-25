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
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/GetTaxRegistrationDocument"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class GetTaxRegistrationDocumentRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The Amazon S3 bucket that you specify to download your tax documents to.
     * </p>
     */
    private DestinationS3Location destinationS3Location;
    /**
     * <p>
     * The metadata for your tax document.
     * </p>
     */
    private TaxDocumentMetadata taxDocumentMetadata;

    /**
     * <p>
     * The Amazon S3 bucket that you specify to download your tax documents to.
     * </p>
     * 
     * @param destinationS3Location
     *        The Amazon S3 bucket that you specify to download your tax documents to.
     */

    public void setDestinationS3Location(DestinationS3Location destinationS3Location) {
        this.destinationS3Location = destinationS3Location;
    }

    /**
     * <p>
     * The Amazon S3 bucket that you specify to download your tax documents to.
     * </p>
     * 
     * @return The Amazon S3 bucket that you specify to download your tax documents to.
     */

    public DestinationS3Location getDestinationS3Location() {
        return this.destinationS3Location;
    }

    /**
     * <p>
     * The Amazon S3 bucket that you specify to download your tax documents to.
     * </p>
     * 
     * @param destinationS3Location
     *        The Amazon S3 bucket that you specify to download your tax documents to.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public GetTaxRegistrationDocumentRequest withDestinationS3Location(DestinationS3Location destinationS3Location) {
        setDestinationS3Location(destinationS3Location);
        return this;
    }

    /**
     * <p>
     * The metadata for your tax document.
     * </p>
     * 
     * @param taxDocumentMetadata
     *        The metadata for your tax document.
     */

    public void setTaxDocumentMetadata(TaxDocumentMetadata taxDocumentMetadata) {
        this.taxDocumentMetadata = taxDocumentMetadata;
    }

    /**
     * <p>
     * The metadata for your tax document.
     * </p>
     * 
     * @return The metadata for your tax document.
     */

    public TaxDocumentMetadata getTaxDocumentMetadata() {
        return this.taxDocumentMetadata;
    }

    /**
     * <p>
     * The metadata for your tax document.
     * </p>
     * 
     * @param taxDocumentMetadata
     *        The metadata for your tax document.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public GetTaxRegistrationDocumentRequest withTaxDocumentMetadata(TaxDocumentMetadata taxDocumentMetadata) {
        setTaxDocumentMetadata(taxDocumentMetadata);
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
        if (getDestinationS3Location() != null)
            sb.append("DestinationS3Location: ").append(getDestinationS3Location()).append(",");
        if (getTaxDocumentMetadata() != null)
            sb.append("TaxDocumentMetadata: ").append(getTaxDocumentMetadata());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof GetTaxRegistrationDocumentRequest == false)
            return false;
        GetTaxRegistrationDocumentRequest other = (GetTaxRegistrationDocumentRequest) obj;
        if (other.getDestinationS3Location() == null ^ this.getDestinationS3Location() == null)
            return false;
        if (other.getDestinationS3Location() != null && other.getDestinationS3Location().equals(this.getDestinationS3Location()) == false)
            return false;
        if (other.getTaxDocumentMetadata() == null ^ this.getTaxDocumentMetadata() == null)
            return false;
        if (other.getTaxDocumentMetadata() != null && other.getTaxDocumentMetadata().equals(this.getTaxDocumentMetadata()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getDestinationS3Location() == null) ? 0 : getDestinationS3Location().hashCode());
        hashCode = prime * hashCode + ((getTaxDocumentMetadata() == null) ? 0 : getTaxDocumentMetadata().hashCode());
        return hashCode;
    }

    @Override
    public GetTaxRegistrationDocumentRequest clone() {
        return (GetTaxRegistrationDocumentRequest) super.clone();
    }

}
