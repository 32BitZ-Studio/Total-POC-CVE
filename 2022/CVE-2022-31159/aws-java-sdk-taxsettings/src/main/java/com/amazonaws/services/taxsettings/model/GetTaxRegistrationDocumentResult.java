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
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/GetTaxRegistrationDocument"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class GetTaxRegistrationDocumentResult extends com.amazonaws.AmazonWebServiceResult<com.amazonaws.ResponseMetadata> implements Serializable, Cloneable {

    /**
     * <p>
     * The file path of the Amazon S3 bucket where you want to download your tax document to.
     * </p>
     */
    private String destinationFilePath;

    /**
     * <p>
     * The file path of the Amazon S3 bucket where you want to download your tax document to.
     * </p>
     * 
     * @param destinationFilePath
     *        The file path of the Amazon S3 bucket where you want to download your tax document to.
     */

    public void setDestinationFilePath(String destinationFilePath) {
        this.destinationFilePath = destinationFilePath;
    }

    /**
     * <p>
     * The file path of the Amazon S3 bucket where you want to download your tax document to.
     * </p>
     * 
     * @return The file path of the Amazon S3 bucket where you want to download your tax document to.
     */

    public String getDestinationFilePath() {
        return this.destinationFilePath;
    }

    /**
     * <p>
     * The file path of the Amazon S3 bucket where you want to download your tax document to.
     * </p>
     * 
     * @param destinationFilePath
     *        The file path of the Amazon S3 bucket where you want to download your tax document to.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public GetTaxRegistrationDocumentResult withDestinationFilePath(String destinationFilePath) {
        setDestinationFilePath(destinationFilePath);
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
        if (getDestinationFilePath() != null)
            sb.append("DestinationFilePath: ").append(getDestinationFilePath());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof GetTaxRegistrationDocumentResult == false)
            return false;
        GetTaxRegistrationDocumentResult other = (GetTaxRegistrationDocumentResult) obj;
        if (other.getDestinationFilePath() == null ^ this.getDestinationFilePath() == null)
            return false;
        if (other.getDestinationFilePath() != null && other.getDestinationFilePath().equals(this.getDestinationFilePath()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getDestinationFilePath() == null) ? 0 : getDestinationFilePath().hashCode());
        return hashCode;
    }

    @Override
    public GetTaxRegistrationDocumentResult clone() {
        try {
            return (GetTaxRegistrationDocumentResult) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

}
