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
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * The location of the Amazon S3 bucket that you specify to download your tax documents to.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/DestinationS3Location" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class DestinationS3Location implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The name of your Amazon S3 bucket that you specify to download your tax documents to.
     * </p>
     */
    private String bucket;
    /**
     * <p>
     * The Amazon S3 object prefix that you specify for your tax document file.
     * </p>
     */
    private String prefix;

    /**
     * <p>
     * The name of your Amazon S3 bucket that you specify to download your tax documents to.
     * </p>
     * 
     * @param bucket
     *        The name of your Amazon S3 bucket that you specify to download your tax documents to.
     */

    public void setBucket(String bucket) {
        this.bucket = bucket;
    }

    /**
     * <p>
     * The name of your Amazon S3 bucket that you specify to download your tax documents to.
     * </p>
     * 
     * @return The name of your Amazon S3 bucket that you specify to download your tax documents to.
     */

    public String getBucket() {
        return this.bucket;
    }

    /**
     * <p>
     * The name of your Amazon S3 bucket that you specify to download your tax documents to.
     * </p>
     * 
     * @param bucket
     *        The name of your Amazon S3 bucket that you specify to download your tax documents to.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DestinationS3Location withBucket(String bucket) {
        setBucket(bucket);
        return this;
    }

    /**
     * <p>
     * The Amazon S3 object prefix that you specify for your tax document file.
     * </p>
     * 
     * @param prefix
     *        The Amazon S3 object prefix that you specify for your tax document file.
     */

    public void setPrefix(String prefix) {
        this.prefix = prefix;
    }

    /**
     * <p>
     * The Amazon S3 object prefix that you specify for your tax document file.
     * </p>
     * 
     * @return The Amazon S3 object prefix that you specify for your tax document file.
     */

    public String getPrefix() {
        return this.prefix;
    }

    /**
     * <p>
     * The Amazon S3 object prefix that you specify for your tax document file.
     * </p>
     * 
     * @param prefix
     *        The Amazon S3 object prefix that you specify for your tax document file.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public DestinationS3Location withPrefix(String prefix) {
        setPrefix(prefix);
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
        if (getBucket() != null)
            sb.append("Bucket: ").append(getBucket()).append(",");
        if (getPrefix() != null)
            sb.append("Prefix: ").append(getPrefix());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof DestinationS3Location == false)
            return false;
        DestinationS3Location other = (DestinationS3Location) obj;
        if (other.getBucket() == null ^ this.getBucket() == null)
            return false;
        if (other.getBucket() != null && other.getBucket().equals(this.getBucket()) == false)
            return false;
        if (other.getPrefix() == null ^ this.getPrefix() == null)
            return false;
        if (other.getPrefix() != null && other.getPrefix().equals(this.getPrefix()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getBucket() == null) ? 0 : getBucket().hashCode());
        hashCode = prime * hashCode + ((getPrefix() == null) ? 0 : getPrefix().hashCode());
        return hashCode;
    }

    @Override
    public DestinationS3Location clone() {
        try {
            return (DestinationS3Location) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.taxsettings.model.transform.DestinationS3LocationMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
