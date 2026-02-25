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
 * Additional tax information associated with your TRN in South Korea.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/SouthKoreaAdditionalInfo"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class SouthKoreaAdditionalInfo implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The business legal name based on the most recently uploaded tax registration certificate.
     * </p>
     */
    private String businessRepresentativeName;
    /**
     * <p>
     * Item of business based on the most recently uploaded tax registration certificate.
     * </p>
     */
    private String itemOfBusiness;
    /**
     * <p>
     * Line of business based on the most recently uploaded tax registration certificate.
     * </p>
     */
    private String lineOfBusiness;

    /**
     * <p>
     * The business legal name based on the most recently uploaded tax registration certificate.
     * </p>
     * 
     * @param businessRepresentativeName
     *        The business legal name based on the most recently uploaded tax registration certificate.
     */

    public void setBusinessRepresentativeName(String businessRepresentativeName) {
        this.businessRepresentativeName = businessRepresentativeName;
    }

    /**
     * <p>
     * The business legal name based on the most recently uploaded tax registration certificate.
     * </p>
     * 
     * @return The business legal name based on the most recently uploaded tax registration certificate.
     */

    public String getBusinessRepresentativeName() {
        return this.businessRepresentativeName;
    }

    /**
     * <p>
     * The business legal name based on the most recently uploaded tax registration certificate.
     * </p>
     * 
     * @param businessRepresentativeName
     *        The business legal name based on the most recently uploaded tax registration certificate.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public SouthKoreaAdditionalInfo withBusinessRepresentativeName(String businessRepresentativeName) {
        setBusinessRepresentativeName(businessRepresentativeName);
        return this;
    }

    /**
     * <p>
     * Item of business based on the most recently uploaded tax registration certificate.
     * </p>
     * 
     * @param itemOfBusiness
     *        Item of business based on the most recently uploaded tax registration certificate.
     */

    public void setItemOfBusiness(String itemOfBusiness) {
        this.itemOfBusiness = itemOfBusiness;
    }

    /**
     * <p>
     * Item of business based on the most recently uploaded tax registration certificate.
     * </p>
     * 
     * @return Item of business based on the most recently uploaded tax registration certificate.
     */

    public String getItemOfBusiness() {
        return this.itemOfBusiness;
    }

    /**
     * <p>
     * Item of business based on the most recently uploaded tax registration certificate.
     * </p>
     * 
     * @param itemOfBusiness
     *        Item of business based on the most recently uploaded tax registration certificate.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public SouthKoreaAdditionalInfo withItemOfBusiness(String itemOfBusiness) {
        setItemOfBusiness(itemOfBusiness);
        return this;
    }

    /**
     * <p>
     * Line of business based on the most recently uploaded tax registration certificate.
     * </p>
     * 
     * @param lineOfBusiness
     *        Line of business based on the most recently uploaded tax registration certificate.
     */

    public void setLineOfBusiness(String lineOfBusiness) {
        this.lineOfBusiness = lineOfBusiness;
    }

    /**
     * <p>
     * Line of business based on the most recently uploaded tax registration certificate.
     * </p>
     * 
     * @return Line of business based on the most recently uploaded tax registration certificate.
     */

    public String getLineOfBusiness() {
        return this.lineOfBusiness;
    }

    /**
     * <p>
     * Line of business based on the most recently uploaded tax registration certificate.
     * </p>
     * 
     * @param lineOfBusiness
     *        Line of business based on the most recently uploaded tax registration certificate.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public SouthKoreaAdditionalInfo withLineOfBusiness(String lineOfBusiness) {
        setLineOfBusiness(lineOfBusiness);
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
        if (getBusinessRepresentativeName() != null)
            sb.append("BusinessRepresentativeName: ").append(getBusinessRepresentativeName()).append(",");
        if (getItemOfBusiness() != null)
            sb.append("ItemOfBusiness: ").append(getItemOfBusiness()).append(",");
        if (getLineOfBusiness() != null)
            sb.append("LineOfBusiness: ").append(getLineOfBusiness());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof SouthKoreaAdditionalInfo == false)
            return false;
        SouthKoreaAdditionalInfo other = (SouthKoreaAdditionalInfo) obj;
        if (other.getBusinessRepresentativeName() == null ^ this.getBusinessRepresentativeName() == null)
            return false;
        if (other.getBusinessRepresentativeName() != null && other.getBusinessRepresentativeName().equals(this.getBusinessRepresentativeName()) == false)
            return false;
        if (other.getItemOfBusiness() == null ^ this.getItemOfBusiness() == null)
            return false;
        if (other.getItemOfBusiness() != null && other.getItemOfBusiness().equals(this.getItemOfBusiness()) == false)
            return false;
        if (other.getLineOfBusiness() == null ^ this.getLineOfBusiness() == null)
            return false;
        if (other.getLineOfBusiness() != null && other.getLineOfBusiness().equals(this.getLineOfBusiness()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getBusinessRepresentativeName() == null) ? 0 : getBusinessRepresentativeName().hashCode());
        hashCode = prime * hashCode + ((getItemOfBusiness() == null) ? 0 : getItemOfBusiness().hashCode());
        hashCode = prime * hashCode + ((getLineOfBusiness() == null) ? 0 : getLineOfBusiness().hashCode());
        return hashCode;
    }

    @Override
    public SouthKoreaAdditionalInfo clone() {
        try {
            return (SouthKoreaAdditionalInfo) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.taxsettings.model.transform.SouthKoreaAdditionalInfoMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
