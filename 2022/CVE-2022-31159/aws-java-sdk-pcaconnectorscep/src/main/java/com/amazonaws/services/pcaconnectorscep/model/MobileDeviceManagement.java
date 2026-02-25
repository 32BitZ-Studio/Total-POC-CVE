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
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * If you don't supply a value, by default Connector for SCEP creates a connector for general-purpose use. A
 * general-purpose connector is designed to work with clients or endpoints that support the SCEP protocol, except
 * Connector for SCEP for Microsoft Intune. For information about considerations and limitations with using Connector
 * for SCEP, see <a href=
 * "https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlc4scep-considerations-limitations.html"
 * >Considerations and Limitations</a>.
 * </p>
 * <p>
 * If you provide an <code>IntuneConfiguration</code>, Connector for SCEP creates a connector for use with Microsoft
 * Intune, and you manage the challenge passwords using Microsoft Intune. For more information, see <a
 * href="https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlconnector-for-scep-intune.html">Using
 * Connector for SCEP for Microsoft Intune</a>.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/pca-connector-scep-2018-05-10/MobileDeviceManagement"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class MobileDeviceManagement implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * Configuration settings for use with Microsoft Intune. For information about using Connector for SCEP for
     * Microsoft Intune, see <a
     * href="https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlconnector-for-scep-intune.html"
     * >Using Connector for SCEP for Microsoft Intune</a>.
     * </p>
     */
    private IntuneConfiguration intune;

    /**
     * <p>
     * Configuration settings for use with Microsoft Intune. For information about using Connector for SCEP for
     * Microsoft Intune, see <a
     * href="https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlconnector-for-scep-intune.html"
     * >Using Connector for SCEP for Microsoft Intune</a>.
     * </p>
     * 
     * @param intune
     *        Configuration settings for use with Microsoft Intune. For information about using Connector for SCEP for
     *        Microsoft Intune, see <a href=
     *        "https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlconnector-for-scep-intune.html"
     *        >Using Connector for SCEP for Microsoft Intune</a>.
     */

    public void setIntune(IntuneConfiguration intune) {
        this.intune = intune;
    }

    /**
     * <p>
     * Configuration settings for use with Microsoft Intune. For information about using Connector for SCEP for
     * Microsoft Intune, see <a
     * href="https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlconnector-for-scep-intune.html"
     * >Using Connector for SCEP for Microsoft Intune</a>.
     * </p>
     * 
     * @return Configuration settings for use with Microsoft Intune. For information about using Connector for SCEP for
     *         Microsoft Intune, see <a href=
     *         "https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlconnector-for-scep-intune.html"
     *         >Using Connector for SCEP for Microsoft Intune</a>.
     */

    public IntuneConfiguration getIntune() {
        return this.intune;
    }

    /**
     * <p>
     * Configuration settings for use with Microsoft Intune. For information about using Connector for SCEP for
     * Microsoft Intune, see <a
     * href="https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlconnector-for-scep-intune.html"
     * >Using Connector for SCEP for Microsoft Intune</a>.
     * </p>
     * 
     * @param intune
     *        Configuration settings for use with Microsoft Intune. For information about using Connector for SCEP for
     *        Microsoft Intune, see <a href=
     *        "https://docs.aws.amazon.com/privateca/latest/userguide/scep-connector.htmlconnector-for-scep-intune.html"
     *        >Using Connector for SCEP for Microsoft Intune</a>.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public MobileDeviceManagement withIntune(IntuneConfiguration intune) {
        setIntune(intune);
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
        if (getIntune() != null)
            sb.append("Intune: ").append(getIntune());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof MobileDeviceManagement == false)
            return false;
        MobileDeviceManagement other = (MobileDeviceManagement) obj;
        if (other.getIntune() == null ^ this.getIntune() == null)
            return false;
        if (other.getIntune() != null && other.getIntune().equals(this.getIntune()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getIntune() == null) ? 0 : getIntune().hashCode());
        return hashCode;
    }

    @Override
    public MobileDeviceManagement clone() {
        try {
            return (MobileDeviceManagement) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.pcaconnectorscep.model.transform.MobileDeviceManagementMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
