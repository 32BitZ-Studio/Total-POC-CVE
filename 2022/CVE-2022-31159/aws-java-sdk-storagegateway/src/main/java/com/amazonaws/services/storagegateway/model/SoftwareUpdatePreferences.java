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
package com.amazonaws.services.storagegateway.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * A set of variables indicating the software update preferences for the gateway.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/storagegateway-2013-06-30/SoftwareUpdatePreferences"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class SoftwareUpdatePreferences implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * Indicates the automatic update policy for a gateway.
     * </p>
     * <p>
     * <code>ALL_VERSIONS</code> - Enables regular gateway maintenance updates.
     * </p>
     * <p>
     * <code>EMERGENCY_VERSIONS_ONLY</code> - Disables regular gateway maintenance updates.
     * </p>
     */
    private String automaticUpdatePolicy;

    /**
     * <p>
     * Indicates the automatic update policy for a gateway.
     * </p>
     * <p>
     * <code>ALL_VERSIONS</code> - Enables regular gateway maintenance updates.
     * </p>
     * <p>
     * <code>EMERGENCY_VERSIONS_ONLY</code> - Disables regular gateway maintenance updates.
     * </p>
     * 
     * @param automaticUpdatePolicy
     *        Indicates the automatic update policy for a gateway.</p>
     *        <p>
     *        <code>ALL_VERSIONS</code> - Enables regular gateway maintenance updates.
     *        </p>
     *        <p>
     *        <code>EMERGENCY_VERSIONS_ONLY</code> - Disables regular gateway maintenance updates.
     * @see AutomaticUpdatePolicy
     */

    public void setAutomaticUpdatePolicy(String automaticUpdatePolicy) {
        this.automaticUpdatePolicy = automaticUpdatePolicy;
    }

    /**
     * <p>
     * Indicates the automatic update policy for a gateway.
     * </p>
     * <p>
     * <code>ALL_VERSIONS</code> - Enables regular gateway maintenance updates.
     * </p>
     * <p>
     * <code>EMERGENCY_VERSIONS_ONLY</code> - Disables regular gateway maintenance updates.
     * </p>
     * 
     * @return Indicates the automatic update policy for a gateway.</p>
     *         <p>
     *         <code>ALL_VERSIONS</code> - Enables regular gateway maintenance updates.
     *         </p>
     *         <p>
     *         <code>EMERGENCY_VERSIONS_ONLY</code> - Disables regular gateway maintenance updates.
     * @see AutomaticUpdatePolicy
     */

    public String getAutomaticUpdatePolicy() {
        return this.automaticUpdatePolicy;
    }

    /**
     * <p>
     * Indicates the automatic update policy for a gateway.
     * </p>
     * <p>
     * <code>ALL_VERSIONS</code> - Enables regular gateway maintenance updates.
     * </p>
     * <p>
     * <code>EMERGENCY_VERSIONS_ONLY</code> - Disables regular gateway maintenance updates.
     * </p>
     * 
     * @param automaticUpdatePolicy
     *        Indicates the automatic update policy for a gateway.</p>
     *        <p>
     *        <code>ALL_VERSIONS</code> - Enables regular gateway maintenance updates.
     *        </p>
     *        <p>
     *        <code>EMERGENCY_VERSIONS_ONLY</code> - Disables regular gateway maintenance updates.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see AutomaticUpdatePolicy
     */

    public SoftwareUpdatePreferences withAutomaticUpdatePolicy(String automaticUpdatePolicy) {
        setAutomaticUpdatePolicy(automaticUpdatePolicy);
        return this;
    }

    /**
     * <p>
     * Indicates the automatic update policy for a gateway.
     * </p>
     * <p>
     * <code>ALL_VERSIONS</code> - Enables regular gateway maintenance updates.
     * </p>
     * <p>
     * <code>EMERGENCY_VERSIONS_ONLY</code> - Disables regular gateway maintenance updates.
     * </p>
     * 
     * @param automaticUpdatePolicy
     *        Indicates the automatic update policy for a gateway.</p>
     *        <p>
     *        <code>ALL_VERSIONS</code> - Enables regular gateway maintenance updates.
     *        </p>
     *        <p>
     *        <code>EMERGENCY_VERSIONS_ONLY</code> - Disables regular gateway maintenance updates.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see AutomaticUpdatePolicy
     */

    public SoftwareUpdatePreferences withAutomaticUpdatePolicy(AutomaticUpdatePolicy automaticUpdatePolicy) {
        this.automaticUpdatePolicy = automaticUpdatePolicy.toString();
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
        if (getAutomaticUpdatePolicy() != null)
            sb.append("AutomaticUpdatePolicy: ").append(getAutomaticUpdatePolicy());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof SoftwareUpdatePreferences == false)
            return false;
        SoftwareUpdatePreferences other = (SoftwareUpdatePreferences) obj;
        if (other.getAutomaticUpdatePolicy() == null ^ this.getAutomaticUpdatePolicy() == null)
            return false;
        if (other.getAutomaticUpdatePolicy() != null && other.getAutomaticUpdatePolicy().equals(this.getAutomaticUpdatePolicy()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getAutomaticUpdatePolicy() == null) ? 0 : getAutomaticUpdatePolicy().hashCode());
        return hashCode;
    }

    @Override
    public SoftwareUpdatePreferences clone() {
        try {
            return (SoftwareUpdatePreferences) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.storagegateway.model.transform.SoftwareUpdatePreferencesMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
