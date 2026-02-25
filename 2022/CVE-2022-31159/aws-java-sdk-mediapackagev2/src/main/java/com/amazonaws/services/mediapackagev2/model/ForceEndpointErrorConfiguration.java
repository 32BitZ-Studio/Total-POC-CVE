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
package com.amazonaws.services.mediapackagev2.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * The failover settings for the endpoint.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/mediapackagev2-2022-12-25/ForceEndpointErrorConfiguration"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ForceEndpointErrorConfiguration implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The failover conditions for the endpoint. The options are:
     * </p>
     * <ul>
     * <li>
     * <p>
     * <code>STALE_MANIFEST</code> - The manifest stalled and there are no new segments or parts.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>INCOMPLETE_MANIFEST</code> - There is a gap in the manifest.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>MISSING_DRM_KEY</code> - Key rotation is enabled but we're unable to fetch the key for the current key
     * period.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>SLATE_INPUT</code> - The segments which contain slate content are considered to be missing content.
     * </p>
     * </li>
     * </ul>
     */
    private java.util.List<String> endpointErrorConditions;

    /**
     * <p>
     * The failover conditions for the endpoint. The options are:
     * </p>
     * <ul>
     * <li>
     * <p>
     * <code>STALE_MANIFEST</code> - The manifest stalled and there are no new segments or parts.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>INCOMPLETE_MANIFEST</code> - There is a gap in the manifest.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>MISSING_DRM_KEY</code> - Key rotation is enabled but we're unable to fetch the key for the current key
     * period.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>SLATE_INPUT</code> - The segments which contain slate content are considered to be missing content.
     * </p>
     * </li>
     * </ul>
     * 
     * @return The failover conditions for the endpoint. The options are:</p>
     *         <ul>
     *         <li>
     *         <p>
     *         <code>STALE_MANIFEST</code> - The manifest stalled and there are no new segments or parts.
     *         </p>
     *         </li>
     *         <li>
     *         <p>
     *         <code>INCOMPLETE_MANIFEST</code> - There is a gap in the manifest.
     *         </p>
     *         </li>
     *         <li>
     *         <p>
     *         <code>MISSING_DRM_KEY</code> - Key rotation is enabled but we're unable to fetch the key for the current
     *         key period.
     *         </p>
     *         </li>
     *         <li>
     *         <p>
     *         <code>SLATE_INPUT</code> - The segments which contain slate content are considered to be missing content.
     *         </p>
     *         </li>
     * @see EndpointErrorCondition
     */

    public java.util.List<String> getEndpointErrorConditions() {
        return endpointErrorConditions;
    }

    /**
     * <p>
     * The failover conditions for the endpoint. The options are:
     * </p>
     * <ul>
     * <li>
     * <p>
     * <code>STALE_MANIFEST</code> - The manifest stalled and there are no new segments or parts.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>INCOMPLETE_MANIFEST</code> - There is a gap in the manifest.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>MISSING_DRM_KEY</code> - Key rotation is enabled but we're unable to fetch the key for the current key
     * period.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>SLATE_INPUT</code> - The segments which contain slate content are considered to be missing content.
     * </p>
     * </li>
     * </ul>
     * 
     * @param endpointErrorConditions
     *        The failover conditions for the endpoint. The options are:</p>
     *        <ul>
     *        <li>
     *        <p>
     *        <code>STALE_MANIFEST</code> - The manifest stalled and there are no new segments or parts.
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        <code>INCOMPLETE_MANIFEST</code> - There is a gap in the manifest.
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        <code>MISSING_DRM_KEY</code> - Key rotation is enabled but we're unable to fetch the key for the current
     *        key period.
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        <code>SLATE_INPUT</code> - The segments which contain slate content are considered to be missing content.
     *        </p>
     *        </li>
     * @see EndpointErrorCondition
     */

    public void setEndpointErrorConditions(java.util.Collection<String> endpointErrorConditions) {
        if (endpointErrorConditions == null) {
            this.endpointErrorConditions = null;
            return;
        }

        this.endpointErrorConditions = new java.util.ArrayList<String>(endpointErrorConditions);
    }

    /**
     * <p>
     * The failover conditions for the endpoint. The options are:
     * </p>
     * <ul>
     * <li>
     * <p>
     * <code>STALE_MANIFEST</code> - The manifest stalled and there are no new segments or parts.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>INCOMPLETE_MANIFEST</code> - There is a gap in the manifest.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>MISSING_DRM_KEY</code> - Key rotation is enabled but we're unable to fetch the key for the current key
     * period.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>SLATE_INPUT</code> - The segments which contain slate content are considered to be missing content.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setEndpointErrorConditions(java.util.Collection)} or
     * {@link #withEndpointErrorConditions(java.util.Collection)} if you want to override the existing values.
     * </p>
     * 
     * @param endpointErrorConditions
     *        The failover conditions for the endpoint. The options are:</p>
     *        <ul>
     *        <li>
     *        <p>
     *        <code>STALE_MANIFEST</code> - The manifest stalled and there are no new segments or parts.
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        <code>INCOMPLETE_MANIFEST</code> - There is a gap in the manifest.
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        <code>MISSING_DRM_KEY</code> - Key rotation is enabled but we're unable to fetch the key for the current
     *        key period.
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        <code>SLATE_INPUT</code> - The segments which contain slate content are considered to be missing content.
     *        </p>
     *        </li>
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see EndpointErrorCondition
     */

    public ForceEndpointErrorConfiguration withEndpointErrorConditions(String... endpointErrorConditions) {
        if (this.endpointErrorConditions == null) {
            setEndpointErrorConditions(new java.util.ArrayList<String>(endpointErrorConditions.length));
        }
        for (String ele : endpointErrorConditions) {
            this.endpointErrorConditions.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The failover conditions for the endpoint. The options are:
     * </p>
     * <ul>
     * <li>
     * <p>
     * <code>STALE_MANIFEST</code> - The manifest stalled and there are no new segments or parts.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>INCOMPLETE_MANIFEST</code> - There is a gap in the manifest.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>MISSING_DRM_KEY</code> - Key rotation is enabled but we're unable to fetch the key for the current key
     * period.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>SLATE_INPUT</code> - The segments which contain slate content are considered to be missing content.
     * </p>
     * </li>
     * </ul>
     * 
     * @param endpointErrorConditions
     *        The failover conditions for the endpoint. The options are:</p>
     *        <ul>
     *        <li>
     *        <p>
     *        <code>STALE_MANIFEST</code> - The manifest stalled and there are no new segments or parts.
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        <code>INCOMPLETE_MANIFEST</code> - There is a gap in the manifest.
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        <code>MISSING_DRM_KEY</code> - Key rotation is enabled but we're unable to fetch the key for the current
     *        key period.
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        <code>SLATE_INPUT</code> - The segments which contain slate content are considered to be missing content.
     *        </p>
     *        </li>
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see EndpointErrorCondition
     */

    public ForceEndpointErrorConfiguration withEndpointErrorConditions(java.util.Collection<String> endpointErrorConditions) {
        setEndpointErrorConditions(endpointErrorConditions);
        return this;
    }

    /**
     * <p>
     * The failover conditions for the endpoint. The options are:
     * </p>
     * <ul>
     * <li>
     * <p>
     * <code>STALE_MANIFEST</code> - The manifest stalled and there are no new segments or parts.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>INCOMPLETE_MANIFEST</code> - There is a gap in the manifest.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>MISSING_DRM_KEY</code> - Key rotation is enabled but we're unable to fetch the key for the current key
     * period.
     * </p>
     * </li>
     * <li>
     * <p>
     * <code>SLATE_INPUT</code> - The segments which contain slate content are considered to be missing content.
     * </p>
     * </li>
     * </ul>
     * 
     * @param endpointErrorConditions
     *        The failover conditions for the endpoint. The options are:</p>
     *        <ul>
     *        <li>
     *        <p>
     *        <code>STALE_MANIFEST</code> - The manifest stalled and there are no new segments or parts.
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        <code>INCOMPLETE_MANIFEST</code> - There is a gap in the manifest.
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        <code>MISSING_DRM_KEY</code> - Key rotation is enabled but we're unable to fetch the key for the current
     *        key period.
     *        </p>
     *        </li>
     *        <li>
     *        <p>
     *        <code>SLATE_INPUT</code> - The segments which contain slate content are considered to be missing content.
     *        </p>
     *        </li>
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see EndpointErrorCondition
     */

    public ForceEndpointErrorConfiguration withEndpointErrorConditions(EndpointErrorCondition... endpointErrorConditions) {
        java.util.ArrayList<String> endpointErrorConditionsCopy = new java.util.ArrayList<String>(endpointErrorConditions.length);
        for (EndpointErrorCondition value : endpointErrorConditions) {
            endpointErrorConditionsCopy.add(value.toString());
        }
        if (getEndpointErrorConditions() == null) {
            setEndpointErrorConditions(endpointErrorConditionsCopy);
        } else {
            getEndpointErrorConditions().addAll(endpointErrorConditionsCopy);
        }
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
        if (getEndpointErrorConditions() != null)
            sb.append("EndpointErrorConditions: ").append(getEndpointErrorConditions());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof ForceEndpointErrorConfiguration == false)
            return false;
        ForceEndpointErrorConfiguration other = (ForceEndpointErrorConfiguration) obj;
        if (other.getEndpointErrorConditions() == null ^ this.getEndpointErrorConditions() == null)
            return false;
        if (other.getEndpointErrorConditions() != null && other.getEndpointErrorConditions().equals(this.getEndpointErrorConditions()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getEndpointErrorConditions() == null) ? 0 : getEndpointErrorConditions().hashCode());
        return hashCode;
    }

    @Override
    public ForceEndpointErrorConfiguration clone() {
        try {
            return (ForceEndpointErrorConfiguration) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.mediapackagev2.model.transform.ForceEndpointErrorConfigurationMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
