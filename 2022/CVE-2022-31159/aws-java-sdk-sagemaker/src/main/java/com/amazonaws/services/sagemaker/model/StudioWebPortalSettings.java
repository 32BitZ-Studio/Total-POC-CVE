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
package com.amazonaws.services.sagemaker.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * Studio settings. If these settings are applied on a user level, they take priority over the settings applied on a
 * domain level.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/sagemaker-2017-07-24/StudioWebPortalSettings" target="_top">AWS
 *      API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class StudioWebPortalSettings implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The machine learning tools that are hidden from the Studio left navigation pane.
     * </p>
     */
    private java.util.List<String> hiddenMlTools;
    /**
     * <p>
     * The <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/studio-updated-apps.html">Applications supported in
     * Studio</a> that are hidden from the Studio left navigation pane.
     * </p>
     */
    private java.util.List<String> hiddenAppTypes;

    /**
     * <p>
     * The machine learning tools that are hidden from the Studio left navigation pane.
     * </p>
     * 
     * @return The machine learning tools that are hidden from the Studio left navigation pane.
     * @see MlTools
     */

    public java.util.List<String> getHiddenMlTools() {
        return hiddenMlTools;
    }

    /**
     * <p>
     * The machine learning tools that are hidden from the Studio left navigation pane.
     * </p>
     * 
     * @param hiddenMlTools
     *        The machine learning tools that are hidden from the Studio left navigation pane.
     * @see MlTools
     */

    public void setHiddenMlTools(java.util.Collection<String> hiddenMlTools) {
        if (hiddenMlTools == null) {
            this.hiddenMlTools = null;
            return;
        }

        this.hiddenMlTools = new java.util.ArrayList<String>(hiddenMlTools);
    }

    /**
     * <p>
     * The machine learning tools that are hidden from the Studio left navigation pane.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setHiddenMlTools(java.util.Collection)} or {@link #withHiddenMlTools(java.util.Collection)} if you want
     * to override the existing values.
     * </p>
     * 
     * @param hiddenMlTools
     *        The machine learning tools that are hidden from the Studio left navigation pane.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see MlTools
     */

    public StudioWebPortalSettings withHiddenMlTools(String... hiddenMlTools) {
        if (this.hiddenMlTools == null) {
            setHiddenMlTools(new java.util.ArrayList<String>(hiddenMlTools.length));
        }
        for (String ele : hiddenMlTools) {
            this.hiddenMlTools.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The machine learning tools that are hidden from the Studio left navigation pane.
     * </p>
     * 
     * @param hiddenMlTools
     *        The machine learning tools that are hidden from the Studio left navigation pane.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see MlTools
     */

    public StudioWebPortalSettings withHiddenMlTools(java.util.Collection<String> hiddenMlTools) {
        setHiddenMlTools(hiddenMlTools);
        return this;
    }

    /**
     * <p>
     * The machine learning tools that are hidden from the Studio left navigation pane.
     * </p>
     * 
     * @param hiddenMlTools
     *        The machine learning tools that are hidden from the Studio left navigation pane.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see MlTools
     */

    public StudioWebPortalSettings withHiddenMlTools(MlTools... hiddenMlTools) {
        java.util.ArrayList<String> hiddenMlToolsCopy = new java.util.ArrayList<String>(hiddenMlTools.length);
        for (MlTools value : hiddenMlTools) {
            hiddenMlToolsCopy.add(value.toString());
        }
        if (getHiddenMlTools() == null) {
            setHiddenMlTools(hiddenMlToolsCopy);
        } else {
            getHiddenMlTools().addAll(hiddenMlToolsCopy);
        }
        return this;
    }

    /**
     * <p>
     * The <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/studio-updated-apps.html">Applications supported in
     * Studio</a> that are hidden from the Studio left navigation pane.
     * </p>
     * 
     * @return The <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/studio-updated-apps.html">Applications
     *         supported in Studio</a> that are hidden from the Studio left navigation pane.
     * @see AppType
     */

    public java.util.List<String> getHiddenAppTypes() {
        return hiddenAppTypes;
    }

    /**
     * <p>
     * The <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/studio-updated-apps.html">Applications supported in
     * Studio</a> that are hidden from the Studio left navigation pane.
     * </p>
     * 
     * @param hiddenAppTypes
     *        The <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/studio-updated-apps.html">Applications
     *        supported in Studio</a> that are hidden from the Studio left navigation pane.
     * @see AppType
     */

    public void setHiddenAppTypes(java.util.Collection<String> hiddenAppTypes) {
        if (hiddenAppTypes == null) {
            this.hiddenAppTypes = null;
            return;
        }

        this.hiddenAppTypes = new java.util.ArrayList<String>(hiddenAppTypes);
    }

    /**
     * <p>
     * The <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/studio-updated-apps.html">Applications supported in
     * Studio</a> that are hidden from the Studio left navigation pane.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setHiddenAppTypes(java.util.Collection)} or {@link #withHiddenAppTypes(java.util.Collection)} if you want
     * to override the existing values.
     * </p>
     * 
     * @param hiddenAppTypes
     *        The <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/studio-updated-apps.html">Applications
     *        supported in Studio</a> that are hidden from the Studio left navigation pane.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see AppType
     */

    public StudioWebPortalSettings withHiddenAppTypes(String... hiddenAppTypes) {
        if (this.hiddenAppTypes == null) {
            setHiddenAppTypes(new java.util.ArrayList<String>(hiddenAppTypes.length));
        }
        for (String ele : hiddenAppTypes) {
            this.hiddenAppTypes.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/studio-updated-apps.html">Applications supported in
     * Studio</a> that are hidden from the Studio left navigation pane.
     * </p>
     * 
     * @param hiddenAppTypes
     *        The <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/studio-updated-apps.html">Applications
     *        supported in Studio</a> that are hidden from the Studio left navigation pane.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see AppType
     */

    public StudioWebPortalSettings withHiddenAppTypes(java.util.Collection<String> hiddenAppTypes) {
        setHiddenAppTypes(hiddenAppTypes);
        return this;
    }

    /**
     * <p>
     * The <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/studio-updated-apps.html">Applications supported in
     * Studio</a> that are hidden from the Studio left navigation pane.
     * </p>
     * 
     * @param hiddenAppTypes
     *        The <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/studio-updated-apps.html">Applications
     *        supported in Studio</a> that are hidden from the Studio left navigation pane.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see AppType
     */

    public StudioWebPortalSettings withHiddenAppTypes(AppType... hiddenAppTypes) {
        java.util.ArrayList<String> hiddenAppTypesCopy = new java.util.ArrayList<String>(hiddenAppTypes.length);
        for (AppType value : hiddenAppTypes) {
            hiddenAppTypesCopy.add(value.toString());
        }
        if (getHiddenAppTypes() == null) {
            setHiddenAppTypes(hiddenAppTypesCopy);
        } else {
            getHiddenAppTypes().addAll(hiddenAppTypesCopy);
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
        if (getHiddenMlTools() != null)
            sb.append("HiddenMlTools: ").append(getHiddenMlTools()).append(",");
        if (getHiddenAppTypes() != null)
            sb.append("HiddenAppTypes: ").append(getHiddenAppTypes());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof StudioWebPortalSettings == false)
            return false;
        StudioWebPortalSettings other = (StudioWebPortalSettings) obj;
        if (other.getHiddenMlTools() == null ^ this.getHiddenMlTools() == null)
            return false;
        if (other.getHiddenMlTools() != null && other.getHiddenMlTools().equals(this.getHiddenMlTools()) == false)
            return false;
        if (other.getHiddenAppTypes() == null ^ this.getHiddenAppTypes() == null)
            return false;
        if (other.getHiddenAppTypes() != null && other.getHiddenAppTypes().equals(this.getHiddenAppTypes()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getHiddenMlTools() == null) ? 0 : getHiddenMlTools().hashCode());
        hashCode = prime * hashCode + ((getHiddenAppTypes() == null) ? 0 : getHiddenAppTypes().hashCode());
        return hashCode;
    }

    @Override
    public StudioWebPortalSettings clone() {
        try {
            return (StudioWebPortalSettings) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.sagemaker.model.transform.StudioWebPortalSettingsMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
