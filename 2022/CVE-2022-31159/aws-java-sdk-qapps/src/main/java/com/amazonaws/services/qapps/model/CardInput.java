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
package com.amazonaws.services.qapps.model;

import java.io.Serializable;
import javax.annotation.Generated;
import com.amazonaws.protocol.StructuredPojo;
import com.amazonaws.protocol.ProtocolMarshaller;

/**
 * <p>
 * The properties defining an input card in an Amazon Q App.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/CardInput" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class CardInput implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * A container for the properties of the text input card.
     * </p>
     */
    private TextInputCardInput textInput;
    /**
     * <p>
     * A container for the properties of the query input card.
     * </p>
     */
    private QQueryCardInput qQuery;
    /**
     * <p>
     * A container for the properties of the plugin input card.
     * </p>
     */
    private QPluginCardInput qPlugin;
    /**
     * <p>
     * A container for the properties of the file upload input card.
     * </p>
     */
    private FileUploadCardInput fileUpload;

    /**
     * <p>
     * A container for the properties of the text input card.
     * </p>
     * 
     * @param textInput
     *        A container for the properties of the text input card.
     */

    public void setTextInput(TextInputCardInput textInput) {
        this.textInput = textInput;
    }

    /**
     * <p>
     * A container for the properties of the text input card.
     * </p>
     * 
     * @return A container for the properties of the text input card.
     */

    public TextInputCardInput getTextInput() {
        return this.textInput;
    }

    /**
     * <p>
     * A container for the properties of the text input card.
     * </p>
     * 
     * @param textInput
     *        A container for the properties of the text input card.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CardInput withTextInput(TextInputCardInput textInput) {
        setTextInput(textInput);
        return this;
    }

    /**
     * <p>
     * A container for the properties of the query input card.
     * </p>
     * 
     * @param qQuery
     *        A container for the properties of the query input card.
     */

    public void setQQuery(QQueryCardInput qQuery) {
        this.qQuery = qQuery;
    }

    /**
     * <p>
     * A container for the properties of the query input card.
     * </p>
     * 
     * @return A container for the properties of the query input card.
     */

    public QQueryCardInput getQQuery() {
        return this.qQuery;
    }

    /**
     * <p>
     * A container for the properties of the query input card.
     * </p>
     * 
     * @param qQuery
     *        A container for the properties of the query input card.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CardInput withQQuery(QQueryCardInput qQuery) {
        setQQuery(qQuery);
        return this;
    }

    /**
     * <p>
     * A container for the properties of the plugin input card.
     * </p>
     * 
     * @param qPlugin
     *        A container for the properties of the plugin input card.
     */

    public void setQPlugin(QPluginCardInput qPlugin) {
        this.qPlugin = qPlugin;
    }

    /**
     * <p>
     * A container for the properties of the plugin input card.
     * </p>
     * 
     * @return A container for the properties of the plugin input card.
     */

    public QPluginCardInput getQPlugin() {
        return this.qPlugin;
    }

    /**
     * <p>
     * A container for the properties of the plugin input card.
     * </p>
     * 
     * @param qPlugin
     *        A container for the properties of the plugin input card.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CardInput withQPlugin(QPluginCardInput qPlugin) {
        setQPlugin(qPlugin);
        return this;
    }

    /**
     * <p>
     * A container for the properties of the file upload input card.
     * </p>
     * 
     * @param fileUpload
     *        A container for the properties of the file upload input card.
     */

    public void setFileUpload(FileUploadCardInput fileUpload) {
        this.fileUpload = fileUpload;
    }

    /**
     * <p>
     * A container for the properties of the file upload input card.
     * </p>
     * 
     * @return A container for the properties of the file upload input card.
     */

    public FileUploadCardInput getFileUpload() {
        return this.fileUpload;
    }

    /**
     * <p>
     * A container for the properties of the file upload input card.
     * </p>
     * 
     * @param fileUpload
     *        A container for the properties of the file upload input card.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public CardInput withFileUpload(FileUploadCardInput fileUpload) {
        setFileUpload(fileUpload);
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
        if (getTextInput() != null)
            sb.append("TextInput: ").append(getTextInput()).append(",");
        if (getQQuery() != null)
            sb.append("QQuery: ").append(getQQuery()).append(",");
        if (getQPlugin() != null)
            sb.append("QPlugin: ").append(getQPlugin()).append(",");
        if (getFileUpload() != null)
            sb.append("FileUpload: ").append(getFileUpload());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof CardInput == false)
            return false;
        CardInput other = (CardInput) obj;
        if (other.getTextInput() == null ^ this.getTextInput() == null)
            return false;
        if (other.getTextInput() != null && other.getTextInput().equals(this.getTextInput()) == false)
            return false;
        if (other.getQQuery() == null ^ this.getQQuery() == null)
            return false;
        if (other.getQQuery() != null && other.getQQuery().equals(this.getQQuery()) == false)
            return false;
        if (other.getQPlugin() == null ^ this.getQPlugin() == null)
            return false;
        if (other.getQPlugin() != null && other.getQPlugin().equals(this.getQPlugin()) == false)
            return false;
        if (other.getFileUpload() == null ^ this.getFileUpload() == null)
            return false;
        if (other.getFileUpload() != null && other.getFileUpload().equals(this.getFileUpload()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getTextInput() == null) ? 0 : getTextInput().hashCode());
        hashCode = prime * hashCode + ((getQQuery() == null) ? 0 : getQQuery().hashCode());
        hashCode = prime * hashCode + ((getQPlugin() == null) ? 0 : getQPlugin().hashCode());
        hashCode = prime * hashCode + ((getFileUpload() == null) ? 0 : getFileUpload().hashCode());
        return hashCode;
    }

    @Override
    public CardInput clone() {
        try {
            return (CardInput) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.qapps.model.transform.CardInputMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
