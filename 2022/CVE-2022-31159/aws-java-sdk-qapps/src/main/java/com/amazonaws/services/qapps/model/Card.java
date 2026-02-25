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
 * A card representing a component or step in an Amazon Q App's flow.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/Card" target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class Card implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * A container for the properties of the text input card.
     * </p>
     */
    private TextInputCard textInput;
    /**
     * <p>
     * A container for the properties of the query card.
     * </p>
     */
    private QQueryCard qQuery;
    /**
     * <p>
     * A container for the properties of the plugin card.
     * </p>
     */
    private QPluginCard qPlugin;
    /**
     * <p>
     * A container for the properties of the file upload card.
     * </p>
     */
    private FileUploadCard fileUpload;

    /**
     * <p>
     * A container for the properties of the text input card.
     * </p>
     * 
     * @param textInput
     *        A container for the properties of the text input card.
     */

    public void setTextInput(TextInputCard textInput) {
        this.textInput = textInput;
    }

    /**
     * <p>
     * A container for the properties of the text input card.
     * </p>
     * 
     * @return A container for the properties of the text input card.
     */

    public TextInputCard getTextInput() {
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

    public Card withTextInput(TextInputCard textInput) {
        setTextInput(textInput);
        return this;
    }

    /**
     * <p>
     * A container for the properties of the query card.
     * </p>
     * 
     * @param qQuery
     *        A container for the properties of the query card.
     */

    public void setQQuery(QQueryCard qQuery) {
        this.qQuery = qQuery;
    }

    /**
     * <p>
     * A container for the properties of the query card.
     * </p>
     * 
     * @return A container for the properties of the query card.
     */

    public QQueryCard getQQuery() {
        return this.qQuery;
    }

    /**
     * <p>
     * A container for the properties of the query card.
     * </p>
     * 
     * @param qQuery
     *        A container for the properties of the query card.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Card withQQuery(QQueryCard qQuery) {
        setQQuery(qQuery);
        return this;
    }

    /**
     * <p>
     * A container for the properties of the plugin card.
     * </p>
     * 
     * @param qPlugin
     *        A container for the properties of the plugin card.
     */

    public void setQPlugin(QPluginCard qPlugin) {
        this.qPlugin = qPlugin;
    }

    /**
     * <p>
     * A container for the properties of the plugin card.
     * </p>
     * 
     * @return A container for the properties of the plugin card.
     */

    public QPluginCard getQPlugin() {
        return this.qPlugin;
    }

    /**
     * <p>
     * A container for the properties of the plugin card.
     * </p>
     * 
     * @param qPlugin
     *        A container for the properties of the plugin card.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Card withQPlugin(QPluginCard qPlugin) {
        setQPlugin(qPlugin);
        return this;
    }

    /**
     * <p>
     * A container for the properties of the file upload card.
     * </p>
     * 
     * @param fileUpload
     *        A container for the properties of the file upload card.
     */

    public void setFileUpload(FileUploadCard fileUpload) {
        this.fileUpload = fileUpload;
    }

    /**
     * <p>
     * A container for the properties of the file upload card.
     * </p>
     * 
     * @return A container for the properties of the file upload card.
     */

    public FileUploadCard getFileUpload() {
        return this.fileUpload;
    }

    /**
     * <p>
     * A container for the properties of the file upload card.
     * </p>
     * 
     * @param fileUpload
     *        A container for the properties of the file upload card.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public Card withFileUpload(FileUploadCard fileUpload) {
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

        if (obj instanceof Card == false)
            return false;
        Card other = (Card) obj;
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
    public Card clone() {
        try {
            return (Card) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.qapps.model.transform.CardMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
