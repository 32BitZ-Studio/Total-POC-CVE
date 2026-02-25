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
 * Represents a file upload card. It can optionally receive a <code>filename</code> and <code>fileId</code> to set a
 * default file. If not received, the user must provide the file when the Q App runs.
 * </p>
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/qapps-2023-11-27/FileUploadCardInput" target="_top">AWS API
 *      Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class FileUploadCardInput implements Serializable, Cloneable, StructuredPojo {

    /**
     * <p>
     * The title or label of the file upload card.
     * </p>
     */
    private String title;
    /**
     * <p>
     * The unique identifier of the file upload card.
     * </p>
     */
    private String id;
    /**
     * <p>
     * The type of the card.
     * </p>
     */
    private String type;
    /**
     * <p>
     * The default filename to use for the file upload card.
     * </p>
     */
    private String filename;
    /**
     * <p>
     * The identifier of a pre-uploaded file associated with the card.
     * </p>
     */
    private String fileId;
    /**
     * <p>
     * A flag indicating if the user can override the default file for the upload card.
     * </p>
     */
    private Boolean allowOverride;

    /**
     * <p>
     * The title or label of the file upload card.
     * </p>
     * 
     * @param title
     *        The title or label of the file upload card.
     */

    public void setTitle(String title) {
        this.title = title;
    }

    /**
     * <p>
     * The title or label of the file upload card.
     * </p>
     * 
     * @return The title or label of the file upload card.
     */

    public String getTitle() {
        return this.title;
    }

    /**
     * <p>
     * The title or label of the file upload card.
     * </p>
     * 
     * @param title
     *        The title or label of the file upload card.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public FileUploadCardInput withTitle(String title) {
        setTitle(title);
        return this;
    }

    /**
     * <p>
     * The unique identifier of the file upload card.
     * </p>
     * 
     * @param id
     *        The unique identifier of the file upload card.
     */

    public void setId(String id) {
        this.id = id;
    }

    /**
     * <p>
     * The unique identifier of the file upload card.
     * </p>
     * 
     * @return The unique identifier of the file upload card.
     */

    public String getId() {
        return this.id;
    }

    /**
     * <p>
     * The unique identifier of the file upload card.
     * </p>
     * 
     * @param id
     *        The unique identifier of the file upload card.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public FileUploadCardInput withId(String id) {
        setId(id);
        return this;
    }

    /**
     * <p>
     * The type of the card.
     * </p>
     * 
     * @param type
     *        The type of the card.
     * @see CardType
     */

    public void setType(String type) {
        this.type = type;
    }

    /**
     * <p>
     * The type of the card.
     * </p>
     * 
     * @return The type of the card.
     * @see CardType
     */

    public String getType() {
        return this.type;
    }

    /**
     * <p>
     * The type of the card.
     * </p>
     * 
     * @param type
     *        The type of the card.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see CardType
     */

    public FileUploadCardInput withType(String type) {
        setType(type);
        return this;
    }

    /**
     * <p>
     * The type of the card.
     * </p>
     * 
     * @param type
     *        The type of the card.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see CardType
     */

    public FileUploadCardInput withType(CardType type) {
        this.type = type.toString();
        return this;
    }

    /**
     * <p>
     * The default filename to use for the file upload card.
     * </p>
     * 
     * @param filename
     *        The default filename to use for the file upload card.
     */

    public void setFilename(String filename) {
        this.filename = filename;
    }

    /**
     * <p>
     * The default filename to use for the file upload card.
     * </p>
     * 
     * @return The default filename to use for the file upload card.
     */

    public String getFilename() {
        return this.filename;
    }

    /**
     * <p>
     * The default filename to use for the file upload card.
     * </p>
     * 
     * @param filename
     *        The default filename to use for the file upload card.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public FileUploadCardInput withFilename(String filename) {
        setFilename(filename);
        return this;
    }

    /**
     * <p>
     * The identifier of a pre-uploaded file associated with the card.
     * </p>
     * 
     * @param fileId
     *        The identifier of a pre-uploaded file associated with the card.
     */

    public void setFileId(String fileId) {
        this.fileId = fileId;
    }

    /**
     * <p>
     * The identifier of a pre-uploaded file associated with the card.
     * </p>
     * 
     * @return The identifier of a pre-uploaded file associated with the card.
     */

    public String getFileId() {
        return this.fileId;
    }

    /**
     * <p>
     * The identifier of a pre-uploaded file associated with the card.
     * </p>
     * 
     * @param fileId
     *        The identifier of a pre-uploaded file associated with the card.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public FileUploadCardInput withFileId(String fileId) {
        setFileId(fileId);
        return this;
    }

    /**
     * <p>
     * A flag indicating if the user can override the default file for the upload card.
     * </p>
     * 
     * @param allowOverride
     *        A flag indicating if the user can override the default file for the upload card.
     */

    public void setAllowOverride(Boolean allowOverride) {
        this.allowOverride = allowOverride;
    }

    /**
     * <p>
     * A flag indicating if the user can override the default file for the upload card.
     * </p>
     * 
     * @return A flag indicating if the user can override the default file for the upload card.
     */

    public Boolean getAllowOverride() {
        return this.allowOverride;
    }

    /**
     * <p>
     * A flag indicating if the user can override the default file for the upload card.
     * </p>
     * 
     * @param allowOverride
     *        A flag indicating if the user can override the default file for the upload card.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public FileUploadCardInput withAllowOverride(Boolean allowOverride) {
        setAllowOverride(allowOverride);
        return this;
    }

    /**
     * <p>
     * A flag indicating if the user can override the default file for the upload card.
     * </p>
     * 
     * @return A flag indicating if the user can override the default file for the upload card.
     */

    public Boolean isAllowOverride() {
        return this.allowOverride;
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
        if (getTitle() != null)
            sb.append("Title: ").append(getTitle()).append(",");
        if (getId() != null)
            sb.append("Id: ").append(getId()).append(",");
        if (getType() != null)
            sb.append("Type: ").append(getType()).append(",");
        if (getFilename() != null)
            sb.append("Filename: ").append(getFilename()).append(",");
        if (getFileId() != null)
            sb.append("FileId: ").append(getFileId()).append(",");
        if (getAllowOverride() != null)
            sb.append("AllowOverride: ").append(getAllowOverride());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof FileUploadCardInput == false)
            return false;
        FileUploadCardInput other = (FileUploadCardInput) obj;
        if (other.getTitle() == null ^ this.getTitle() == null)
            return false;
        if (other.getTitle() != null && other.getTitle().equals(this.getTitle()) == false)
            return false;
        if (other.getId() == null ^ this.getId() == null)
            return false;
        if (other.getId() != null && other.getId().equals(this.getId()) == false)
            return false;
        if (other.getType() == null ^ this.getType() == null)
            return false;
        if (other.getType() != null && other.getType().equals(this.getType()) == false)
            return false;
        if (other.getFilename() == null ^ this.getFilename() == null)
            return false;
        if (other.getFilename() != null && other.getFilename().equals(this.getFilename()) == false)
            return false;
        if (other.getFileId() == null ^ this.getFileId() == null)
            return false;
        if (other.getFileId() != null && other.getFileId().equals(this.getFileId()) == false)
            return false;
        if (other.getAllowOverride() == null ^ this.getAllowOverride() == null)
            return false;
        if (other.getAllowOverride() != null && other.getAllowOverride().equals(this.getAllowOverride()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getTitle() == null) ? 0 : getTitle().hashCode());
        hashCode = prime * hashCode + ((getId() == null) ? 0 : getId().hashCode());
        hashCode = prime * hashCode + ((getType() == null) ? 0 : getType().hashCode());
        hashCode = prime * hashCode + ((getFilename() == null) ? 0 : getFilename().hashCode());
        hashCode = prime * hashCode + ((getFileId() == null) ? 0 : getFileId().hashCode());
        hashCode = prime * hashCode + ((getAllowOverride() == null) ? 0 : getAllowOverride().hashCode());
        return hashCode;
    }

    @Override
    public FileUploadCardInput clone() {
        try {
            return (FileUploadCardInput) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone() " + "even though we're Cloneable!", e);
        }
    }

    @com.amazonaws.annotation.SdkInternalApi
    @Override
    public void marshall(ProtocolMarshaller protocolMarshaller) {
        com.amazonaws.services.qapps.model.transform.FileUploadCardInputMarshaller.getInstance().marshall(this, protocolMarshaller);
    }
}
