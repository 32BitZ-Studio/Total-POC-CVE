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

import javax.annotation.Generated;

/**
 * <p>
 * The exception when the input doesn't pass validation for at least one of the input parameters.
 * </p>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class ValidationException extends com.amazonaws.services.taxsettings.model.AWSTaxSettingsException {
    private static final long serialVersionUID = 1L;

    /**
     * <p>
     * 400
     * </p>
     */
    private String errorCode;
    /**
     * <p>
     * 400
     * </p>
     */
    private java.util.List<ValidationExceptionField> fieldList;

    /**
     * Constructs a new ValidationException with the specified error message.
     *
     * @param message
     *        Describes the error encountered.
     */
    public ValidationException(String message) {
        super(message);
    }

    /**
     * <p>
     * 400
     * </p>
     * 
     * @param errorCode
     *        400
     * @see ValidationExceptionErrorCode
     */

    @com.fasterxml.jackson.annotation.JsonProperty("errorCode")
    public void setErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }

    /**
     * <p>
     * 400
     * </p>
     * 
     * @return 400
     * @see ValidationExceptionErrorCode
     */

    @com.fasterxml.jackson.annotation.JsonProperty("errorCode")
    public String getErrorCode() {
        return this.errorCode;
    }

    /**
     * <p>
     * 400
     * </p>
     * 
     * @param errorCode
     *        400
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ValidationExceptionErrorCode
     */

    public ValidationException withErrorCode(String errorCode) {
        setErrorCode(errorCode);
        return this;
    }

    /**
     * <p>
     * 400
     * </p>
     * 
     * @param errorCode
     *        400
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see ValidationExceptionErrorCode
     */

    public ValidationException withErrorCode(ValidationExceptionErrorCode errorCode) {
        this.errorCode = errorCode.toString();
        return this;
    }

    /**
     * <p>
     * 400
     * </p>
     * 
     * @return 400
     */

    @com.fasterxml.jackson.annotation.JsonProperty("fieldList")
    public java.util.List<ValidationExceptionField> getFieldList() {
        return fieldList;
    }

    /**
     * <p>
     * 400
     * </p>
     * 
     * @param fieldList
     *        400
     */

    @com.fasterxml.jackson.annotation.JsonProperty("fieldList")
    public void setFieldList(java.util.Collection<ValidationExceptionField> fieldList) {
        if (fieldList == null) {
            this.fieldList = null;
            return;
        }

        this.fieldList = new java.util.ArrayList<ValidationExceptionField>(fieldList);
    }

    /**
     * <p>
     * 400
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setFieldList(java.util.Collection)} or {@link #withFieldList(java.util.Collection)} if you want to
     * override the existing values.
     * </p>
     * 
     * @param fieldList
     *        400
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ValidationException withFieldList(ValidationExceptionField... fieldList) {
        if (this.fieldList == null) {
            setFieldList(new java.util.ArrayList<ValidationExceptionField>(fieldList.length));
        }
        for (ValidationExceptionField ele : fieldList) {
            this.fieldList.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * 400
     * </p>
     * 
     * @param fieldList
     *        400
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public ValidationException withFieldList(java.util.Collection<ValidationExceptionField> fieldList) {
        setFieldList(fieldList);
        return this;
    }

}
