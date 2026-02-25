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
package com.amazonaws.services.workspaces.model;

import java.io.Serializable;
import javax.annotation.Generated;

import com.amazonaws.AmazonWebServiceRequest;

/**
 * 
 * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/workspaces-2015-04-08/RegisterWorkspaceDirectory"
 *      target="_top">AWS API Documentation</a>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public class RegisterWorkspaceDirectoryRequest extends com.amazonaws.AmazonWebServiceRequest implements Serializable, Cloneable {

    /**
     * <p>
     * The identifier of the directory. You cannot register a directory if it does not have a status of Active. If the
     * directory does not have a status of Active, you will receive an InvalidResourceStateException error. If you have
     * already registered the maximum number of directories that you can register with Amazon WorkSpaces, you will
     * receive a ResourceLimitExceededException error. Deregister directories that you are not using for WorkSpaces, and
     * try again.
     * </p>
     */
    private String directoryId;
    /**
     * <p>
     * The identifiers of the subnets for your virtual private cloud (VPC). Make sure that the subnets are in supported
     * Availability Zones. The subnets must also be in separate Availability Zones. If these conditions are not met, you
     * will receive an OperationNotSupportedException error.
     * </p>
     */
    private com.amazonaws.internal.SdkInternalList<String> subnetIds;
    /**
     * <p>
     * Indicates whether Amazon WorkDocs is enabled or disabled. If you have enabled this parameter and WorkDocs is not
     * available in the Region, you will receive an OperationNotSupportedException error. Set
     * <code>EnableWorkDocs</code> to disabled, and try again.
     * </p>
     */
    private Boolean enableWorkDocs;
    /**
     * <p>
     * Indicates whether self-service capabilities are enabled or disabled.
     * </p>
     */
    private Boolean enableSelfService;
    /**
     * <p>
     * Indicates whether your WorkSpace directory is dedicated or shared. To use Bring Your Own License (BYOL) images,
     * this value must be set to <code>DEDICATED</code> and your Amazon Web Services account must be enabled for BYOL.
     * If your account has not been enabled for BYOL, you will receive an InvalidParameterValuesException error. For
     * more information about BYOL images, see <a
     * href="https://docs.aws.amazon.com/workspaces/latest/adminguide/byol-windows-images.html">Bring Your Own Windows
     * Desktop Images</a>.
     * </p>
     */
    private String tenancy;
    /**
     * <p>
     * The tags associated with the directory.
     * </p>
     */
    private com.amazonaws.internal.SdkInternalList<Tag> tags;
    /**
     * <p>
     * The name of the directory to register.
     * </p>
     */
    private String workspaceDirectoryName;
    /**
     * <p>
     * Description of the directory to register.
     * </p>
     */
    private String workspaceDirectoryDescription;
    /**
     * <p>
     * The type of identity management the user is using.
     * </p>
     */
    private String userIdentityType;
    /**
     * <p>
     * Indicates whether the directory's WorkSpace type is personal or pools.
     * </p>
     */
    private String workspaceType;
    /**
     * <p>
     * The active directory config of the directory.
     * </p>
     */
    private ActiveDirectoryConfig activeDirectoryConfig;

    /**
     * <p>
     * The identifier of the directory. You cannot register a directory if it does not have a status of Active. If the
     * directory does not have a status of Active, you will receive an InvalidResourceStateException error. If you have
     * already registered the maximum number of directories that you can register with Amazon WorkSpaces, you will
     * receive a ResourceLimitExceededException error. Deregister directories that you are not using for WorkSpaces, and
     * try again.
     * </p>
     * 
     * @param directoryId
     *        The identifier of the directory. You cannot register a directory if it does not have a status of Active.
     *        If the directory does not have a status of Active, you will receive an InvalidResourceStateException
     *        error. If you have already registered the maximum number of directories that you can register with Amazon
     *        WorkSpaces, you will receive a ResourceLimitExceededException error. Deregister directories that you are
     *        not using for WorkSpaces, and try again.
     */

    public void setDirectoryId(String directoryId) {
        this.directoryId = directoryId;
    }

    /**
     * <p>
     * The identifier of the directory. You cannot register a directory if it does not have a status of Active. If the
     * directory does not have a status of Active, you will receive an InvalidResourceStateException error. If you have
     * already registered the maximum number of directories that you can register with Amazon WorkSpaces, you will
     * receive a ResourceLimitExceededException error. Deregister directories that you are not using for WorkSpaces, and
     * try again.
     * </p>
     * 
     * @return The identifier of the directory. You cannot register a directory if it does not have a status of Active.
     *         If the directory does not have a status of Active, you will receive an InvalidResourceStateException
     *         error. If you have already registered the maximum number of directories that you can register with Amazon
     *         WorkSpaces, you will receive a ResourceLimitExceededException error. Deregister directories that you are
     *         not using for WorkSpaces, and try again.
     */

    public String getDirectoryId() {
        return this.directoryId;
    }

    /**
     * <p>
     * The identifier of the directory. You cannot register a directory if it does not have a status of Active. If the
     * directory does not have a status of Active, you will receive an InvalidResourceStateException error. If you have
     * already registered the maximum number of directories that you can register with Amazon WorkSpaces, you will
     * receive a ResourceLimitExceededException error. Deregister directories that you are not using for WorkSpaces, and
     * try again.
     * </p>
     * 
     * @param directoryId
     *        The identifier of the directory. You cannot register a directory if it does not have a status of Active.
     *        If the directory does not have a status of Active, you will receive an InvalidResourceStateException
     *        error. If you have already registered the maximum number of directories that you can register with Amazon
     *        WorkSpaces, you will receive a ResourceLimitExceededException error. Deregister directories that you are
     *        not using for WorkSpaces, and try again.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public RegisterWorkspaceDirectoryRequest withDirectoryId(String directoryId) {
        setDirectoryId(directoryId);
        return this;
    }

    /**
     * <p>
     * The identifiers of the subnets for your virtual private cloud (VPC). Make sure that the subnets are in supported
     * Availability Zones. The subnets must also be in separate Availability Zones. If these conditions are not met, you
     * will receive an OperationNotSupportedException error.
     * </p>
     * 
     * @return The identifiers of the subnets for your virtual private cloud (VPC). Make sure that the subnets are in
     *         supported Availability Zones. The subnets must also be in separate Availability Zones. If these
     *         conditions are not met, you will receive an OperationNotSupportedException error.
     */

    public java.util.List<String> getSubnetIds() {
        if (subnetIds == null) {
            subnetIds = new com.amazonaws.internal.SdkInternalList<String>();
        }
        return subnetIds;
    }

    /**
     * <p>
     * The identifiers of the subnets for your virtual private cloud (VPC). Make sure that the subnets are in supported
     * Availability Zones. The subnets must also be in separate Availability Zones. If these conditions are not met, you
     * will receive an OperationNotSupportedException error.
     * </p>
     * 
     * @param subnetIds
     *        The identifiers of the subnets for your virtual private cloud (VPC). Make sure that the subnets are in
     *        supported Availability Zones. The subnets must also be in separate Availability Zones. If these conditions
     *        are not met, you will receive an OperationNotSupportedException error.
     */

    public void setSubnetIds(java.util.Collection<String> subnetIds) {
        if (subnetIds == null) {
            this.subnetIds = null;
            return;
        }

        this.subnetIds = new com.amazonaws.internal.SdkInternalList<String>(subnetIds);
    }

    /**
     * <p>
     * The identifiers of the subnets for your virtual private cloud (VPC). Make sure that the subnets are in supported
     * Availability Zones. The subnets must also be in separate Availability Zones. If these conditions are not met, you
     * will receive an OperationNotSupportedException error.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setSubnetIds(java.util.Collection)} or {@link #withSubnetIds(java.util.Collection)} if you want to
     * override the existing values.
     * </p>
     * 
     * @param subnetIds
     *        The identifiers of the subnets for your virtual private cloud (VPC). Make sure that the subnets are in
     *        supported Availability Zones. The subnets must also be in separate Availability Zones. If these conditions
     *        are not met, you will receive an OperationNotSupportedException error.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public RegisterWorkspaceDirectoryRequest withSubnetIds(String... subnetIds) {
        if (this.subnetIds == null) {
            setSubnetIds(new com.amazonaws.internal.SdkInternalList<String>(subnetIds.length));
        }
        for (String ele : subnetIds) {
            this.subnetIds.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The identifiers of the subnets for your virtual private cloud (VPC). Make sure that the subnets are in supported
     * Availability Zones. The subnets must also be in separate Availability Zones. If these conditions are not met, you
     * will receive an OperationNotSupportedException error.
     * </p>
     * 
     * @param subnetIds
     *        The identifiers of the subnets for your virtual private cloud (VPC). Make sure that the subnets are in
     *        supported Availability Zones. The subnets must also be in separate Availability Zones. If these conditions
     *        are not met, you will receive an OperationNotSupportedException error.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public RegisterWorkspaceDirectoryRequest withSubnetIds(java.util.Collection<String> subnetIds) {
        setSubnetIds(subnetIds);
        return this;
    }

    /**
     * <p>
     * Indicates whether Amazon WorkDocs is enabled or disabled. If you have enabled this parameter and WorkDocs is not
     * available in the Region, you will receive an OperationNotSupportedException error. Set
     * <code>EnableWorkDocs</code> to disabled, and try again.
     * </p>
     * 
     * @param enableWorkDocs
     *        Indicates whether Amazon WorkDocs is enabled or disabled. If you have enabled this parameter and WorkDocs
     *        is not available in the Region, you will receive an OperationNotSupportedException error. Set
     *        <code>EnableWorkDocs</code> to disabled, and try again.
     */

    public void setEnableWorkDocs(Boolean enableWorkDocs) {
        this.enableWorkDocs = enableWorkDocs;
    }

    /**
     * <p>
     * Indicates whether Amazon WorkDocs is enabled or disabled. If you have enabled this parameter and WorkDocs is not
     * available in the Region, you will receive an OperationNotSupportedException error. Set
     * <code>EnableWorkDocs</code> to disabled, and try again.
     * </p>
     * 
     * @return Indicates whether Amazon WorkDocs is enabled or disabled. If you have enabled this parameter and WorkDocs
     *         is not available in the Region, you will receive an OperationNotSupportedException error. Set
     *         <code>EnableWorkDocs</code> to disabled, and try again.
     */

    public Boolean getEnableWorkDocs() {
        return this.enableWorkDocs;
    }

    /**
     * <p>
     * Indicates whether Amazon WorkDocs is enabled or disabled. If you have enabled this parameter and WorkDocs is not
     * available in the Region, you will receive an OperationNotSupportedException error. Set
     * <code>EnableWorkDocs</code> to disabled, and try again.
     * </p>
     * 
     * @param enableWorkDocs
     *        Indicates whether Amazon WorkDocs is enabled or disabled. If you have enabled this parameter and WorkDocs
     *        is not available in the Region, you will receive an OperationNotSupportedException error. Set
     *        <code>EnableWorkDocs</code> to disabled, and try again.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public RegisterWorkspaceDirectoryRequest withEnableWorkDocs(Boolean enableWorkDocs) {
        setEnableWorkDocs(enableWorkDocs);
        return this;
    }

    /**
     * <p>
     * Indicates whether Amazon WorkDocs is enabled or disabled. If you have enabled this parameter and WorkDocs is not
     * available in the Region, you will receive an OperationNotSupportedException error. Set
     * <code>EnableWorkDocs</code> to disabled, and try again.
     * </p>
     * 
     * @return Indicates whether Amazon WorkDocs is enabled or disabled. If you have enabled this parameter and WorkDocs
     *         is not available in the Region, you will receive an OperationNotSupportedException error. Set
     *         <code>EnableWorkDocs</code> to disabled, and try again.
     */

    public Boolean isEnableWorkDocs() {
        return this.enableWorkDocs;
    }

    /**
     * <p>
     * Indicates whether self-service capabilities are enabled or disabled.
     * </p>
     * 
     * @param enableSelfService
     *        Indicates whether self-service capabilities are enabled or disabled.
     */

    public void setEnableSelfService(Boolean enableSelfService) {
        this.enableSelfService = enableSelfService;
    }

    /**
     * <p>
     * Indicates whether self-service capabilities are enabled or disabled.
     * </p>
     * 
     * @return Indicates whether self-service capabilities are enabled or disabled.
     */

    public Boolean getEnableSelfService() {
        return this.enableSelfService;
    }

    /**
     * <p>
     * Indicates whether self-service capabilities are enabled or disabled.
     * </p>
     * 
     * @param enableSelfService
     *        Indicates whether self-service capabilities are enabled or disabled.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public RegisterWorkspaceDirectoryRequest withEnableSelfService(Boolean enableSelfService) {
        setEnableSelfService(enableSelfService);
        return this;
    }

    /**
     * <p>
     * Indicates whether self-service capabilities are enabled or disabled.
     * </p>
     * 
     * @return Indicates whether self-service capabilities are enabled or disabled.
     */

    public Boolean isEnableSelfService() {
        return this.enableSelfService;
    }

    /**
     * <p>
     * Indicates whether your WorkSpace directory is dedicated or shared. To use Bring Your Own License (BYOL) images,
     * this value must be set to <code>DEDICATED</code> and your Amazon Web Services account must be enabled for BYOL.
     * If your account has not been enabled for BYOL, you will receive an InvalidParameterValuesException error. For
     * more information about BYOL images, see <a
     * href="https://docs.aws.amazon.com/workspaces/latest/adminguide/byol-windows-images.html">Bring Your Own Windows
     * Desktop Images</a>.
     * </p>
     * 
     * @param tenancy
     *        Indicates whether your WorkSpace directory is dedicated or shared. To use Bring Your Own License (BYOL)
     *        images, this value must be set to <code>DEDICATED</code> and your Amazon Web Services account must be
     *        enabled for BYOL. If your account has not been enabled for BYOL, you will receive an
     *        InvalidParameterValuesException error. For more information about BYOL images, see <a
     *        href="https://docs.aws.amazon.com/workspaces/latest/adminguide/byol-windows-images.html">Bring Your Own
     *        Windows Desktop Images</a>.
     * @see Tenancy
     */

    public void setTenancy(String tenancy) {
        this.tenancy = tenancy;
    }

    /**
     * <p>
     * Indicates whether your WorkSpace directory is dedicated or shared. To use Bring Your Own License (BYOL) images,
     * this value must be set to <code>DEDICATED</code> and your Amazon Web Services account must be enabled for BYOL.
     * If your account has not been enabled for BYOL, you will receive an InvalidParameterValuesException error. For
     * more information about BYOL images, see <a
     * href="https://docs.aws.amazon.com/workspaces/latest/adminguide/byol-windows-images.html">Bring Your Own Windows
     * Desktop Images</a>.
     * </p>
     * 
     * @return Indicates whether your WorkSpace directory is dedicated or shared. To use Bring Your Own License (BYOL)
     *         images, this value must be set to <code>DEDICATED</code> and your Amazon Web Services account must be
     *         enabled for BYOL. If your account has not been enabled for BYOL, you will receive an
     *         InvalidParameterValuesException error. For more information about BYOL images, see <a
     *         href="https://docs.aws.amazon.com/workspaces/latest/adminguide/byol-windows-images.html">Bring Your Own
     *         Windows Desktop Images</a>.
     * @see Tenancy
     */

    public String getTenancy() {
        return this.tenancy;
    }

    /**
     * <p>
     * Indicates whether your WorkSpace directory is dedicated or shared. To use Bring Your Own License (BYOL) images,
     * this value must be set to <code>DEDICATED</code> and your Amazon Web Services account must be enabled for BYOL.
     * If your account has not been enabled for BYOL, you will receive an InvalidParameterValuesException error. For
     * more information about BYOL images, see <a
     * href="https://docs.aws.amazon.com/workspaces/latest/adminguide/byol-windows-images.html">Bring Your Own Windows
     * Desktop Images</a>.
     * </p>
     * 
     * @param tenancy
     *        Indicates whether your WorkSpace directory is dedicated or shared. To use Bring Your Own License (BYOL)
     *        images, this value must be set to <code>DEDICATED</code> and your Amazon Web Services account must be
     *        enabled for BYOL. If your account has not been enabled for BYOL, you will receive an
     *        InvalidParameterValuesException error. For more information about BYOL images, see <a
     *        href="https://docs.aws.amazon.com/workspaces/latest/adminguide/byol-windows-images.html">Bring Your Own
     *        Windows Desktop Images</a>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see Tenancy
     */

    public RegisterWorkspaceDirectoryRequest withTenancy(String tenancy) {
        setTenancy(tenancy);
        return this;
    }

    /**
     * <p>
     * Indicates whether your WorkSpace directory is dedicated or shared. To use Bring Your Own License (BYOL) images,
     * this value must be set to <code>DEDICATED</code> and your Amazon Web Services account must be enabled for BYOL.
     * If your account has not been enabled for BYOL, you will receive an InvalidParameterValuesException error. For
     * more information about BYOL images, see <a
     * href="https://docs.aws.amazon.com/workspaces/latest/adminguide/byol-windows-images.html">Bring Your Own Windows
     * Desktop Images</a>.
     * </p>
     * 
     * @param tenancy
     *        Indicates whether your WorkSpace directory is dedicated or shared. To use Bring Your Own License (BYOL)
     *        images, this value must be set to <code>DEDICATED</code> and your Amazon Web Services account must be
     *        enabled for BYOL. If your account has not been enabled for BYOL, you will receive an
     *        InvalidParameterValuesException error. For more information about BYOL images, see <a
     *        href="https://docs.aws.amazon.com/workspaces/latest/adminguide/byol-windows-images.html">Bring Your Own
     *        Windows Desktop Images</a>.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see Tenancy
     */

    public RegisterWorkspaceDirectoryRequest withTenancy(Tenancy tenancy) {
        this.tenancy = tenancy.toString();
        return this;
    }

    /**
     * <p>
     * The tags associated with the directory.
     * </p>
     * 
     * @return The tags associated with the directory.
     */

    public java.util.List<Tag> getTags() {
        if (tags == null) {
            tags = new com.amazonaws.internal.SdkInternalList<Tag>();
        }
        return tags;
    }

    /**
     * <p>
     * The tags associated with the directory.
     * </p>
     * 
     * @param tags
     *        The tags associated with the directory.
     */

    public void setTags(java.util.Collection<Tag> tags) {
        if (tags == null) {
            this.tags = null;
            return;
        }

        this.tags = new com.amazonaws.internal.SdkInternalList<Tag>(tags);
    }

    /**
     * <p>
     * The tags associated with the directory.
     * </p>
     * <p>
     * <b>NOTE:</b> This method appends the values to the existing list (if any). Use
     * {@link #setTags(java.util.Collection)} or {@link #withTags(java.util.Collection)} if you want to override the
     * existing values.
     * </p>
     * 
     * @param tags
     *        The tags associated with the directory.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public RegisterWorkspaceDirectoryRequest withTags(Tag... tags) {
        if (this.tags == null) {
            setTags(new com.amazonaws.internal.SdkInternalList<Tag>(tags.length));
        }
        for (Tag ele : tags) {
            this.tags.add(ele);
        }
        return this;
    }

    /**
     * <p>
     * The tags associated with the directory.
     * </p>
     * 
     * @param tags
     *        The tags associated with the directory.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public RegisterWorkspaceDirectoryRequest withTags(java.util.Collection<Tag> tags) {
        setTags(tags);
        return this;
    }

    /**
     * <p>
     * The name of the directory to register.
     * </p>
     * 
     * @param workspaceDirectoryName
     *        The name of the directory to register.
     */

    public void setWorkspaceDirectoryName(String workspaceDirectoryName) {
        this.workspaceDirectoryName = workspaceDirectoryName;
    }

    /**
     * <p>
     * The name of the directory to register.
     * </p>
     * 
     * @return The name of the directory to register.
     */

    public String getWorkspaceDirectoryName() {
        return this.workspaceDirectoryName;
    }

    /**
     * <p>
     * The name of the directory to register.
     * </p>
     * 
     * @param workspaceDirectoryName
     *        The name of the directory to register.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public RegisterWorkspaceDirectoryRequest withWorkspaceDirectoryName(String workspaceDirectoryName) {
        setWorkspaceDirectoryName(workspaceDirectoryName);
        return this;
    }

    /**
     * <p>
     * Description of the directory to register.
     * </p>
     * 
     * @param workspaceDirectoryDescription
     *        Description of the directory to register.
     */

    public void setWorkspaceDirectoryDescription(String workspaceDirectoryDescription) {
        this.workspaceDirectoryDescription = workspaceDirectoryDescription;
    }

    /**
     * <p>
     * Description of the directory to register.
     * </p>
     * 
     * @return Description of the directory to register.
     */

    public String getWorkspaceDirectoryDescription() {
        return this.workspaceDirectoryDescription;
    }

    /**
     * <p>
     * Description of the directory to register.
     * </p>
     * 
     * @param workspaceDirectoryDescription
     *        Description of the directory to register.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public RegisterWorkspaceDirectoryRequest withWorkspaceDirectoryDescription(String workspaceDirectoryDescription) {
        setWorkspaceDirectoryDescription(workspaceDirectoryDescription);
        return this;
    }

    /**
     * <p>
     * The type of identity management the user is using.
     * </p>
     * 
     * @param userIdentityType
     *        The type of identity management the user is using.
     * @see UserIdentityType
     */

    public void setUserIdentityType(String userIdentityType) {
        this.userIdentityType = userIdentityType;
    }

    /**
     * <p>
     * The type of identity management the user is using.
     * </p>
     * 
     * @return The type of identity management the user is using.
     * @see UserIdentityType
     */

    public String getUserIdentityType() {
        return this.userIdentityType;
    }

    /**
     * <p>
     * The type of identity management the user is using.
     * </p>
     * 
     * @param userIdentityType
     *        The type of identity management the user is using.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see UserIdentityType
     */

    public RegisterWorkspaceDirectoryRequest withUserIdentityType(String userIdentityType) {
        setUserIdentityType(userIdentityType);
        return this;
    }

    /**
     * <p>
     * The type of identity management the user is using.
     * </p>
     * 
     * @param userIdentityType
     *        The type of identity management the user is using.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see UserIdentityType
     */

    public RegisterWorkspaceDirectoryRequest withUserIdentityType(UserIdentityType userIdentityType) {
        this.userIdentityType = userIdentityType.toString();
        return this;
    }

    /**
     * <p>
     * Indicates whether the directory's WorkSpace type is personal or pools.
     * </p>
     * 
     * @param workspaceType
     *        Indicates whether the directory's WorkSpace type is personal or pools.
     * @see WorkspaceType
     */

    public void setWorkspaceType(String workspaceType) {
        this.workspaceType = workspaceType;
    }

    /**
     * <p>
     * Indicates whether the directory's WorkSpace type is personal or pools.
     * </p>
     * 
     * @return Indicates whether the directory's WorkSpace type is personal or pools.
     * @see WorkspaceType
     */

    public String getWorkspaceType() {
        return this.workspaceType;
    }

    /**
     * <p>
     * Indicates whether the directory's WorkSpace type is personal or pools.
     * </p>
     * 
     * @param workspaceType
     *        Indicates whether the directory's WorkSpace type is personal or pools.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see WorkspaceType
     */

    public RegisterWorkspaceDirectoryRequest withWorkspaceType(String workspaceType) {
        setWorkspaceType(workspaceType);
        return this;
    }

    /**
     * <p>
     * Indicates whether the directory's WorkSpace type is personal or pools.
     * </p>
     * 
     * @param workspaceType
     *        Indicates whether the directory's WorkSpace type is personal or pools.
     * @return Returns a reference to this object so that method calls can be chained together.
     * @see WorkspaceType
     */

    public RegisterWorkspaceDirectoryRequest withWorkspaceType(WorkspaceType workspaceType) {
        this.workspaceType = workspaceType.toString();
        return this;
    }

    /**
     * <p>
     * The active directory config of the directory.
     * </p>
     * 
     * @param activeDirectoryConfig
     *        The active directory config of the directory.
     */

    public void setActiveDirectoryConfig(ActiveDirectoryConfig activeDirectoryConfig) {
        this.activeDirectoryConfig = activeDirectoryConfig;
    }

    /**
     * <p>
     * The active directory config of the directory.
     * </p>
     * 
     * @return The active directory config of the directory.
     */

    public ActiveDirectoryConfig getActiveDirectoryConfig() {
        return this.activeDirectoryConfig;
    }

    /**
     * <p>
     * The active directory config of the directory.
     * </p>
     * 
     * @param activeDirectoryConfig
     *        The active directory config of the directory.
     * @return Returns a reference to this object so that method calls can be chained together.
     */

    public RegisterWorkspaceDirectoryRequest withActiveDirectoryConfig(ActiveDirectoryConfig activeDirectoryConfig) {
        setActiveDirectoryConfig(activeDirectoryConfig);
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
        if (getDirectoryId() != null)
            sb.append("DirectoryId: ").append(getDirectoryId()).append(",");
        if (getSubnetIds() != null)
            sb.append("SubnetIds: ").append(getSubnetIds()).append(",");
        if (getEnableWorkDocs() != null)
            sb.append("EnableWorkDocs: ").append(getEnableWorkDocs()).append(",");
        if (getEnableSelfService() != null)
            sb.append("EnableSelfService: ").append(getEnableSelfService()).append(",");
        if (getTenancy() != null)
            sb.append("Tenancy: ").append(getTenancy()).append(",");
        if (getTags() != null)
            sb.append("Tags: ").append(getTags()).append(",");
        if (getWorkspaceDirectoryName() != null)
            sb.append("WorkspaceDirectoryName: ").append(getWorkspaceDirectoryName()).append(",");
        if (getWorkspaceDirectoryDescription() != null)
            sb.append("WorkspaceDirectoryDescription: ").append(getWorkspaceDirectoryDescription()).append(",");
        if (getUserIdentityType() != null)
            sb.append("UserIdentityType: ").append(getUserIdentityType()).append(",");
        if (getWorkspaceType() != null)
            sb.append("WorkspaceType: ").append(getWorkspaceType()).append(",");
        if (getActiveDirectoryConfig() != null)
            sb.append("ActiveDirectoryConfig: ").append(getActiveDirectoryConfig());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;

        if (obj instanceof RegisterWorkspaceDirectoryRequest == false)
            return false;
        RegisterWorkspaceDirectoryRequest other = (RegisterWorkspaceDirectoryRequest) obj;
        if (other.getDirectoryId() == null ^ this.getDirectoryId() == null)
            return false;
        if (other.getDirectoryId() != null && other.getDirectoryId().equals(this.getDirectoryId()) == false)
            return false;
        if (other.getSubnetIds() == null ^ this.getSubnetIds() == null)
            return false;
        if (other.getSubnetIds() != null && other.getSubnetIds().equals(this.getSubnetIds()) == false)
            return false;
        if (other.getEnableWorkDocs() == null ^ this.getEnableWorkDocs() == null)
            return false;
        if (other.getEnableWorkDocs() != null && other.getEnableWorkDocs().equals(this.getEnableWorkDocs()) == false)
            return false;
        if (other.getEnableSelfService() == null ^ this.getEnableSelfService() == null)
            return false;
        if (other.getEnableSelfService() != null && other.getEnableSelfService().equals(this.getEnableSelfService()) == false)
            return false;
        if (other.getTenancy() == null ^ this.getTenancy() == null)
            return false;
        if (other.getTenancy() != null && other.getTenancy().equals(this.getTenancy()) == false)
            return false;
        if (other.getTags() == null ^ this.getTags() == null)
            return false;
        if (other.getTags() != null && other.getTags().equals(this.getTags()) == false)
            return false;
        if (other.getWorkspaceDirectoryName() == null ^ this.getWorkspaceDirectoryName() == null)
            return false;
        if (other.getWorkspaceDirectoryName() != null && other.getWorkspaceDirectoryName().equals(this.getWorkspaceDirectoryName()) == false)
            return false;
        if (other.getWorkspaceDirectoryDescription() == null ^ this.getWorkspaceDirectoryDescription() == null)
            return false;
        if (other.getWorkspaceDirectoryDescription() != null
                && other.getWorkspaceDirectoryDescription().equals(this.getWorkspaceDirectoryDescription()) == false)
            return false;
        if (other.getUserIdentityType() == null ^ this.getUserIdentityType() == null)
            return false;
        if (other.getUserIdentityType() != null && other.getUserIdentityType().equals(this.getUserIdentityType()) == false)
            return false;
        if (other.getWorkspaceType() == null ^ this.getWorkspaceType() == null)
            return false;
        if (other.getWorkspaceType() != null && other.getWorkspaceType().equals(this.getWorkspaceType()) == false)
            return false;
        if (other.getActiveDirectoryConfig() == null ^ this.getActiveDirectoryConfig() == null)
            return false;
        if (other.getActiveDirectoryConfig() != null && other.getActiveDirectoryConfig().equals(this.getActiveDirectoryConfig()) == false)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int hashCode = 1;

        hashCode = prime * hashCode + ((getDirectoryId() == null) ? 0 : getDirectoryId().hashCode());
        hashCode = prime * hashCode + ((getSubnetIds() == null) ? 0 : getSubnetIds().hashCode());
        hashCode = prime * hashCode + ((getEnableWorkDocs() == null) ? 0 : getEnableWorkDocs().hashCode());
        hashCode = prime * hashCode + ((getEnableSelfService() == null) ? 0 : getEnableSelfService().hashCode());
        hashCode = prime * hashCode + ((getTenancy() == null) ? 0 : getTenancy().hashCode());
        hashCode = prime * hashCode + ((getTags() == null) ? 0 : getTags().hashCode());
        hashCode = prime * hashCode + ((getWorkspaceDirectoryName() == null) ? 0 : getWorkspaceDirectoryName().hashCode());
        hashCode = prime * hashCode + ((getWorkspaceDirectoryDescription() == null) ? 0 : getWorkspaceDirectoryDescription().hashCode());
        hashCode = prime * hashCode + ((getUserIdentityType() == null) ? 0 : getUserIdentityType().hashCode());
        hashCode = prime * hashCode + ((getWorkspaceType() == null) ? 0 : getWorkspaceType().hashCode());
        hashCode = prime * hashCode + ((getActiveDirectoryConfig() == null) ? 0 : getActiveDirectoryConfig().hashCode());
        return hashCode;
    }

    @Override
    public RegisterWorkspaceDirectoryRequest clone() {
        return (RegisterWorkspaceDirectoryRequest) super.clone();
    }

}
