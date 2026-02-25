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
package com.amazonaws.services.taxsettings;

import javax.annotation.Generated;

import com.amazonaws.*;
import com.amazonaws.regions.*;

import com.amazonaws.services.taxsettings.model.*;

/**
 * Interface for accessing Tax Settings.
 * <p>
 * <b>Note:</b> Do not directly implement this interface, new methods are added to it regularly. Extend from
 * {@link com.amazonaws.services.taxsettings.AbstractAWSTaxSettings} instead.
 * </p>
 * <p>
 * <p>
 * You can use the tax setting API to programmatically set, modify, and delete the tax registration number (TRN),
 * associated business legal name, and address (Collectively referred to as "TRN information"). You can also
 * programmatically view TRN information and tax addresses ("Tax profiles").
 * </p>
 * <p>
 * You can use this API to automate your TRN information settings instead of manually using the console.
 * </p>
 * <p>
 * Service Endpoint
 * </p>
 * <ul>
 * <li>
 * <p>
 * https://tax.us-east-1.amazonaws.com
 * </p>
 * </li>
 * </ul>
 */
@Generated("com.amazonaws:aws-java-sdk-code-generator")
public interface AWSTaxSettings {

    /**
     * The region metadata service name for computing region endpoints. You can use this value to retrieve metadata
     * (such as supported regions) of the service.
     *
     * @see RegionUtils#getRegionsForService(String)
     */
    String ENDPOINT_PREFIX = "tax";

    /**
     * <p>
     * Deletes tax registration for multiple accounts in batch. This can be used to delete tax registrations for up to
     * five accounts in one batch.
     * </p>
     * <note>
     * <p>
     * This API operation can't be used to delete your tax registration in Brazil. Use the <a
     * href="https://console.aws.amazon.com/billing/home#/paymentpreferences/paymentmethods">Payment preferences</a>
     * page in the Billing and Cost Management console instead.
     * </p>
     * </note>
     * 
     * @param batchDeleteTaxRegistrationRequest
     * @return Result of the BatchDeleteTaxRegistration operation returned by the service.
     * @throws ValidationException
     *         The exception when the input doesn't pass validation for at least one of the input parameters.
     * @throws ConflictException
     *         The exception when the input is creating conflict with the given state.
     * @throws InternalServerException
     *         The exception thrown when an unexpected error occurs when processing a request.
     * @sample AWSTaxSettings.BatchDeleteTaxRegistration
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/BatchDeleteTaxRegistration"
     *      target="_top">AWS API Documentation</a>
     */
    BatchDeleteTaxRegistrationResult batchDeleteTaxRegistration(BatchDeleteTaxRegistrationRequest batchDeleteTaxRegistrationRequest);

    /**
     * <p>
     * Adds or updates tax registration for multiple accounts in batch. This can be used to add or update tax
     * registrations for up to five accounts in one batch. You can't set a TRN if there's a pending TRN. You'll need to
     * delete the pending TRN first.
     * </p>
     * <p>
     * To call this API operation for specific countries, see the following country-specific requirements.
     * </p>
     * <p>
     * <b>Bangladesh</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * You must specify the tax registration certificate document in the <code>taxRegistrationDocuments</code> field of
     * the <code>VerificationDetails</code> object.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Brazil</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * You must complete the tax registration process in the <a
     * href="https://console.aws.amazon.com/billing/home#/paymentpreferences/paymentmethods">Payment preferences</a>
     * page in the Billing and Cost Management console. After your TRN and billing address are verified, you can call
     * this API operation.
     * </p>
     * </li>
     * <li>
     * <p>
     * For Amazon Web Services accounts created through Organizations, you can call this API operation when you don't
     * have a billing address.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Georgia</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * The valid <code>personType</code> values are <code>Physical Person</code> and <code>Business</code>.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Kenya</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * You must specify the <code>personType</code> in the <code>kenyaAdditionalInfo</code> field of the
     * <code>additionalTaxInformation</code> object.
     * </p>
     * </li>
     * <li>
     * <p>
     * If the <code>personType</code> is <code>Physical Person</code>, you must specify the tax registration certificate
     * document in the <code>taxRegistrationDocuments</code> field of the <code>VerificationDetails</code> object.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Malaysia</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * If you use this operation to set a tax registration number (TRN) in Malaysia, only resellers with a valid sales
     * and service tax (SST) number are required to provide tax registration information.
     * </p>
     * </li>
     * <li>
     * <p>
     * By using this API operation to set a TRN in Malaysia, Amazon Web Services will regard you as self-declaring that
     * you're an authorized business reseller registered with the Royal Malaysia Customs Department (RMCD) and have a
     * valid SST number.
     * </p>
     * </li>
     * <li>
     * <p>
     * Amazon Web Services reserves the right to seek additional information and/or take other actions to support your
     * self-declaration as appropriate.
     * </p>
     * </li>
     * <li>
     * <p>
     * If you're not a reseller of Amazon Web Services, we don't recommend that you use this operation to set the TRN in
     * Malaysia.
     * </p>
     * </li>
     * <li>
     * <p>
     * Only use this API operation to upload the TRNs for accounts through which you're reselling Amazon Web Services.
     * </p>
     * </li>
     * <li>
     * <p>
     * Amazon Web Services is currently registered under the following service tax codes. You must include at least one
     * of the service tax codes in the service tax code strings to declare yourself as an authorized registered business
     * reseller.
     * </p>
     * <p>
     * Taxable service and service tax codes:
     * </p>
     * <p>
     * Consultancy - 9907061674
     * </p>
     * <p>
     * Training or coaching service - 9907071685
     * </p>
     * <p>
     * IT service - 9907101676
     * </p>
     * <p>
     * Digital services and electronic medium - 9907121690
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Nepal</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * The sector valid values are <code>Business</code> and <code>Individual</code>.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Saudi Arabia</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * For <code>address</code>, you must specify <code>addressLine3</code>.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>South Korea</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * You must specify the <code>certifiedEmailId</code> and <code>legalName</code> in the
     * <code>TaxRegistrationEntry</code> object. Use Korean characters for <code>legalName</code>.
     * </p>
     * </li>
     * <li>
     * <p>
     * You must specify the <code>businessRepresentativeName</code>, <code>itemOfBusiness</code>, and
     * <code>lineOfBusiness</code> in the <code>southKoreaAdditionalInfo</code> field of the
     * <code>additionalTaxInformation</code> object. Use Korean characters for these fields.
     * </p>
     * </li>
     * <li>
     * <p>
     * You must specify the tax registration certificate document in the <code>taxRegistrationDocuments</code> field of
     * the <code>VerificationDetails</code> object.
     * </p>
     * </li>
     * <li>
     * <p>
     * For the <code>address</code> object, use Korean characters for <code>addressLine1</code>,
     * <code>addressLine2</code> <code>city</code>, <code>postalCode</code>, and <code>stateOrRegion</code>.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Spain</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * You must specify the <code>registrationType</code> in the <code>spainAdditionalInfo</code> field of the
     * <code>additionalTaxInformation</code> object.
     * </p>
     * </li>
     * <li>
     * <p>
     * If the <code>registrationType</code> is <code>Local</code>, you must specify the tax registration certificate
     * document in the <code>taxRegistrationDocuments</code> field of the <code>VerificationDetails</code> object.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Turkey</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * You must specify the <code>sector</code> in the <code>taxRegistrationEntry</code> object.
     * </p>
     * </li>
     * <li>
     * <p>
     * If your <code>sector</code> is <code>Business</code>, <code>Individual</code>, or <code>Government</code>:
     * </p>
     * <ul>
     * <li>
     * <p>
     * Specify the <code>taxOffice</code>. If your <code>sector</code> is <code>Individual</code>, don't enter this
     * value.
     * </p>
     * </li>
     * <li>
     * <p>
     * (Optional) Specify the <code>kepEmailId</code>. If your <code>sector</code> is <code>Individual</code>, don't
     * enter this value.
     * </p>
     * </li>
     * <li>
     * <p>
     * <b>Note:</b> In the <b>Tax Settings</b> page of the Billing console, <code>Government</code> appears as <b>Public
     * institutions</b>
     * </p>
     * </li>
     * </ul>
     * </li>
     * <li>
     * <p>
     * If your <code>sector</code> is <code>Business</code> and you're subject to KDV tax, you must specify your
     * industry in the <code>industries</code> field.
     * </p>
     * </li>
     * <li>
     * <p>
     * For <code>address</code>, you must specify <code>districtOrCounty</code>.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Ukraine</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * The sector valid values are <code>Business</code> and <code>Individual</code>.
     * </p>
     * </li>
     * </ul>
     * 
     * @param batchPutTaxRegistrationRequest
     * @return Result of the BatchPutTaxRegistration operation returned by the service.
     * @throws ValidationException
     *         The exception when the input doesn't pass validation for at least one of the input parameters.
     * @throws ConflictException
     *         The exception when the input is creating conflict with the given state.
     * @throws InternalServerException
     *         The exception thrown when an unexpected error occurs when processing a request.
     * @sample AWSTaxSettings.BatchPutTaxRegistration
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/BatchPutTaxRegistration"
     *      target="_top">AWS API Documentation</a>
     */
    BatchPutTaxRegistrationResult batchPutTaxRegistration(BatchPutTaxRegistrationRequest batchPutTaxRegistrationRequest);

    /**
     * <p>
     * Deletes tax registration for a single account.
     * </p>
     * <note>
     * <p>
     * This API operation can't be used to delete your tax registration in Brazil. Use the <a
     * href="https://console.aws.amazon.com/billing/home#/paymentpreferences/paymentmethods">Payment preferences</a>
     * page in the Billing and Cost Management console instead.
     * </p>
     * </note>
     * 
     * @param deleteTaxRegistrationRequest
     * @return Result of the DeleteTaxRegistration operation returned by the service.
     * @throws ValidationException
     *         The exception when the input doesn't pass validation for at least one of the input parameters.
     * @throws ConflictException
     *         The exception when the input is creating conflict with the given state.
     * @throws ResourceNotFoundException
     *         The exception thrown when the input doesn't have a resource associated to it.
     * @throws InternalServerException
     *         The exception thrown when an unexpected error occurs when processing a request.
     * @sample AWSTaxSettings.DeleteTaxRegistration
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/DeleteTaxRegistration"
     *      target="_top">AWS API Documentation</a>
     */
    DeleteTaxRegistrationResult deleteTaxRegistration(DeleteTaxRegistrationRequest deleteTaxRegistrationRequest);

    /**
     * <p>
     * Retrieves tax registration for a single account.
     * </p>
     * 
     * @param getTaxRegistrationRequest
     * @return Result of the GetTaxRegistration operation returned by the service.
     * @throws ValidationException
     *         The exception when the input doesn't pass validation for at least one of the input parameters.
     * @throws ResourceNotFoundException
     *         The exception thrown when the input doesn't have a resource associated to it.
     * @throws InternalServerException
     *         The exception thrown when an unexpected error occurs when processing a request.
     * @sample AWSTaxSettings.GetTaxRegistration
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/GetTaxRegistration" target="_top">AWS
     *      API Documentation</a>
     */
    GetTaxRegistrationResult getTaxRegistration(GetTaxRegistrationRequest getTaxRegistrationRequest);

    /**
     * <p>
     * Downloads your tax documents to the Amazon S3 bucket that you specify in your request.
     * </p>
     * 
     * @param getTaxRegistrationDocumentRequest
     * @return Result of the GetTaxRegistrationDocument operation returned by the service.
     * @throws ValidationException
     *         The exception when the input doesn't pass validation for at least one of the input parameters.
     * @throws InternalServerException
     *         The exception thrown when an unexpected error occurs when processing a request.
     * @sample AWSTaxSettings.GetTaxRegistrationDocument
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/GetTaxRegistrationDocument"
     *      target="_top">AWS API Documentation</a>
     */
    GetTaxRegistrationDocumentResult getTaxRegistrationDocument(GetTaxRegistrationDocumentRequest getTaxRegistrationDocumentRequest);

    /**
     * <p>
     * Retrieves the tax registration of accounts listed in a consolidated billing family. This can be used to retrieve
     * up to 100 accounts' tax registrations in one call (default 50).
     * </p>
     * 
     * @param listTaxRegistrationsRequest
     * @return Result of the ListTaxRegistrations operation returned by the service.
     * @throws ValidationException
     *         The exception when the input doesn't pass validation for at least one of the input parameters.
     * @throws ResourceNotFoundException
     *         The exception thrown when the input doesn't have a resource associated to it.
     * @throws InternalServerException
     *         The exception thrown when an unexpected error occurs when processing a request.
     * @sample AWSTaxSettings.ListTaxRegistrations
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/ListTaxRegistrations"
     *      target="_top">AWS API Documentation</a>
     */
    ListTaxRegistrationsResult listTaxRegistrations(ListTaxRegistrationsRequest listTaxRegistrationsRequest);

    /**
     * <p>
     * Adds or updates tax registration for a single account. You can't set a TRN if there's a pending TRN. You'll need
     * to delete the pending TRN first.
     * </p>
     * <p>
     * To call this API operation for specific countries, see the following country-specific requirements.
     * </p>
     * <p>
     * <b>Bangladesh</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * You must specify the tax registration certificate document in the <code>taxRegistrationDocuments</code> field of
     * the <code>VerificationDetails</code> object.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Brazil</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * You must complete the tax registration process in the <a
     * href="https://console.aws.amazon.com/billing/home#/paymentpreferences/paymentmethods">Payment preferences</a>
     * page in the Billing and Cost Management console. After your TRN and billing address are verified, you can call
     * this API operation.
     * </p>
     * </li>
     * <li>
     * <p>
     * For Amazon Web Services accounts created through Organizations, you can call this API operation when you don't
     * have a billing address.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Georgia</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * The valid <code>personType</code> values are <code>Physical Person</code> and <code>Business</code>.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Kenya</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * You must specify the <code>personType</code> in the <code>kenyaAdditionalInfo</code> field of the
     * <code>additionalTaxInformation</code> object.
     * </p>
     * </li>
     * <li>
     * <p>
     * If the <code>personType</code> is <code>Physical Person</code>, you must specify the tax registration certificate
     * document in the <code>taxRegistrationDocuments</code> field of the <code>VerificationDetails</code> object.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Malaysia</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * If you use this operation to set a tax registration number (TRN) in Malaysia, only resellers with a valid sales
     * and service tax (SST) number are required to provide tax registration information.
     * </p>
     * </li>
     * <li>
     * <p>
     * By using this API operation to set a TRN in Malaysia, Amazon Web Services will regard you as self-declaring that
     * you're an authorized business reseller registered with the Royal Malaysia Customs Department (RMCD) and have a
     * valid SST number.
     * </p>
     * </li>
     * <li>
     * <p>
     * Amazon Web Services reserves the right to seek additional information and/or take other actions to support your
     * self-declaration as appropriate.
     * </p>
     * </li>
     * <li>
     * <p>
     * If you're not a reseller of Amazon Web Services, we don't recommend that you use this operation to set the TRN in
     * Malaysia.
     * </p>
     * </li>
     * <li>
     * <p>
     * Only use this API operation to upload the TRNs for accounts through which you're reselling Amazon Web Services.
     * </p>
     * </li>
     * <li>
     * <p>
     * Amazon Web Services is currently registered under the following service tax codes. You must include at least one
     * of the service tax codes in the service tax code strings to declare yourself as an authorized registered business
     * reseller.
     * </p>
     * <p>
     * Taxable service and service tax codes:
     * </p>
     * <p>
     * Consultancy - 9907061674
     * </p>
     * <p>
     * Training or coaching service - 9907071685
     * </p>
     * <p>
     * IT service - 9907101676
     * </p>
     * <p>
     * Digital services and electronic medium - 9907121690
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Nepal</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * The sector valid values are <code>Business</code> and <code>Individual</code>.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Saudi Arabia</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * For <code>address</code>, you must specify <code>addressLine3</code>.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>South Korea</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * You must specify the <code>certifiedEmailId</code> and <code>legalName</code> in the
     * <code>TaxRegistrationEntry</code> object. Use Korean characters for <code>legalName</code>.
     * </p>
     * </li>
     * <li>
     * <p>
     * You must specify the <code>businessRepresentativeName</code>, <code>itemOfBusiness</code>, and
     * <code>lineOfBusiness</code> in the <code>southKoreaAdditionalInfo</code> field of the
     * <code>additionalTaxInformation</code> object. Use Korean characters for these fields.
     * </p>
     * </li>
     * <li>
     * <p>
     * You must specify the tax registration certificate document in the <code>taxRegistrationDocuments</code> field of
     * the <code>VerificationDetails</code> object.
     * </p>
     * </li>
     * <li>
     * <p>
     * For the <code>address</code> object, use Korean characters for <code>addressLine1</code>,
     * <code>addressLine2</code> <code>city</code>, <code>postalCode</code>, and <code>stateOrRegion</code>.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Spain</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * You must specify the <code>registrationType</code> in the <code>spainAdditionalInfo</code> field of the
     * <code>additionalTaxInformation</code> object.
     * </p>
     * </li>
     * <li>
     * <p>
     * If the <code>registrationType</code> is <code>Local</code>, you must specify the tax registration certificate
     * document in the <code>taxRegistrationDocuments</code> field of the <code>VerificationDetails</code> object.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Turkey</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * You must specify the <code>sector</code> in the <code>taxRegistrationEntry</code> object.
     * </p>
     * </li>
     * <li>
     * <p>
     * If your <code>sector</code> is <code>Business</code>, <code>Individual</code>, or <code>Government</code>:
     * </p>
     * <ul>
     * <li>
     * <p>
     * Specify the <code>taxOffice</code>. If your <code>sector</code> is <code>Individual</code>, don't enter this
     * value.
     * </p>
     * </li>
     * <li>
     * <p>
     * (Optional) Specify the <code>kepEmailId</code>. If your <code>sector</code> is <code>Individual</code>, don't
     * enter this value.
     * </p>
     * </li>
     * <li>
     * <p>
     * <b>Note:</b> In the <b>Tax Settings</b> page of the Billing console, <code>Government</code> appears as <b>Public
     * institutions</b>
     * </p>
     * </li>
     * </ul>
     * </li>
     * <li>
     * <p>
     * If your <code>sector</code> is <code>Business</code> and you're subject to KDV tax, you must specify your
     * industry in the <code>industries</code> field.
     * </p>
     * </li>
     * <li>
     * <p>
     * For <code>address</code>, you must specify <code>districtOrCounty</code>.
     * </p>
     * </li>
     * </ul>
     * <p>
     * <b>Ukraine</b>
     * </p>
     * <ul>
     * <li>
     * <p>
     * The sector valid values are <code>Business</code> and <code>Individual</code>.
     * </p>
     * </li>
     * </ul>
     * 
     * @param putTaxRegistrationRequest
     * @return Result of the PutTaxRegistration operation returned by the service.
     * @throws ValidationException
     *         The exception when the input doesn't pass validation for at least one of the input parameters.
     * @throws ConflictException
     *         The exception when the input is creating conflict with the given state.
     * @throws InternalServerException
     *         The exception thrown when an unexpected error occurs when processing a request.
     * @sample AWSTaxSettings.PutTaxRegistration
     * @see <a href="http://docs.aws.amazon.com/goto/WebAPI/taxsettings-2018-05-10/PutTaxRegistration" target="_top">AWS
     *      API Documentation</a>
     */
    PutTaxRegistrationResult putTaxRegistration(PutTaxRegistrationRequest putTaxRegistrationRequest);

    /**
     * Shuts down this client object, releasing any resources that might be held open. This is an optional method, and
     * callers are not expected to call it, but can if they want to explicitly release any open resources. Once a client
     * has been shutdown, it should not be used to make any more requests.
     */
    void shutdown();

    /**
     * Returns additional metadata for a previously executed successful request, typically used for debugging issues
     * where a service isn't acting as expected. This data isn't considered part of the result data returned by an
     * operation, so it's available through this separate, diagnostic interface.
     * <p>
     * Response metadata is only cached for a limited period of time, so if you need to access this extra diagnostic
     * information for an executed request, you should use this method to retrieve it as soon as possible after
     * executing a request.
     *
     * @param request
     *        The originally executed request.
     *
     * @return The response metadata for the specified request, or null if none is available.
     */
    ResponseMetadata getCachedResponseMetadata(AmazonWebServiceRequest request);

}
