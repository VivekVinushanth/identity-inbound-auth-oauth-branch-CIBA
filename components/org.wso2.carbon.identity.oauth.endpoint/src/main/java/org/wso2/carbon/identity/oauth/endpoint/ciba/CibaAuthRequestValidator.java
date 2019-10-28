/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.endpoint.ciba;


import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.xpath.operations.Bool;
import org.wso2.carbon.identity.oauth.ciba.common.CibaParams;
import org.wso2.carbon.identity.oauth.ciba.dto.AuthResponseContextDTO;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthRequestDTO;
import org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes;
import org.wso2.carbon.identity.oauth.ciba.util.AuthReqIDManager;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.user.api.UserStoreException;

import java.io.IOException;
import java.text.ParseException;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.concurrent.ExecutionException;
import javax.servlet.http.HttpServletResponse;


/**
 *
 *This class handles the validation of ciba authentication request.
 *
 * */
public class CibaAuthRequestValidator {


    private boolean  isValid;
    private boolean isValidClient;
    private static final String VALID_ID_TOKEN_ISSUER = "https://localhost:9443/oauth2/token";

    private static final Log log = LogFactory.getLog(CibaAuthRequestValidator.class);
    private CibaAuthRequestValidator() {

    }

    private static CibaAuthRequestValidator cibaAuthRequestValidatorInstance = new CibaAuthRequestValidator();

    public static CibaAuthRequestValidator getInstance() {
        if (cibaAuthRequestValidatorInstance == null) {

            synchronized (CibaAuthRequestValidator.class) {

                if (cibaAuthRequestValidatorInstance == null) {

                    /* instance will be created at request time */
                    cibaAuthRequestValidatorInstance = new CibaAuthRequestValidator();
                }
            }
        }
        return cibaAuthRequestValidatorInstance;


    }

    /**
     * This method create CIBA Authentication Error Response.
     * @param authResponseContextDTO CIBA AuthenticationResponseContext that accumulates error codes,error,description
     * @param request CIBA Authentication Request
     * @param cibaAuthRequestDTO DTO that is to capture validated parameters
     * @return Boolean
     * @throws ExecutionException,IOException
     */
    public Boolean isValidAuthRequest(String request, AuthResponseContextDTO authResponseContextDTO,
                                      CibaAuthRequestDTO cibaAuthRequestDTO) throws OAuthSystemException {
        try {

        long currentTime = ZonedDateTime.now().toInstant().toEpochMilli();
        long skewTime = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
        SignedJWT signedJWT = SignedJWT.parse(request);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        JSONObject authRequestAsJSON = null;

            authRequestAsJSON = signedJWT.getJWTClaimsSet().toJSONObject();



        if (!this.isValidSignature(signedJWT)) {
            //Signature is invalid.
            authResponseContextDTO.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            authResponseContextDTO.setError(ErrorCodes.UNAUTHORIZED_CLIENT);
            authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.INVALID_SIGNATURE);
            return false;

        } else {

            //Validation for aud-audience.
            if (isValidAudience(claimsSet, authResponseContextDTO, cibaAuthRequestDTO).equals(false)) {
                // Invalid audience.
                return false;

            } else if (isValidJWTID(claimsSet, authResponseContextDTO, cibaAuthRequestDTO).equals(false)) {
                //Invalid JWT-ID.
                return false;

            } else if (isValidExpiryTime(claimsSet, authResponseContextDTO, cibaAuthRequestDTO, currentTime, skewTime)
                    .equals(false)) {
                //Invalid expiry time.
                return false;

            } else if (isvalidIssuedTime(claimsSet, authResponseContextDTO, cibaAuthRequestDTO, currentTime)
            .equals(false)) {
                //Invalid issuedTime.
                return false;

            } else if (isValidNBF(claimsSet, authResponseContextDTO, cibaAuthRequestDTO, currentTime, skewTime)
                .equals(false)) {
                //Invalid NBF.
                return false;

            } else if (isValidScope(authRequestAsJSON, authResponseContextDTO, cibaAuthRequestDTO).equals(false)) {
                //Invalid Scope values.
                return false;

            } else if (isValidClientNotificationToken(authRequestAsJSON, authResponseContextDTO, cibaAuthRequestDTO)
            .equals(false)) {
                //Invalid client_notification_token.
                return false;

            } else if (isValidACRValues(authRequestAsJSON, authResponseContextDTO, cibaAuthRequestDTO).equals(false)) {
                //Invalid ACR values.
                return false;

            } else if (isValidUserCode(authRequestAsJSON, authResponseContextDTO, cibaAuthRequestDTO).equals(false)) {
                //Invalid user_code  values.
                return false;

            } else if (isvalidBindingMessage(authRequestAsJSON, authResponseContextDTO, cibaAuthRequestDTO).equals(false)) {
                //Invalid binding_message values.
                return false;

            }  else if (isValidTransactionContext(authRequestAsJSON, authResponseContextDTO, cibaAuthRequestDTO).equals(false)) {
                //Invalid transaction_context values.
                return false;


            } else if (isValidRequestedExpiry(authRequestAsJSON, authResponseContextDTO, cibaAuthRequestDTO).equals(false)) {
                //Invalid requested_expiry value.
                return false;

            } else {
                      isValid = true;
                if (log.isDebugEnabled()) {
                    log.debug(" CIBA Authentication Request made by client with clientID : " +
                            cibaAuthRequestDTO.getAudience() + "is properly validated.");
                }

                authResponseContextDTO.setStatus(HttpServletResponse.SC_OK);
                return isValid;
            }

        }
        } catch (ParseException e) {
            authResponseContextDTO.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            authResponseContextDTO.setError(ErrorCodes.INTERNAL_SERVER_ERROR);
            authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.UNEXPECTED_SERVER_ERROR + e.getMessage());
            return false;
        }
    }





    /**
     * This method checks whether the requested_expiry values exists and is valid.
     *
     * @param authRequestAsJSON CIBA Authentication request as JSON
     * @param cibaAuthRequestDTO DTO that captures valid - authentication request params
     * @param authResponseContextDTO DTO to capture authentication response context
     * @return requested_expiry of JWT is valid or not.
     */
    private Boolean isValidRequestedExpiry(JSONObject authRequestAsJSON, AuthResponseContextDTO authResponseContextDTO,
                                           CibaAuthRequestDTO cibaAuthRequestDTO) {

        //Validation for requested_expiry

        boolean isValidRequestedExpiry;

        if ((authRequestAsJSON.get(CibaParams.REQUESTED_EXPIRY)) == null) {
            //requested_expiry value doesnt exists- is acceptable.

            isValidRequestedExpiry = true;

        } else {
            if (StringUtils.isBlank(authRequestAsJSON.get(CibaParams.REQUESTED_EXPIRY).toString())) {
                //Requested expiry is a blank value.
                if (log.isDebugEnabled()) {
                    log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                            cibaAuthRequestDTO.getAudience() + ".The request is with invalid  value for 'requested_expiry'.");
                }
                authResponseContextDTO.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                authResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
                authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);
                return false;

            } else {
                String requestedExpiryAsString = String.valueOf(authRequestAsJSON.get(CibaParams.REQUESTED_EXPIRY));
                long requestedExpiry = Long.parseLong(requestedExpiryAsString);

                if (requestedExpiry < CibaParams.MAXIMUM_REQUESTED_EXPIRY) {
                    cibaAuthRequestDTO.setRequestedExpiry(requestedExpiry);
                    isValidRequestedExpiry = true;
                } else {
                    cibaAuthRequestDTO.setRequestedExpiry(CibaParams.MAXIMUM_REQUESTED_EXPIRY);
                    isValidRequestedExpiry = true;
                    if (log.isDebugEnabled()) {
                        log.debug("Warning. CIBA Authentication Request made by client with clientID : " +
                                cibaAuthRequestDTO.getAudience() + ".Requested expiry is too long.Setting the maximum default value.");
                    }


                }
            }
        }
        return isValidRequestedExpiry;
    }





    /**
     * This method checks whether the transaction_context values exists and is valid.
     *
     * @param authRequestAsJSON CIBA Authentication request as JSON
     * @param cibaAuthRequestDTO DTO that captures valid - authentication request params
     * @param authResponseContextDTO DTO to capture authentication response context
     * @return transaction_context of JWT is valid or not.
     */
    private Boolean isValidTransactionContext(JSONObject authRequestAsJSON, AuthResponseContextDTO
            authResponseContextDTO, CibaAuthRequestDTO cibaAuthRequestDTO) {

        //Validation for transaction_context.

        boolean isValidTransactionContext ;
        if ((authRequestAsJSON.get(CibaParams.TRANSACTION_CONTEXT)) == null) {
            //Request has no transaction_context claim.
            isValidTransactionContext = true;

        } else {
            if (StringUtils.isBlank(authRequestAsJSON.get(CibaParams.TRANSACTION_CONTEXT).toString())) {
                if (log.isDebugEnabled()) {
                    log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                            cibaAuthRequestDTO.getAudience() + ".The request is with invalid  value for 'transaction_context'.");
                }
                authResponseContextDTO.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                authResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
                authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);

                return false;


            } else {
                cibaAuthRequestDTO.setTransactionContext(String.valueOf(authRequestAsJSON.get(CibaParams.TRANSACTION_CONTEXT)));
                isValidTransactionContext = true;

            }
        }
        return isValidTransactionContext;
    }




    /**
     * This method checks whether the binding_message values exists and is valid.
     *
     * @param authRequestAsJSON CIBA Authentication request as JSON
     * @param cibaAuthRequestDTO DTO that captures valid - authentication request params
     * @param authResponseContextDTO DTO to capture authentication response context
     * @return binding_message of JWT is valid or not.
     */
    private Boolean isvalidBindingMessage(JSONObject authRequestAsJSON, AuthResponseContextDTO authResponseContextDTO,
                                          CibaAuthRequestDTO cibaAuthRequestDTO) {
        //Validation for binding_message.
        boolean isValidBindingMessage;

        if ((authRequestAsJSON.get(CibaParams.BINDING_MESSAGE)) == null) {
            //Request has no claim for binding_message.

            isValidBindingMessage = true;


        } else  {
            if (StringUtils.isBlank(authRequestAsJSON.get(CibaParams.BINDING_MESSAGE).toString())) {
                //Binding_message with a blank value which is not acceptable.


                if (log.isDebugEnabled()) {
                    log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                            cibaAuthRequestDTO.getAudience() + ".The request is with invalid  value for 'binding_message'.");
                }
                authResponseContextDTO.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                authResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
                authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);

                return false;


            } else {
                cibaAuthRequestDTO.setBindingMessage(String.valueOf(authRequestAsJSON.get(CibaParams.BINDING_MESSAGE)));
                isValidBindingMessage = true;

            }
        }
        return isValidBindingMessage;
    }






    /**
     * This method checks whether the user code values exists and is valid.
     *
     * @param authRequestAsJSON CIBA Authentication request as JSON
     * @param cibaAuthRequestDTO DTO that captures valid - authentication request params
     * @param authResponseContextDTO DTO to capture authentication response context
     * @return acr of JWT is valid or not.
     */

    private Boolean isValidUserCode(JSONObject authRequestAsJSON, AuthResponseContextDTO authResponseContextDTO,
                                    CibaAuthRequestDTO cibaAuthRequestDTO) {


        //Validation for usercode-values.

        boolean isValiduserCode;

        if ((authRequestAsJSON.get(CibaParams.USER_CODE)) == null) {
            //No claims for user_code.
            isValiduserCode = true;

        } else {
            if ((StringUtils.isBlank(authRequestAsJSON.get(CibaParams.USER_CODE).toString()))) {
                //user_code with blank values

                if (log.isDebugEnabled()) {
                    log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                            cibaAuthRequestDTO.getAudience() + ".The request is with invalid  value for 'user_code'.");
                }
                authResponseContextDTO.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                authResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
                authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);

                return false;
            } else {
                cibaAuthRequestDTO.setUserCode(String.valueOf(authRequestAsJSON.get(CibaParams.USER_CODE)));
                isValiduserCode = true;

            }
        }
        return isValiduserCode;
    }





    /**
     * This method checks whether the ACR values exists and is valid.
     *
     * @param authRequestAsJSON CIBA Authentication request as JSON
     * @param cibaAuthRequestDTO DTO that captures valid - authentication request params
     * @param authResponseContextDTO DTO to capture authentication response context
     * @return acr of JWT is valid or not.
     */
    private Boolean isValidACRValues(JSONObject authRequestAsJSON, AuthResponseContextDTO authResponseContextDTO,
                                     CibaAuthRequestDTO cibaAuthRequestDTO) {
        //Validation for acr-values.

        boolean isValidACR;
        if ((authRequestAsJSON.get(CibaParams.ACR_VALUES)) == null) {
            //No acr claim.
            isValidACR = true;

        } else {
            if (StringUtils.isBlank(authRequestAsJSON.get(CibaParams.ACR_VALUES).toString())) {
                //ACR claim with blank values.
                if (log.isDebugEnabled()) {
                    log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                            cibaAuthRequestDTO.getAudience() + ".The request is with invalid  value for 'acr'.");
                }
                authResponseContextDTO.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                authResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
                authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);

                return false;

            } else {
                cibaAuthRequestDTO.setAcrValues(String.valueOf(authRequestAsJSON.get(CibaParams.ACR_VALUES)));
                isValidACR = true;

            }
        }
        return isValidACR;

    }




    /**
     * This method checks whether the client_notification_token exists and is valid.
     *
     * @param authRequestAsJSON CIBA Authentication request as JSON
     * @param cibaAuthRequestDTO DTO that captures valid - authentication request params
     * @param authResponseContextDTO DTO to capture authentication response context
     * @return client_notification_token of JWT is valid or not.
     */
    private Boolean isValidClientNotificationToken(JSONObject authRequestAsJSON, AuthResponseContextDTO
            authResponseContextDTO, CibaAuthRequestDTO cibaAuthRequestDTO) {

        // Validation for client_notification_token.Mandatory parameter for CIBA Authentication Request for ping mode.

        boolean isValidClientNotificationToken;

        if (authRequestAsJSON.get(CibaParams.CLIENT_NOTIFICATION_TOKEN) == null) {
            // Client_notification_token does not exist - acceptable.

            isValidClientNotificationToken = true;

        } else {
            if (StringUtils.isBlank(authRequestAsJSON.get(CibaParams.CLIENT_NOTIFICATION_TOKEN).toString())) {
                // Blank values for client_notification_token.
                if (log.isDebugEnabled()) {
                    log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                            cibaAuthRequestDTO.getAudience() + ".The request is with invalid  value for 'client_notification_token'.");
                }
                authResponseContextDTO.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                authResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
                authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);
                return false;

            } else {
                cibaAuthRequestDTO.setClientNotificationToken(String.valueOf(authRequestAsJSON.
                        get(CibaParams.CLIENT_NOTIFICATION_TOKEN)));
                isValidClientNotificationToken = true;
            }
        }
             return isValidClientNotificationToken;
    }





    /**
     * This method checks whether the scope exists and is valid.
     *
     * @param authRequestAsJSON CIBA Authentication request as JSON
     * @param cibaAuthRequestDTO DTO that captures valid - authentication request params
     * @param authResponseContextDTO DTO to capture authentication response context
     * @return scope of JWT is valid or not.
     */
    private Boolean isValidScope(JSONObject authRequestAsJSON, AuthResponseContextDTO authResponseContextDTO,
                                 CibaAuthRequestDTO cibaAuthRequestDTO) {
        //Validation for scope.Mandatory parameter for CIBA AuthenticationRequest.

        boolean isValidScope;

        if (authRequestAsJSON.get(CibaParams.SCOPE) == null) {
            // Missing 'scope' claim in the request.
            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        cibaAuthRequestDTO.getAudience() + ".The request is missing the mandatory claim 'scope'.");
            }
            authResponseContextDTO.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            authResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
            authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.MISSING_PARAMETERS);
            return false;



        } else if (StringUtils.isBlank(String.valueOf(authRequestAsJSON.get(CibaParams.SCOPE)))) {
            // Scope is with blank value.

            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        cibaAuthRequestDTO.getAudience() + ".The request is with invalid  value for 'scope'.");
            }
            authResponseContextDTO.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            authResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
            authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);

            return false;
        } else  {
            cibaAuthRequestDTO.setScope(String.valueOf(authRequestAsJSON.get(CibaParams.SCOPE)));
            isValidScope = true;
        }

        return isValidScope;

    }





    /**
     * This method checks whether the JWT-NBF is valid.
     *
     * @param claimsSet CIBA Authentication request claimset
     * @param cibaAuthRequestDTO DTO that captures valid - authentication request params
     * @param authResponseContextDTO DTO to capture authentication response context
     * @return NBF of JWT is valid or not.
     */
    private Boolean isValidNBF(JWTClaimsSet claimsSet, AuthResponseContextDTO authResponseContextDTO,
                               CibaAuthRequestDTO cibaAuthRequestDTO, long currentTime, long skewTime) throws OAuthSystemException {
        // Validation for nbf-time before signed request is acceptable. Mandatory parameter if signed.

        boolean isValidNBF;
        if (claimsSet.getNotBeforeTime() == null) {

            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        cibaAuthRequestDTO.getAudience() + ".The request is missing the mandatory parameter 'nbf'.");
            }
            authResponseContextDTO.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            authResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
            authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.MISSING_PARAMETERS);
            return false;

        } else {

            long nbfTime = claimsSet.getNotBeforeTime().getTime();
            try {
                if (checkNotBeforeTime(currentTime, nbfTime, skewTime)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                                cibaAuthRequestDTO.getAudience() + ".The request is with invalid  value for 'nbf'.");
                    }
                    authResponseContextDTO.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    authResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
                    authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);
                    return false;
                } else {
                    isValidNBF = true;
                }
            } catch (IdentityOAuth2Exception e) {
                authResponseContextDTO.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                authResponseContextDTO.setError(ErrorCodes.INTERNAL_SERVER_ERROR);
                authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.UNEXPECTED_SERVER_ERROR+e.getMessage());
                throw new OAuthSystemException();
            }

        }
            return isValidNBF;
    }






    /**
     * This method checks whether the JWT-Issued time is valid.
     *
     * @param claimsSet CIBA Authentication request claimset
     * @param cibaAuthRequestDTO DTO that captures valid - authentication request params
     * @param authResponseContextDTO DTO to capture authentication response context
     * @return IssuedTime of JWT is valid or not.
     */
    private Boolean isvalidIssuedTime(JWTClaimsSet claimsSet, AuthResponseContextDTO authResponseContextDTO,
                                      CibaAuthRequestDTO cibaAuthRequestDTO, long currentTime) {

        //Validation for iat-issued at.Mandatory parameter if signed.

        boolean isValidIssueTime;


        if (claimsSet.getIssueTime() == null) {
            //IsssuedAt is a null value.
            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        cibaAuthRequestDTO.getAudience() + ".The request is missing the mandatory parameter 'iat'.");
            }
            authResponseContextDTO.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            authResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
            authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.MISSING_PARAMETERS);
            return false;

        } else {
            long issuedTime = claimsSet.getIssueTime().getTime();
            if (issuedTime > currentTime) {
                //Invalid issued time.Issued time can not be in the future.
                if (log.isDebugEnabled()) {
                    log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                            cibaAuthRequestDTO.getAudience() + ".The request is with invalid value for 'iat' .");
                }
                authResponseContextDTO.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                authResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
                authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);
                return false;
            } else {

                isValidIssueTime = true;
            }
        }
        return isValidIssueTime;

    }


    /**
     * This method checks whether the JWT-Expiry time is valid.
     *
     * @param claimsSet CIBA Authentication request claimset
     * @param cibaAuthRequestDTO DTO that captures valid - authentication request params
     * @param authResponseContextDTO DTO to capture authentication response context
     * @return Expiry of JWT is valid or not.
     */
    private Boolean isValidExpiryTime(JWTClaimsSet claimsSet, AuthResponseContextDTO authResponseContextDTO,
                                      CibaAuthRequestDTO cibaAuthRequestDTO, long currentTime, long skewTime ) {

        //Validation for expiryTime.


        boolean isValidExpiry;

        if (claimsSet.getExpirationTime() == null) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        cibaAuthRequestDTO.getAudience() + ".The request is missing the mandatory parameter 'exp'.");
            }

            authResponseContextDTO.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            authResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
            authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.MISSING_PARAMETERS);
            return false;

        } else {

            long expiryTime = claimsSet.getExpirationTime().getTime();
            if (expiryTime < currentTime + skewTime) {
                //Invalid token as expired time has passed.
                if (log.isDebugEnabled()) {
                    log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                            cibaAuthRequestDTO.getAudience() + ".The provided JWT is expired.");
                }
                authResponseContextDTO.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                authResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
                authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);
                return false;
            } else {
                isValidExpiry = true;
            }
        }
        return isValidExpiry;
    }


    /**
     * This method checks whether the JWT-ID is valid.
     *
     * @param claimsSet CIBA Authentication request claimset
     * @param cibaAuthRequestDTO DTO that captures valid - authentication request params
     * @param authResponseContextDTO DTO to capture authentication response context
     * @return JWT is valid or not
     */
    private Boolean isValidJWTID(JWTClaimsSet claimsSet, AuthResponseContextDTO authResponseContextDTO,
                                CibaAuthRequestDTO cibaAuthRequestDTO) {
       boolean isvalidJWTID;

        //Validation for jti.Mandatory parameter if signed.
        if (claimsSet.getJWTID() == null) {
            //JTI is null.
            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        cibaAuthRequestDTO.getAudience() + ".The request is missing the mandatory parameter 'jti'.");
            }

            authResponseContextDTO.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            authResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
            authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.MISSING_PARAMETERS);
            return false;

        }else if (StringUtils.isBlank(claimsSet.getJWTID())) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        cibaAuthRequestDTO.getAudience() + ".The request has invalid values for the parameter 'jti'.");
            }


            authResponseContextDTO.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            authResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
            authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);
            return false;
        } else {

            cibaAuthRequestDTO.setJWTID(claimsSet.getJWTID());

            isvalidJWTID = true;

        }
        return isvalidJWTID;

    }



    /**
     * This method checks whether the request is properly signed.
     *
     * @param signedJWT SignedJWT
     * @return Boolean
     * @throws IdentityOAuth2Exception,InvalidOAuthClientException
     */
    private boolean isValidSignature(SignedJWT signedJWT) {
        //signedJWT.verify();

        // TODO: 10/18/19 verify signature 
        return true;
    }





    /**
     * This method checks whether the audience is valid as expected.
     *
     * @param claimsSet CIBA Authentication request claimset
     * @param cibaAuthRequestDTO DTO that captures valid - authentication request params
     * @param authResponseContextDTO DTO to capture authentication response context
     * @return Audience is valid or not
     */
    public Boolean isValidAudience(JWTClaimsSet claimsSet , AuthResponseContextDTO authResponseContextDTO,
                                   CibaAuthRequestDTO cibaAuthRequestDTO) {

        boolean isValidAudience ;

        //Validation for aud-audience.
        if (claimsSet.getAudience().isEmpty()) {
            //No value for audience found in the request.

            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        cibaAuthRequestDTO.getAudience() + ".The request is missing the mandatory parameter 'aud'.");
            }
            authResponseContextDTO.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            authResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
            authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.MISSING_PARAMETERS);
            return false;

        } else {
            List<String> aud = claimsSet.getAudience();

            if (aud.contains(CibaParams.CIBA_AS_AUDIENCE)) {
                //The audience value suits mandated value.
                isValidAudience = true;

                cibaAuthRequestDTO.setIssuer(CibaParams.CIBA_AS_AUDIENCE);

            } else {
                //The audience value failed to meet mandated value.
                if (log.isDebugEnabled()) {
                    log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                            cibaAuthRequestDTO.getAudience() + ".Invalid value for 'aud'.");
                }

                authResponseContextDTO.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                authResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
                authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);
                return false;

            }
        }
        return isValidAudience;
    }



    /**
     * This method checks whether the client is valid.
     *
     * @param request CIBA Authentication request
     * @return Boolean
     * @throws IdentityOAuth2Exception,InvalidOAuthClientException
     */
    public Boolean isValidClient(String request, AuthResponseContextDTO authResponseContextDTO,
                                 CibaAuthRequestDTO cibaAuthRequestDTO) throws ParseException,
            IdentityOAuth2Exception {

        SignedJWT signedJWT = SignedJWT.parse(request);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        JSONObject jo = signedJWT.getJWTClaimsSet().toJSONObject();


        //Validate 'issuer' of the authentication request.
        String clientId = claimsSet.getIssuer();
        if (clientId == null) {

            if (log.isDebugEnabled()) {
                log.debug("Missing issuer of the JWT of the request : " + request);
            }
            authResponseContextDTO.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            authResponseContextDTO.setError(ErrorCodes.UNAUTHORIZED_CLIENT);
            authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.MISSING_CLIENT_ID);
            cibaAuthRequestDTO = null;
            return false;

        } else if (StringUtils.isBlank(claimsSet.getIssuer())) {

            if (log.isDebugEnabled()) {
                log.debug("Missing issuer of the JWT of the request : " + request);
            }
            authResponseContextDTO.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            authResponseContextDTO.setError(ErrorCodes.UNAUTHORIZED_CLIENT);
            authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);
            cibaAuthRequestDTO = null;

            return false;
        } else  {
            try {
                OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(clientId);

                String callbackUri = appDO.getCallbackUrl();
                String clientSecret = appDO.getOauthConsumerSecret();


                if (clientSecret == null || StringUtils.isBlank(clientSecret) || clientSecret.equals("null")) {
                    authResponseContextDTO.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    authResponseContextDTO.setError(ErrorCodes.UNAUTHORIZED_CLIENT);
                    authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.UNKNOWN_CLIENT);
                    cibaAuthRequestDTO = null;

                    if (log.isDebugEnabled()) {
                        log.debug("The request : " + request + " doesn't have a proper clientID.");
                    }
                    return false;
                } else {
                    cibaAuthRequestDTO.setAudience(clientId);
                    return true;
                }
            } catch (InvalidOAuthClientException e) {
                authResponseContextDTO.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                authResponseContextDTO.setError(ErrorCodes.UNAUTHORIZED_CLIENT);
                authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.UNKNOWN_CLIENT);
                if (log.isDebugEnabled()) {
                    log.debug("The request : " + request + " doesn't have a proper clientID.");
                }
                return false;
            }
        }
    }



    /**
     * The JWT MAY contain an nbf (not before) claim that identifies the time before which the
     * token MUST NOT be accepted for processing.
     *
     * @param notBeforeTimeMillis       Not before time
     * @param currentTimeInMillis Current time
     * @param timeStampSkewMillis Time skew
     * @return true or false
     */
    private boolean checkNotBeforeTime(long notBeforeTimeMillis, long currentTimeInMillis, long timeStampSkewMillis)
            throws IdentityOAuth2Exception {

        if (currentTimeInMillis + timeStampSkewMillis < notBeforeTimeMillis) {
            if (log.isDebugEnabled()) {
                log.error("JSON Web Token is used before Not_Before_Time." +
                        ", Not Before Time(ms) : " + notBeforeTimeMillis +
                        ", TimeStamp Skew : " + timeStampSkewMillis +
                        ", Current Time : " + currentTimeInMillis + ". JWT Rejected.");
            }
            return false;
        } else {
            return true;
        }
    }


    /**
     * Verify whether the user code matches with the user.
     *
     * @param authRequest CIBA request
     * @return boolean
     */
    public boolean isMatchingUserCode(String authRequest, AuthResponseContextDTO authResponseContextDTO,
                                      CibaAuthRequestDTO cibaAuthRequestDTO) throws ParseException {
        SignedJWT signedJWT = SignedJWT.parse(authRequest);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        JSONObject authRequestAsJSON = signedJWT.getJWTClaimsSet().toJSONObject();


        if (isValidUserCode(authRequestAsJSON, authResponseContextDTO, cibaAuthRequestDTO)) {
            //no implementation for the moment.Modify if needed.
            // TODO: 10/16/19 provide support for usercode-Not on the first release.
            return true;
         } else {
            return false;
        }
    }


    /**
     * Validation for login_hint_token,id_token_hint.
     * Anyone and exactly one is mandatory.
     *
     * @param authRequest CIBA request
     * @return boolean
     * @throws  ParseException
     */
    public boolean isValidUser(String authRequest, AuthResponseContextDTO authResponseContextDTO,
                               CibaAuthRequestDTO cibaAuthRequestDTO) throws ParseException, IdentityOAuth2Exception,
            UserStoreException, RegistryException {
        boolean validUser = false;
        SignedJWT signedJWT = SignedJWT.parse(authRequest);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        JSONObject jo = signedJWT.getJWTClaimsSet().toJSONObject();
        String clientID = cibaAuthRequestDTO.getAudience();

        if (!(jo.get(CibaParams.LOGIN_HINT_TOKEN) == null)
                && (jo.get(CibaParams.LOGIN_HINT) == null)
                && (jo.get(CibaParams.ID_TOKEN_HINT) == null)) {

            if (log.isDebugEnabled()) {
                log.debug("No Login_hint_token support for current version of IS.Invalid Ciba Authentication request : " + authRequest);
            }
            authResponseContextDTO.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            authResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
            authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);
            return false;


        } else  if ((jo.get(CibaParams.LOGIN_HINT_TOKEN) == null)
                && (!(jo.get(CibaParams.LOGIN_HINT) == null))
                && (jo.get(CibaParams.ID_TOKEN_HINT) == null)) {

            if (StringUtils.isBlank(jo.get(CibaParams.LOGIN_HINT).toString())) {
                authResponseContextDTO.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                authResponseContextDTO.setError(ErrorCodes.UNAUTHORIZED_USER);
                authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.MISSING_USER_ID);

            } else {
                if (this.doesUserExist(String.valueOf(jo.get(CibaParams.LOGIN_HINT)))) {
                    //confirmed that user exists in the store and setting the user hint here
                    cibaAuthRequestDTO.setUserHint(String.valueOf(jo.get(CibaParams.LOGIN_HINT)));
                    validUser = true;
                } else {
                    authResponseContextDTO.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    authResponseContextDTO.setError(ErrorCodes.UNAUTHORIZED_USER);
                    authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.UNKNOWN_USER);
                    if (log.isDebugEnabled()) {
                        log.debug("Unknown user identity from the request : " + authRequest);
                    }
                    return false;
                }
            }

        } else  if ((jo.get(CibaParams.LOGIN_HINT_TOKEN) == null)
                && (jo.get(CibaParams.LOGIN_HINT) == null)
                && (!(jo.get(CibaParams.ID_TOKEN_HINT) == null))) {
            //Value exists for id_token_hint

            if (StringUtils.isBlank(jo.get(CibaParams.ID_TOKEN_HINT).toString())) {
                authResponseContextDTO.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                authResponseContextDTO.setError(ErrorCodes.UNAUTHORIZED_USER);
                authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.MISSING_USER_ID);
                if (log.isDebugEnabled()) {
                    log.debug("Unknown user identity from the request " + authRequest);
                }

                return false;

            } else {
                if (OAuth2Util.validateIdToken(String.valueOf(jo.get(CibaParams.ID_TOKEN_HINT)))) {
                    //Provided id_token_hint is valid.

                    if (this.doesUserExist(getUserfromIDToken(String.valueOf(jo.get(CibaParams.ID_TOKEN_HINT))))) {
                        //User exists in store
                        cibaAuthRequestDTO.setUserHint(getUserfromIDToken(String.valueOf(jo.get(CibaParams.ID_TOKEN_HINT))));
                        validUser = true;

                    } else {
                        authResponseContextDTO.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        authResponseContextDTO.setError(ErrorCodes.UNAUTHORIZED_USER);
                        authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.UNKNOWN_USER);
                        if (log.isDebugEnabled()) {
                            log.debug("Unknown user identity from the request " + authRequest);
                        }

                        return false;
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Invalid id_token_hint from the request " + authRequest);
                    }
                    authResponseContextDTO.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    authResponseContextDTO.setError(ErrorCodes.UNAUTHORIZED_USER);
                    authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.INVALID_ID_TOKEN_HINT);
                    return false;
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Invalid request. Missing mandatory parameter, 'hints' from the request : " + authRequest);
            }
            authResponseContextDTO.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            authResponseContextDTO.setError(ErrorCodes.UNAUTHORIZED_USER);
            authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.MISSING_USER_ID);
            return false;

        }
        return validUser;
    }


    /**
     * Verify whether the mentioned user exists.
     *
     * @param user_hint it carries user identity
     * @return boolean
     *
     */
    private boolean doesUserExist(String user_hint) throws UserStoreException, IdentityOAuth2Exception {
        //Check whether given user exists in the store.Only username is supported as user_hint

        if (log.isDebugEnabled()) {
            log.info("Checking whether user exists in the store for the user id " + user_hint );
        }

        int tenantID = OAuth2Util.getTenantIdFromUserName(user_hint); //getting the tenantID of where he is registered in

        return AuthReqIDManager.getInstance().isUserExists(tenantID, user_hint);  //checking with realm service whether user exists

    }


    /**
     * Obtain sub from given id token.
     *
     * @param id_token_hint it carries user identity
     * @return String- the user identity
     */
    private String getUserfromIDToken(String id_token_hint) throws ParseException {
        //Obtain 'sub' from id_token_hint

        if (log.isDebugEnabled()) {
            log.info("Extracting 'sub' from this id_token_hint " + id_token_hint);
        }

        SignedJWT signedJWT = SignedJWT.parse(id_token_hint);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        String subject = claimsSet.getSubject();
        return subject;
    }


}
