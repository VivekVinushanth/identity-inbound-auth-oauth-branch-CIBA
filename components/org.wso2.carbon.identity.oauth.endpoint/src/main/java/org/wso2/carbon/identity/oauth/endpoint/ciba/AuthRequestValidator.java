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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
 *This class handles the validation of authentication request.
 *
 * */
public class AuthRequestValidator {


    private boolean  isValid;
    private boolean isValidClient;
    private static final String VALID_ID_TOKEN_ISSUER = "https://localhost:9443/oauth2/token";

    private static final Log log = LogFactory.getLog(AuthRequestValidator.class);
    private AuthRequestValidator() {

    }

    private static AuthRequestValidator authRequestValidatorInstance = new AuthRequestValidator();

    public static AuthRequestValidator getInstance() {
        if (authRequestValidatorInstance == null) {

            synchronized (AuthRequestValidator.class) {

                if (authRequestValidatorInstance == null) {

                    /* instance will be created at request time */
                    authRequestValidatorInstance = new AuthRequestValidator();
                }
            }
        }
        return authRequestValidatorInstance;


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
                                      CibaAuthRequestDTO cibaAuthRequestDTO) throws ParseException {
        long currentTime = ZonedDateTime.now().toInstant().toEpochMilli();
        long skewTime = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;

        SignedJWT signedJWT = SignedJWT.parse(request);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        JSONObject jo = signedJWT.getJWTClaimsSet().toJSONObject();


        if (!this.checkSignature(signedJWT)) {
            //Signature is invalid.
            authResponseContextDTO.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            authResponseContextDTO.setError(ErrorCodes.UNAUTHORIZED_CLIENT);
            authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.INVALID_SIGNATURE);
            return false;

        } else {

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
                    isValid = true;

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



            //Validation for jti.Mandatory parameter if signed.
            if (claimsSet.getJWTID() == null) {
                //JTI is null.
                if (log.isDebugEnabled()) {
                    log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                            cibaAuthRequestDTO.getAudience() + ".The request is missing the mandatory parameter 'jti'.");
                }
                isValid = false;

                authResponseContextDTO.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                authResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
                authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.MISSING_PARAMETERS);
                return false;
            } else {

                cibaAuthRequestDTO.setJWTID(claimsSet.getJWTID());

                isValid = true;

            }


            //Validation for expiryTime.
            if (claimsSet.getExpirationTime() == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                            cibaAuthRequestDTO.getAudience() + ".The request is missing the mandatory parameter 'exp'.");
                }
                isValid = false;

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
                    isValid = false;
                    return false;
                } else {
                    isValid = true;
                }
            }


             //Validation for iat-issued at.Mandatory parameter if signed.
            if (claimsSet.getIssueTime() == null) {
                //IsssuedAt is a null value.
                if (log.isDebugEnabled()) {
                    log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                            cibaAuthRequestDTO.getAudience() + ".The request is missing the mandatory parameter 'iat'.");
                }
                authResponseContextDTO.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                authResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
                authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.MISSING_PARAMETERS);
                isValid = false;
                return false;

            } else {
                long issuedTime = claimsSet.getIssueTime().getTime();
                log.info("iat" + issuedTime);
                if (issuedTime > currentTime) {
                    //Invalid issued time.Issued time can not be in the future.
                    if (log.isDebugEnabled()) {
                        log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                                cibaAuthRequestDTO.getAudience() + ".The request is with invalid value for 'iat' .");
                    }
                    authResponseContextDTO.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    authResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
                    authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);
                    isValid = false;
                    return false;
                } else {

                    isValid = true;
                }
            }

        }

        //  Validation for nbf-time before signed request is acceptable. Mandatory parameter if signed.
        if (claimsSet.getNotBeforeTime() == null) {

            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        cibaAuthRequestDTO.getAudience() + ".The request is missing the mandatory parameter 'nbf'.");
            }
            authResponseContextDTO.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            authResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
            authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.MISSING_PARAMETERS);
            isValid = false;
            return false;

        } else {

            long nbfTime = claimsSet.getNotBeforeTime().getTime();
            try {
                if (checkNotBeforeTime(currentTime, nbfTime, skewTime)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                                cibaAuthRequestDTO.getAudience() + ".The request is with invalid  value for 'nbf'.");
                    }
                    isValid = false;
                    authResponseContextDTO.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    authResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
                    authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.INVALID_PARAMETERS);
                    return false;
                } else {
                    isValid = true;
                }
            } catch (IdentityOAuth2Exception e) {

            }

        }


        //Validation for scope.Mandatory parameter for CIBA AuthenticationRequest.
        if (String.valueOf(jo.get("scope")) == null) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid CIBA Authentication Request made by client with clientID : " +
                        cibaAuthRequestDTO.getAudience() + ".The request is with invalid  value for 'scope'.");
            }
            authResponseContextDTO.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            authResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
            authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.MISSING_PARAMETERS);
            isValid = false;
            return false;

        } else {
            cibaAuthRequestDTO.setScope(String.valueOf(jo.get("scope")));
            isValid = true;
        }



        //Validation for scope.Mandatory parameter for CIBA AuthenticationRequest.
        if (String.valueOf(jo.get("client_notification_token")) == null) {
            //do nothing

        } else {
            cibaAuthRequestDTO.setClientNotificationToken(String.valueOf(jo.get("client_notification_token")));
            isValid = true;
        }



        //Validation for acr-values.
        if ((String.valueOf(jo.get("acr")).isEmpty())) {
            //do nothing


        } else if ((jo.get("acr")) == null) {
            //do nothing


        } else {
            cibaAuthRequestDTO.setAcrValues(String.valueOf(jo.get("acr")));
            isValid = true;

        }



        //Validation for usercode-values.
        if ((String.valueOf(jo.get("user_code")).isEmpty())) {
            //do nothing


        } else if ((jo.get("user_code")) == null) {
            //do nothing


        } else {
            cibaAuthRequestDTO.setUserCode(String.valueOf(jo.get("user_code")));
            isValid = true;

        }


        //Validation for binding_message.
        if ((String.valueOf(jo.get("binding_message")).isEmpty())) {
            //do nothing


        } else if ((jo.get("binding_message")) == null) {
            //do nothing


        } else {
            cibaAuthRequestDTO.setBindingMessage(String.valueOf(jo.get("binding_message")));
            isValid = true;

        }


        //Validation for transaction_context.
        if ((String.valueOf(jo.get("transaction_context")).isEmpty())) {
            //do nothing


        } else if ((jo.get("transaction_context")) == null) {
            //do nothing


        } else {
            cibaAuthRequestDTO.setTransactionContext(String.valueOf(jo.get("transaction_context")));
            isValid = true;

        }


        //Validation for iat-issued at.Mandatory parameter if signed.
        if ((String.valueOf(jo.get("requested_expiry")).isEmpty())) {
            //do nothing


        } else if ((jo.get("requested_expiry")) == null) {
            //do nothing


        } else {
            String requestedExpiryAsString = String.valueOf(jo.get("requested_expiry"));
            long requestedExpiry = Long.parseLong(requestedExpiryAsString);

            if (requestedExpiry < CibaParams.MAXIMUM_REQUESTED_EXPIRY) {
                cibaAuthRequestDTO.setRequestedExpiry(requestedExpiry);
                isValid = true;
            } else {
                cibaAuthRequestDTO.setRequestedExpiry(CibaParams.MAXIMUM_REQUESTED_EXPIRY);
                if (log.isDebugEnabled()) {
                    log.debug("Warning on  CIBA Authentication Request made by client with clientID : " +
                            cibaAuthRequestDTO.getAudience() + ".Requested expiry is too long.Setting the maximum default value.");
                }



            }
        }

        if (log.isDebugEnabled()) {
            log.debug(" CIBA Authentication Request made by client with clientID : " +
                    cibaAuthRequestDTO.getAudience() + "is properly validated.");
        }

        authResponseContextDTO.setStatus(HttpServletResponse.SC_OK);
        return isValid;
    }

    //Verify  the signature.
    private boolean checkSignature(SignedJWT signedJWT) {
        //signedJWT.verify();

        // TODO: 10/18/19 verify signature 
        return true;
    }



    /**
`     * This method cheks whether the client is valid
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


        //validate 'issuer' of the authentication request.
        String clientId = claimsSet.getIssuer();
        if (clientId == null) {

            if (log.isDebugEnabled()) {
                log.debug("Missing issuer of the JWT.");
            }
            authResponseContextDTO.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            authResponseContextDTO.setError(ErrorCodes.UNAUTHORIZED_CLIENT);
            authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.MISSING_CLIENT_ID);
            cibaAuthRequestDTO = null;
            return false;

        } else  {
            try {
            OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(clientId);

            String callbackUri = appDO.getCallbackUrl();
            String clientSecret = appDO.getOauthConsumerSecret();


            if (clientSecret == null || clientSecret.isEmpty() || clientSecret.equals("null")) {
                authResponseContextDTO.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                authResponseContextDTO.setError(ErrorCodes.UNAUTHORIZED_CLIENT);
                authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.UNKNOWN_CLIENT);
                cibaAuthRequestDTO = null;

                if (log.isDebugEnabled()) {
                    log.debug("Aforementioned clientID is not available.");
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
                    log.debug("Aforementioned clientID is not available.");
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
     * Verify whether the user code matches with the user
     *
     * @param authRequest CIBA request
     * @return boolean
     */
    public boolean isValidUserCode(String authRequest, AuthResponseContextDTO authResponseContextDTO) {
        return true;
        //no implementation for the moment.Modify if needed.
        // TODO: 10/16/19 provide support for usercode-Not on the first release.
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
                               CibaAuthRequestDTO cibaAuthRequestDTO) throws ParseException, IdentityOAuth2Exception, InvalidOAuthClientException, UserStoreException, RegistryException {
       boolean validUser = false;
        SignedJWT signedJWT = SignedJWT.parse(authRequest);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        JSONObject jo = signedJWT.getJWTClaimsSet().toJSONObject();
        String clientID = cibaAuthRequestDTO.getAudience();

        if (!(String.valueOf(jo.get("login_hint_token")).equals("null"))
                && (String.valueOf(jo.get("login_hint")).equals("null"))
                && (String.valueOf(jo.get("id_token_hint")).equals("null"))) {

            if (log.isDebugEnabled()) {
                log.debug("No Login_hint_token support for current version of IS.");
            }
            authResponseContextDTO.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            authResponseContextDTO.setError(ErrorCodes.INVALID_REQUEST);
            authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.MISSING_PARAMETERS);
            validUser = false;


        } else if ((String.valueOf(jo.get("login_hint_token")).equals("null"))
                && (!String.valueOf(jo.get("login_hint")).equals("null"))
                && (String.valueOf(jo.get("id_token_hint")).equals("null"))) {

            if (this.doesUserExist(String.valueOf(jo.get("login_hint")))) {
                //confirmed that user exists in the store and setting the user hint here
                cibaAuthRequestDTO.setUserHint(String.valueOf(jo.get("login_hint")));
                validUser = true;
            } else {
                authResponseContextDTO.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                authResponseContextDTO.setError(ErrorCodes.UNAUTHORIZED_USER);
                authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.UNKNOWN_USER);
                if (log.isDebugEnabled()) {
                    log.debug("Unknown user identity.");
                }
                validUser = false;
            }


            // TODO: 8/4/19 To be validated for the user-id and etc provided

        } else if ((String.valueOf(jo.get("login_hint_token")).equals("null"))
                && (String.valueOf(jo.get("login_hint")).equals("null"))
                && (!String.valueOf(jo.get("id_token_hint")).equals("null"))) {

            if (OAuth2Util.validateIdToken(String.valueOf(jo.get("id_token_hint")))) {
                //provided id_token_hint is valid.

                if(this.doesUserExist(String.valueOf(jo.get("id_token_hint")))) {
                    //user exists in store
                    cibaAuthRequestDTO.setUserHint(getUserfromIDToken(String.valueOf(jo.get("id_token_hint"))));
                    validUser = true;

            } else {
                authResponseContextDTO.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                authResponseContextDTO.setError(ErrorCodes.UNAUTHORIZED_USER);
                authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.UNKNOWN_USER);
                if (log.isDebugEnabled()) {
                    log.debug("Unknown user identity.");
                }
                validUser = false;
            }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Invalid id_token_hint");
                }
                authResponseContextDTO.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                authResponseContextDTO.setError(ErrorCodes.UNAUTHORIZED_USER);
                authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.INVALID_ID_TOKEN_HINT);
                validUser = false;
            }


        } else {
            if (log.isDebugEnabled()) {
                log.debug("Invalid request : Missing mandatory parameter 'hints'");
            }
            authResponseContextDTO.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            authResponseContextDTO.setError(ErrorCodes.UNAUTHORIZED_USER);
            authResponseContextDTO.setErrorDescription(ErrorCodes.SubErrorCodes.UNKNOWN_USER);
            if (log.isDebugEnabled()) {
                log.debug("Unknown user identity.");
            }
            validUser = false;

        }
        return validUser;
    }


    /**
     * Verify whether the mentioned user exists
     * @param user_hint it carries user identity
     * @return boolean
     *
     */
    private boolean doesUserExist(String user_hint) throws UserStoreException, IdentityOAuth2Exception {
        //only username is supported as user_hint

        if (log.isDebugEnabled()) {
            log.info("Checking whether user exists in the store.");
        }

        int tenantID = OAuth2Util.getTenantIdFromUserName(user_hint); //getting the tenantID of where he is registered in

        log.info("tenantID of user :" +tenantID);

        return AuthReqIDManager.getInstance().isUserExists(tenantID,user_hint);

    }


    /**
     * Obtain sub from given id token
     * @param id_token_hint it carries user identity
     * @return String- the user identity
     */
    private String getUserfromIDToken(String id_token_hint) throws ParseException {
        SignedJWT signedJWT = SignedJWT.parse(id_token_hint);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        String subject = claimsSet.getSubject();
        return subject;
    }


}
