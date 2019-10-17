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
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthRequestDTO;
import org.wso2.carbon.identity.oauth.ciba.util.AuthReqIDManager;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;

import java.text.ParseException;
import java.time.ZonedDateTime;
import java.util.List;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Context;


/**
 *
 *This class handles the validation of authentication request.
 *
 * */
public class AuthRequestValidator {


    private boolean  isValid;
    private boolean isValidClient;
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

    public Boolean isValidAuthRequest(String request, @Context HttpServletResponse response,
                                      CibaAuthRequestDTO cibaAuthRequestDTO) throws ParseException {
        long currentTime = ZonedDateTime.now().toInstant().toEpochMilli();
        long skewTime = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;

        SignedJWT signedJWT = SignedJWT.parse(request);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        JSONObject jo = signedJWT.getJWTClaimsSet().toJSONObject();


        if (!this.checkSignature(signedJWT)) {
            return false;
        } else {

            /*Validation for aud-audience.
             * Mandatory parameter if signed.
             */
            if (claimsSet.getAudience().isEmpty()) {

                if (log.isDebugEnabled()) {
                    log.debug("Invalid request. Missing audience for the JWT.");
                }
                return false;

            } else {
                List<String> aud = claimsSet.getAudience();

                if (aud.contains(CibaParams.CIBA_AS_AUDIENCE)) {
                    //This will be the mandatory value for ciba
                    isValid = true;

                    cibaAuthRequestDTO.setIssuer(CibaParams.CIBA_AS_AUDIENCE);

                    if (log.isDebugEnabled()) {
                        log.debug("The request is supported by CIBA EndPoint.");
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Invalid value for audience.Check the configuration.");
                    }
                    return false;
                }
            }



            /*Validation for jti-.
             * Mandatory parameter if signed.
             */
            if (claimsSet.getJWTID() == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Invalid request. Missing 'jti' of JWT.");
                }
                isValid = false;
                return false;
            } else {

                cibaAuthRequestDTO.setJWTID(claimsSet.getJWTID());

                isValid = true;

            }


            /*Validation for exp*/
            if (claimsSet.getExpirationTime() == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Invalid request. Missing mandatory parameter 'exp'");
                }
                isValid = false;
                return false;

            } else {

                long expiryTime = claimsSet.getExpirationTime().getTime();
                if (expiryTime < currentTime + skewTime) {
                    //invalid token if expired time has passed.
                    if (log.isDebugEnabled()) {
                        log.debug("Authentication request rejected.Request JWT expired.");
                    }

                    isValid = false;
                    return false;
                } else {
                    isValid = true;
                }
            }


            /**
             * Validation for iat-issued at.
             * Mandatory parameter if signed.
             */

            if (claimsSet.getIssueTime() == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Invalid request : Missing mandatory parameter 'iat'");
                }
                isValid = false;
                return false;

            } else {
                long issuedTime = claimsSet.getIssueTime().getTime();
                log.info("iat" + issuedTime);
                if (issuedTime > currentTime) {
                    //invalid issued time.Issued time can not be in the future.
                    log.info("incoorect issue time");
                    if (log.isDebugEnabled()) {
                        log.debug("Authentication request rejected.Invalid Request JWT issued time.");
                    }

                    isValid = false;
                    return false;
                } else {

                    isValid = true;
                }
            }

        }
        /**
         * Validation for nbf-time before signed request is acceptable.
         * Mandatory parameter if signed.
         */
        if (claimsSet.getNotBeforeTime() == null) {

            if (log.isDebugEnabled()) {
                log.debug("Invalid request : Missing mandatory parameter 'nbf'");
            }

            isValid = false;
            return false;

        } else {

            long nbfTime = claimsSet.getNotBeforeTime().getTime();
            try {
                if (checkNotBeforeTime(currentTime, nbfTime, skewTime)) {
                    isValid = false;
                    return false;
                } else {
                    isValid = true;
                }
            } catch (IdentityOAuth2Exception e) {
                if (log.isDebugEnabled()) {
                    log.error("Exception caught when validating 'nbf'.", e);
                }
            }

        }


        /**
         * Validation for scope-.
         * Mandatory parameter of CIBA.
         */
        if (String.valueOf(jo.get("scope")) == null) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid request : Missing mandatory parameter 'scope'");
            }
            isValid = false;
            return false;

        } else {
            cibaAuthRequestDTO.setScope(String.valueOf(jo.get("scope")));
            isValid = true;
        }


        // TODO: 10/14/19  Validation for client_notification_token.
        /* Not Mandatory for polling.
         * Mandatory if ping.
         * */



        /*Validation for acr-values
         * Not mandatory
         */
        if ((String.valueOf(jo.get("acr")).isEmpty())) {
            //do nothing


        } else if ((jo.get("acr")) == null) {
            //do nothing


        } else {
            cibaAuthRequestDTO.setAcrValues(String.valueOf(jo.get("acr")));
            isValid = true;

        }



        /*Validation for user-code
         * Not mandatory
         */
        if ((String.valueOf(jo.get("user_code")).isEmpty())) {
            //do nothing


        } else if ((jo.get("user_code")) == null) {
            //do nothing


        } else {
            cibaAuthRequestDTO.setUserCode(String.valueOf(jo.get("user_code")));
            isValid = true;

        }


        /*Validation for binding_message
         * Not mandatory
         */
        if ((String.valueOf(jo.get("binding_message")).isEmpty())) {
            //do nothing


        } else if ((jo.get("binding_message")) == null) {
            //do nothing


        } else {
            cibaAuthRequestDTO.setBindingMessage(String.valueOf(jo.get("binding_message")));
            isValid = true;

        }


        /*Validation for binding_message
         * Not mandatory
         */
        if ((String.valueOf(jo.get("transaction_context")).isEmpty())) {
            //do nothing


        } else if ((jo.get("transaction_context")) == null) {
            //do nothing


        } else {
            cibaAuthRequestDTO.setTransactionContext(String.valueOf(jo.get("transaction_context")));
            isValid = true;

        }


        /*Validation for iat-issued at.
         * Mandatory parameter if signed.
         */
        if ((String.valueOf(jo.get("requested_expiry")).isEmpty())) {
            //do nothing


        } else if ((jo.get("requested_expiry")) == null) {
            //do nothing


        } else {
            String requestedExpiryAsString = String.valueOf(jo.get("requested_expiry"));
            long requestedExpiry = Long.parseLong(requestedExpiryAsString);
            cibaAuthRequestDTO.setRequestedExpiry(requestedExpiry);
            isValid = true;
        }

        if (log.isDebugEnabled()) {
            log.debug("CIBA Authentication Request Validated.");
        }
        return isValid;
    }

    /*Verify  the signature
     */
    private boolean checkSignature(SignedJWT signedJWT) {
        //signedJWT.verify();
        return true;
    }



    /**
     * This method cheks whether the client is valis
     * @param request CIBA Authentication request
     * @param response Http Servlet response
     * @return Boolean
     * @throws IdentityOAuth2Exception,InvalidOAuthClientException
     */
    public Boolean isValidClient(String request, @Context HttpServletResponse response,
                                 CibaAuthRequestDTO cibaAuthRequestDTO) throws ParseException,
            IdentityOAuth2Exception, InvalidOAuthClientException {

        SignedJWT signedJWT = SignedJWT.parse(request);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        JSONObject jo = signedJWT.getJWTClaimsSet().toJSONObject();


        //validate 'issuer' of the authentication request.
        String clientId = claimsSet.getIssuer();
        if (clientId == null) {

            if (log.isDebugEnabled()) {
                log.debug("unauthorized : Missing issuer of the JWT.");
            }
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            cibaAuthRequestDTO = null;
            return false;

        } else  {
            log.info("iss" + clientId);
            OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(clientId);

            String callbackUri = appDO.getCallbackUrl();
            String clientSecret = appDO.getOauthConsumerSecret();


            if (clientSecret == null || clientSecret.isEmpty() || clientSecret.equals("null")) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                cibaAuthRequestDTO = null;
                return false;
            } else {
                    cibaAuthRequestDTO.setAudience(clientId);
                return true;
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
     * @param response HTTP Servlet response
     * @return boolean
     */
    public boolean isValidUserCode(String authRequest, HttpServletResponse response) {
        return true;
        //no implementation for the moment.Modify if needed.
        // TODO: 10/16/19 provide support for usercode-currently not at the moment 
    }


    /**
     * Validation for login_hint_token,id_token_hint.
     * Anyone and exactly one is mandatory.
     *
     * @param authRequest CIBA request
     * @param response HTTP Servlet response
     * @return boolean
     * @throws  ParseException
     */
    public boolean isValidUser(String authRequest, @Context HttpServletResponse response,
                               CibaAuthRequestDTO cibaAuthRequestDTO) throws ParseException, IdentityOAuth2Exception, InvalidOAuthClientException, UserStoreException, RegistryException {
       boolean validUser = false;
        SignedJWT signedJWT = SignedJWT.parse(authRequest);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        JSONObject jo = signedJWT.getJWTClaimsSet().toJSONObject();
        String clientID = cibaAuthRequestDTO.getAudience();
        OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(clientID);
        String tenantDomain = OAuth2Util.getTenantDomainOfOauthApp(clientID);

        int tenantID = OAuth2Util.getTenantId(tenantDomain);

        if (!(String.valueOf(jo.get("login_hint_token")).equals("null"))
                && (String.valueOf(jo.get("login_hint")).equals("null"))
                && (String.valueOf(jo.get("id_token_hint")).equals("null"))) {

            if (log.isDebugEnabled()) {
                log.debug("No Login_hint_token supported for current version of IS.");
            }
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            validUser = false;


        } else if ((String.valueOf(jo.get("login_hint_token")).equals("null"))
                && (!String.valueOf(jo.get("login_hint")).equals("null"))
                && (String.valueOf(jo.get("id_token_hint")).equals("null"))) {

            if (this.isUserExists(String.valueOf(jo.get("login_hint")),tenantID)) {
                cibaAuthRequestDTO.setUserHint(String.valueOf(jo.get("login_hint")));
                validUser = true;
            } else {
                validUser = false;
            }


            // TODO: 8/4/19 To be validated for the user-id and etc provided

        } else if ((String.valueOf(jo.get("login_hint_token")).equals("null"))
                && (String.valueOf(jo.get("login_hint")).equals("null"))
                && (!String.valueOf(jo.get("id_token_hint")).equals("null"))) {

            if (this.isSubjectExists(String.valueOf(jo.get("id_token_hint")))) {
                cibaAuthRequestDTO.setUserHint(getUserfromIDToken(String.valueOf(jo.get("id_token_hint"))));
                validUser = true;
            } else {
                validUser = false;
            }


        } else {
            if (log.isDebugEnabled()) {
                log.debug("Invalid request : Missing mandatory parameter 'hints'");
            }
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            validUser = false;

        }
        return validUser;
    }


    /**
     * Verify whether the mentioned user exists
     * @param login_hint it carries user identity
     * @return boolean
     */
    private boolean isUserExists(String login_hint,int tenantID) throws UserStoreException, RegistryException {
        //only username is supported as login_hint

        // TODO: 10/15/19 check with db for user existence
        log.info("Checked whether user exist in the store ");
        return AuthReqIDManager.getInstance().isUserExists(tenantID, login_hint);


    }

    /**
     * Verify whether the mentioned user exists
     * @param id_token_hint it carries user identity
     * @return boolean
     */
    private boolean isSubjectExists(String id_token_hint) throws ParseException {
        SignedJWT signedJWT = SignedJWT.parse(id_token_hint);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        //JSONObject jo = signedJWT.getJWTClaimsSet().toJSONObject();

        if (claimsSet.getSubject() == null) {
            return false;
        } else {
            return true;
        }


    }

    /**
     * Obtain sub from given id token
     * @param id_token_hint it carries user identity
     * @return String- the user identity
     */
    private String getUserfromIDToken(String id_token_hint) throws ParseException {
        // TODO: 10/15/19 check and return sub from ID token
        SignedJWT signedJWT = SignedJWT.parse(id_token_hint);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        String subject = claimsSet.getSubject();
        log.info(subject);
        return subject;
    }


}
