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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.wso2.carbon.identity.oauth.ciba.common.CibaParams;
import org.wso2.carbon.identity.oauth.ciba.dto.AuthResponseContextDTO;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthRequestDTO;
import org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.user.api.UserStoreException;

import java.text.ParseException;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;


@Path("/ciba")
public class OAuth2CibaEndpoint {
    private static final Log log = LogFactory.getLog(OAuth2CibaEndpoint.class);

    @POST
    @Path("/")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("application/json")
    public Response ciba(@Context HttpServletRequest request, @Context HttpServletResponse response) throws IdentityOAuth2Exception {

        Map<String, String[]> attributeNames =  request.getParameterMap();
        //Capture all CIBA Authentication Request parameters.


        log.info("CIBA request has hit Client Initiated Back-Channel Authentication EndPoint.");

        try {
            if (attributeNames.containsKey(CibaParams.REQUEST)) {
                //Confirmed existence of 'request' parameter.


                String authRequest = request.getParameter(CibaParams.REQUEST);

                if (log.isDebugEnabled()) {
                    log.debug("CIBA Authentication Request with  'request' :" + authRequest + "  has hit Client " +
                            "Initiated Back-Channel Authentication EndPoint.");
                }

                CibaAuthRequestDTO cibaAuthRequestDTO = new CibaAuthRequestDTO(); //DTO to capture claims in request.

                AuthResponseContextDTO authResponseContextDTO = new AuthResponseContextDTO(); //DTO to capture authenticationResponse Context.

                if (AuthRequestValidator.getInstance().isValidClient(authRequest, authResponseContextDTO, cibaAuthRequestDTO)) {
                    //The CIBA Authentication Request is with proper client.

                    if (log.isDebugEnabled()) {
                        log.debug("CIBA Authentication Request 'request' :" + authRequest +
                                " is having a proper clientID : " + cibaAuthRequestDTO.getAudience() + " as the issuer.");
                    }

                    if (AuthRequestValidator.getInstance().isValidUser(authRequest, authResponseContextDTO, cibaAuthRequestDTO)) {
                        //The CIBA Authentication Request is with proper user hint.

                        if (log.isDebugEnabled()) {
                            log.debug("CIBA Authentication Request made by Client with clientID," + cibaAuthRequestDTO.getAudience() +
                                    " is having a proper user hint  : " + cibaAuthRequestDTO.getUserHint() + ".");
                        }

                        if (AuthRequestValidator.getInstance().isValidUserCode(authRequest, authResponseContextDTO)) {
                            //Usercode is validated.


                            if (AuthRequestValidator.getInstance().isValidAuthRequest
                                    (authRequest, authResponseContextDTO, cibaAuthRequestDTO)) {
                                //Authentication request is validated.

                                if (log.isDebugEnabled()) {
                                    log.debug("CIBA Authentication Request made by Client with clientID," +
                                            cibaAuthRequestDTO.getAudience() + " is properly validated.");
                                }

                                try {

                                    if (log.isDebugEnabled()) {
                                        log.debug("CIBA Authentication Request made by Client with clientID," +
                                                cibaAuthRequestDTO.getAudience() + " is returned with Ciba Authentication Response.");
                                    }

                                    //Create a Ciba Authentication Response.
                                    return CibaAuthResponseHandler.getInstance().
                                            createAuthResponse(request, response, cibaAuthRequestDTO);


                                } catch (NullPointerException e) {

                                    if (log.isDebugEnabled()) {
                                        log.debug("Unable to create AuthenticationResponse for the CIBA Authentication " +
                                                "Request made by client of clientID : " + cibaAuthRequestDTO.getAudience() + ".", e);
                                    }
                                }
                            } else {
                                try {

                                    if (log.isDebugEnabled()) {
                                        log.debug("CIBA Authentication Request made by Client with clientID," +
                                                cibaAuthRequestDTO.getAudience() + " is returned with an Error.");
                                    }

                                    return CibaAuthResponseHandler.getInstance().createErrorResponse(authResponseContextDTO);
                                    //Create Error Response.


                                } catch (NullPointerException e) {

                                    if (log.isDebugEnabled()) {
                                        log.debug("Unable to create AuthenticationResponse for the CIBA Authentication " +
                                                "Request made by client of clientID : " + cibaAuthRequestDTO.getAudience() + ".", e);
                                    }
                                }
                            }
                        } else {
                            //Create Error Response.
                            return  CibaAuthResponseHandler.getInstance().createErrorResponse(authResponseContextDTO);
                        }
                    } else {

                        //Create Error Response.
                        return    CibaAuthResponseHandler.getInstance().createErrorResponse(authResponseContextDTO);
                    }
                } else {

                    //Create Error Response.
                    return CibaAuthResponseHandler.getInstance().createErrorResponse(authResponseContextDTO);
                }


            } else {
                //Create error response since there is no 'request' parameter which is a must in signed request.

                if (log.isDebugEnabled()) {
                    log.debug("CIBA Authentication Request that hits Client Initiated Authentication Endpoint has " +
                            "no 'request' parameter.");
                }

                OAuthResponse errorresponse;
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);

                errorresponse = OAuthASResponse
                        .errorResponse(response.getStatus())
                        .setError(ErrorCodes.INVALID_REQUEST)
                        .setErrorDescription(ErrorCodes.SubErrorCodes.MISSING_PARAMETERS)
                        .buildJSONMessage();


                Response.ResponseBuilder respBuilder = Response.status(response.getStatus());
                return respBuilder.entity(errorresponse.getBody()).build();

            }
        } catch (InvalidOAuthClientException e) {
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
            throw new IdentityOAuth2Exception(e.getMessage());
        } catch (ParseException e) {
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
            throw new IdentityOAuth2Exception(e.getMessage());
        } catch (OAuthSystemException e) {
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
            throw new IdentityOAuth2Exception(e.getMessage());
        } catch (IdentityOAuth2Exception e) {
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
            throw new IdentityOAuth2Exception(e.getMessage());
        } catch (UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
            throw new IdentityOAuth2Exception(e.getMessage());
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
            throw new IdentityOAuth2Exception(e.getMessage());
        }
        return null;

    }
}











