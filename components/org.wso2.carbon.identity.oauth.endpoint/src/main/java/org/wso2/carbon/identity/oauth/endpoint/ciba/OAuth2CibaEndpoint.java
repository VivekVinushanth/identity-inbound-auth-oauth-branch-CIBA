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
    public Response ciba(@Context HttpServletRequest request, @Context HttpServletResponse response) {

        Map<String, String[]> attributeNames =  request.getParameterMap();
        //capture all parameters


            log.info("CIBA request has hit Client Initiated Back-Channel Authentication EndPoint.");

        try {
            if (attributeNames.containsKey(CibaParams.REQUEST)) {
                //only allow signed request - check for existence of 'request' parameter.
                if (log.isDebugEnabled()) {
                    log.debug("CIBA request has the 'request' parameter.");
                }

                String authRequest = request.getParameter(CibaParams.REQUEST);

                CibaAuthRequestDTO cibaAuthRequestDTO = new CibaAuthRequestDTO(); //new DTO to capture claims in request

                AuthResponseContextDTO authResponseContextDTO = new AuthResponseContextDTO();

                if (AuthRequestValidator.getInstance().isValidClient(authRequest, authResponseContextDTO, cibaAuthRequestDTO)) {
                    //check whether the client exists

                    if (AuthRequestValidator.getInstance().isValidUser(authRequest, authResponseContextDTO, cibaAuthRequestDTO)) {
                        //check whether the user exists

                        if (AuthRequestValidator.getInstance().isValidUserCode(authRequest, authResponseContextDTO)) {
                            //extensible method to validate usercode if needed


                            if (AuthRequestValidator.getInstance().isValidAuthRequest
                                    (authRequest, authResponseContextDTO, cibaAuthRequestDTO)) {
                                //validate authentication request for existence of mandatory parameters and values
                                try {
                                    return CibaAuthResponseHandler.getInstance().
                                            createAuthResponse(request, response, cibaAuthRequestDTO);
                                    //if valid request - create a ciba authentication response

                                } catch (NullPointerException e) {
                                    if (log.isDebugEnabled()) {
                                        log.debug("Unable to create AuthenticationResponse.", e);
                                    }
                                }
                            } else {
                                try {
                                    return CibaAuthResponseHandler.getInstance().
                                            createErrorResponse(authResponseContextDTO);
                                    //if invalid request - create a ciba error response


                                } catch (NullPointerException e) {
                                    if (log.isDebugEnabled()) {
                                        log.debug("Unable to create AuthenticationResponse.", e);
                                    }
                                }
                            }
                        } else {
                        /*    OAuthResponse errorresponse = null;

                            errorresponse = OAuthASResponse
                                    .errorResponse(response.getStatus())
                                    .setError(ErrorCodes.UNAUTHORIZED_CLIENT)
                                    .setErrorDescription("Invalid user_code.")
                                    .buildJSONMessage();

                            Response.ResponseBuilder respBuilder = Response.status(response.getStatus());
                            return respBuilder.entity(errorresponse.getBody()).build();*/
                            return  CibaAuthResponseHandler.getInstance().createErrorResponse(authResponseContextDTO);
                        }
                    } else {
                      /*  OAuthResponse errorresponse = null;
                        try {
                            errorresponse = OAuthASResponse
                                    .errorResponse(response.getStatus())
                                    .setError(ErrorCodes.UNAUTHORIZED_USER)
                                    .setErrorDescription(ErrorCodes.SubErrorCodes.UNKNOWN_USER)
                                    .buildJSONMessage();

                            Response.ResponseBuilder respBuilder = Response.status(response.getStatus());
                            return respBuilder.entity(errorresponse.getBody()).build();
                        } catch (OAuthSystemException e) {

                            if (log.isDebugEnabled()) {
                                log.debug("Error building errorResponse.", e);
                            }
                        }*/

                   return    CibaAuthResponseHandler.getInstance().createErrorResponse(authResponseContextDTO);
                    }
                } else {
                   /* OAuthResponse errorresponse = null;
                    try {
                        errorresponse = OAuthASResponse
                                .errorResponse(response.getStatus())
                                .setError(ErrorCodes.UNAUTHORIZED_CLIENT)
                                .setErrorDescription(ErrorCodes.SubErrorCodes.UNKNOWN_CLIENT)
                                .buildJSONMessage();

                        Response.ResponseBuilder respBuilder = Response.status(response.getStatus());
                        return respBuilder.entity(errorresponse.getBody()).build();
                    } catch (OAuthSystemException e) {

                        if (log.isDebugEnabled()) {
                            log.debug("Error building errorResponse.", e);
                        }
                    }*/

                    return CibaAuthResponseHandler.getInstance().createErrorResponse(authResponseContextDTO);
                }


            } else {
                if (log.isDebugEnabled()) {
                    log.debug("CIBA request has no 'request' parameter.");
                }
                //create error response since there is no 'request' parameter which is a must in signed request.
                OAuthResponse errorresponse;
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);

                errorresponse = OAuthASResponse
                        .errorResponse(response.getStatus())
                        .setError(ErrorCodes.INVALID_REQUEST)
                        .setErrorDescription("Missing 'request' parameter.")
                        .buildJSONMessage();


                Response.ResponseBuilder respBuilder = Response.status(response.getStatus());
                return respBuilder.entity(errorresponse.getBody()).build();

            }
        } catch (InvalidOAuthClientException e) {
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
        } catch (ParseException e) {
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
        } catch (OAuthSystemException e) {
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
        } catch (IdentityOAuth2Exception e) {
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
        } catch (UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;

    }
}











