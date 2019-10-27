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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.wso2.carbon.identity.oauth.ciba.common.CibaParams;
import org.wso2.carbon.identity.oauth.ciba.dao.CibAuthCodeMgtDAO;
import org.wso2.carbon.identity.oauth.ciba.dto.AuthResponseContextDTO;
import org.wso2.carbon.identity.oauth.ciba.dto.AuthzRequestDTO;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthRequestDTO;
import org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes;
import org.wso2.carbon.identity.oauth.ciba.handlers.CibaAuthorizationHandler;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthResponse;
import org.wso2.carbon.identity.oauth.ciba.util.AuthReqIDManager;
import org.wso2.carbon.identity.oauth.ciba.util.AuthzRequestDOBuilder;
import org.wso2.carbon.identity.oauth.ciba.util.CibaAuthCodeDOBuilder;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestParentException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.text.ParseException;
import java.util.concurrent.ExecutionException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;


/**
 *
 *This class handles authentication response.
 *
 * */
public class CibaAuthResponseHandler  {


    private static final Log log = LogFactory.getLog(CibaAuthResponseHandler.class);
    private CibaAuthResponseHandler() {

    }

    private static CibaAuthResponseHandler CibaAuthResponseHandlerInstance = new CibaAuthResponseHandler();

    public static CibaAuthResponseHandler getInstance() {
        if (CibaAuthResponseHandlerInstance == null) {

            synchronized (CibaAuthResponseHandler.class) {

                if (CibaAuthResponseHandlerInstance == null) {

                    /* instance will be created at request time */
                    CibaAuthResponseHandlerInstance = new CibaAuthResponseHandler();
                }
            }
        }
        return CibaAuthResponseHandlerInstance;

    }


    /**
     * This method create CIBA AuthenticationResponse.
     * @param cibaAuthRequestDTO CIBA Authentication Request Data Transfer Object
     * @return response
     * @throws ExecutionException,IOException
     */
    public Response createAuthResponse( @Context HttpServletRequest request, @Context HttpServletResponse response,
                                        CibaAuthRequestDTO cibaAuthRequestDTO) {
        try {

            //Create JWT as CibaAuthCode.
            JWT cibaAuthCodeasJWT = AuthReqIDManager.getInstance().getCibaAuthCode(cibaAuthRequestDTO);

            if(log.isDebugEnabled()) {
                log.info("Creating CibaAuthCode as a JWT for the request made by client with clientID : " + cibaAuthRequestDTO.getAudience() + ".");
            }

            //Set the ExpiryTime.
            long expiresIn = AuthReqIDManager.getInstance().getExpiresIn(cibaAuthRequestDTO);
            if(log.isDebugEnabled()) {
                log.info("Setting ExpiryTime for the response to the  request made by client with clientID : " + cibaAuthRequestDTO.getAudience() + ".");
            }

            //Serialize so that can be returned in preferable manner.
            String cibaAuthCode = cibaAuthCodeasJWT.serialize();
            if (log.isDebugEnabled()) {
                log.info("Ciba auth_req_id " + cibaAuthCode + " is created for the response to the request made by client with clientID : " + cibaAuthRequestDTO.getAudience() + ".");
            }

            //Create authentication response.
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType(MediaType.APPLICATION_JSON);

            CibaAuthResponse.CibaAuthResponseBuilder cibaAuthResponsebuilder = CibaAuthResponse
                    .cibaAuthenticationResponse(HttpServletResponse.SC_OK)
                    .setAuthReqID(cibaAuthCode)
                    .setExpiresIn(Long.toString(expiresIn))
                    .setInterval(Long.toString(CibaParams.interval));


            if (log.isDebugEnabled()) {
                log.info("Creating CIBA Authentication response to the request made by client with clientID : " + cibaAuthRequestDTO.getAudience() + ".");
            }

            Response.ResponseBuilder respBuilder = Response.status(response.getStatus());

            OAuthResponse cibaAuthenticationresponse  = cibaAuthResponsebuilder.buildJSONMessage();

            //Build authCode with all the parameters that need to be persisted.
            CibaAuthCodeDO cibaAuthCodeDO = CibaAuthCodeDOBuilder.getInstance().buildCibaAuthCodeDO(cibaAuthCode);
            // TODO: 10/14/19 can add as a builder format-

            if (log.isDebugEnabled()) {
                log.info("Building CibaAuthCodeDO that accumulates parameters to be persisted in regard to the request made by client with clientID : " + cibaAuthRequestDTO.getAudience() + ".");
            }


            //Persist CibaAuthCode.
            CibAuthCodeMgtDAO.getInstance().persistCibaAuthReqCode(cibaAuthCodeDO);
            if (log.isDebugEnabled()) {
                log.info("Persisting CibaAuthCodeDO that accumilates parameters to be persisted in regard to the request made by client with clientID : " + cibaAuthRequestDTO.getAudience() + ".");
            }

            //Build authorize request data transfer object.
            AuthzRequestDTO authzRequestDTO = AuthzRequestDOBuilder.getInstance().buildAuthzRequestDO(cibaAuthRequestDTO, cibaAuthCodeDO);
            // TODO: 10/14/19 can add as a builder format-
            if (log.isDebugEnabled()) {
                log.info("Build CibaAuthzRequestDTO using  CibaAuthCodeDo in regard to the request made by client with clientID : " + cibaAuthRequestDTO.getAudience() + ".");
            }

            //Internal http authorize call to /authorize end point.
            CibaAuthorizationHandler.getInstance().initiateAuthzRequest(authzRequestDTO);
            if (log.isDebugEnabled()) {
                log.info("Firing a Authorization request in regard to the request made by client with clientID : " + cibaAuthRequestDTO.getAudience() + ".");
            }

            log.info("Returning CIBA Authentication Response for the request made by client with clientID : " + cibaAuthRequestDTO.getAudience() + ".");

            if(log.isDebugEnabled()) {
                log.info("Returning CIBA Authentication Response for the request made by client with clientID : " + cibaAuthRequestDTO.getAudience() + ".");
            }
          // return respBuilder.entity(cibaAuthResponse.getBody()).build();
           return respBuilder.entity(cibaAuthenticationresponse.getBody()).build();

        } catch (OAuthSystemException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error in building authenticationResponse for Authentication Request made by client with clientID : " + cibaAuthRequestDTO.getAudience()+ ".");

            }


        } catch (NoSuchAlgorithmException e) {
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
        } catch (ExecutionException e) {
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
        } catch (ParseException e) {
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
        } catch (InvalidOAuthClientException e) {
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
        } catch (ClassNotFoundException e) {
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
        } catch (IdentityOAuth2Exception e) {
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
        } catch (JOSEException e) {
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
        } catch (InterruptedException e) {
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }

        //Return empty response.
        return Response.noContent().build();
    }




    /**
     * This method create CIBA Authentication Error Response.
     * @param authResponseContextDTO CIBA AuthenticationResponseContext that accumulates error codes,error,description
     * @return response
     * @throws ExecutionException,IOException
     */
    public Response createErrorResponse(AuthResponseContextDTO authResponseContextDTO)
            throws OAuthSystemException {
        //Create CIBA Authentication Error Response.

        if (log.isDebugEnabled()) {
            log.debug("Creating Error Response for CIBA Authentication Request.");
        }

        OAuthResponse errorresponse =  OAuthASResponse
                .errorResponse(authResponseContextDTO.getStatus())
                .setError(authResponseContextDTO.getError())
                .setErrorDescription(authResponseContextDTO.getErrorDescription())
                .buildJSONMessage();

        Response.ResponseBuilder respBuilder = Response.status(authResponseContextDTO.getStatus());
        return respBuilder.entity(errorresponse.getBody()).build();
    }





}
