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

import org.apache.catalina.connector.Response;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthRequestWrapper;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthResponseWrapper;
import org.wso2.carbon.identity.oauth.ciba.common.CibaParams;
import org.wso2.carbon.identity.oauth.ciba.dto.AuthzRequestDTO;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes;
import org.wso2.carbon.identity.oauth.endpoint.authz.OAuth2AuthzEndpoint;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestParentException;

import java.net.URISyntaxException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Context;

/**
 * This class handle mechanism of making authorize request to the authorize request.
 */
public class CibaAuthzHandler {

    private static final Log log = LogFactory.getLog(CibaAuthzHandler.class);

    OAuth2AuthzEndpoint authzEndPoint = new OAuth2AuthzEndpoint();

    private CibaAuthzHandler() {

    }

    private static CibaAuthzHandler CibaAuthzHandlerInstance = new CibaAuthzHandler();

    public static CibaAuthzHandler getInstance() {

        if (CibaAuthzHandlerInstance == null) {

            synchronized (CibaAuthzHandler.class) {

                if (CibaAuthzHandlerInstance == null) {

                    /* instance will be created at request time */
                    CibaAuthzHandlerInstance = new CibaAuthzHandler();
                }
            }
        }
        return CibaAuthzHandlerInstance;
    }

    /**
     * Trigger authorize request after building the url.
     *
     * @param authzRequestDto AuthorizeRequest Data Transfer Object..
     * @throws CibaCoreException
     */
    public void initiateAuthzRequest(AuthzRequestDTO authzRequestDto, @Context HttpServletRequest request,
                                     @Context HttpServletResponse response)
            throws CibaCoreException, CibaAuthFailedException {

        // Add custom parameters to the request by wrapping.
        CommonAuthRequestWrapper commonAuthRequestWrapper = new CommonAuthRequestWrapper(request);

        request.removeAttribute(CibaParams.REQUEST);


        commonAuthRequestWrapper.setParameter(CibaParams.SCOPE, authzRequestDto.getScope());
        commonAuthRequestWrapper.setParameter(CibaParams.RESPONSE_TYPE, CibaParams.RESPONSE_TYPE_VALUE);
        commonAuthRequestWrapper.setParameter(CibaParams.NONCE, authzRequestDto.getAuthReqIDasState());
        commonAuthRequestWrapper.setParameter(CibaParams.REDIRECT_URI, authzRequestDto.getCallBackUrl());
        commonAuthRequestWrapper.setParameter(CibaParams.CLIENT_ID, authzRequestDto.getClient_id());
        commonAuthRequestWrapper.setParameter(CibaParams.USER_IDENTITY, authzRequestDto.getUser());
        commonAuthRequestWrapper.setParameter(CibaParams.BINDING_MESSAGE, authzRequestDto.getBindingMessage());
        commonAuthRequestWrapper.setParameter(CibaParams.TRANSACTION_CONTEXT,
                authzRequestDto.getTransactionContext());

        // Create an instance of response.
        CommonAuthResponseWrapper commonAuthResponseWrapper = new CommonAuthResponseWrapper(response);

        if (log.isDebugEnabled()) {
            log.debug("Building AuthorizeRequest wrapper from CIBA component for the user : " +
                    authzRequestDto.getUser() + " to continue the authentication request made by client with " +
                    "clientID : " + authzRequestDto.getClient_id());
        }

        // Fire authorize request and forget.
        fireAuthzReq(commonAuthRequestWrapper, commonAuthResponseWrapper);
    }

    /**
     * Initiate the async authorize request.
     *
     * @param requestWrapper Authentication request wrapper.
     * @param responseWrapper   AuthenticationResponse wrapper.
     * @authzRequestDTO url URL for authorize request.
     */
    private void fireAuthzReq(CommonAuthRequestWrapper requestWrapper, CommonAuthResponseWrapper responseWrapper)
            throws CibaAuthFailedException {

        try {
            authzEndPoint.authorize(requestWrapper, responseWrapper);
        } catch (URISyntaxException | InvalidRequestParentException e) {
            throw new CibaAuthFailedException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }

    }




}
