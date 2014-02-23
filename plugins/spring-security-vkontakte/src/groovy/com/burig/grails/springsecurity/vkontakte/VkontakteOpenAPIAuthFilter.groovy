/*
 * Copyright 2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.burig.grails.springsecurity.vkontakte

import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.DisabledException
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 *
 * @author Pavel Burov
 */
class VkontakteOpenAPIAuthFilter extends AbstractAuthenticationProcessingFilter {

    def vkontakteAuthUtilsService

    protected VkontakteOpenAPIAuthFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl)
    }

    @Override
    Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        try {
            VkontakteAccessToken accessToken = new VkontakteAccessToken(
                    userId: request.getParameter(VkontakteAccessToken.REQUEST_PARAMETER_USER_ID) as Long,
                    accessToken: request.getParameter(VkontakteAccessToken.REQUEST_PARAMETER_ACCESS_TOKEN),
                    expireAt: VkontakteAccessToken.convertToExpireAt(request.getParameter(VkontakteAccessToken.REQUEST_PARAMETER_EXPIRE) as Long),
            )

            Map userDetails = vkontakteAuthUtilsService.getUserDetails(accessToken.userId as String)

            VkontakteAuthToken securityToken = new VkontakteAuthToken(
                    accessToken: accessToken,
                    code: request.getParameter(VkontakteAuthToken.REQUEST_PARAMETER_CODE),
                    userDetails: userDetails,
            )

            securityToken.authenticated = true
            Authentication auth = authenticationManager.authenticate(securityToken)
            if (auth.authenticated) {
                rememberMeServices.loginSuccess(request, response, auth)
                logger.info "Successful authentication"
                return auth
            } else {
                throw new DisabledException("User is disabled")
            }
        } catch (Exception e) {
            logger.error "Failed processing auth callback", e
        }
        throw new BadCredentialsException("Invalid auth token")
    }
}
