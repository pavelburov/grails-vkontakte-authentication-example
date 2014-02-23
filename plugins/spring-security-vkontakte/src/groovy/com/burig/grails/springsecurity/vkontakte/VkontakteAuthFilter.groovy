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

import grails.plugin.springsecurity.SpringSecurityUtils
import org.codehaus.groovy.grails.web.mapping.LinkGenerator
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
class VkontakteAuthFilter extends AbstractAuthenticationProcessingFilter {

    def vkontakteAuthUtilsService

    VkontakteAuthFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl)
    }

    @Override
    Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {

        String error = request.getParameter("error")
        if (error) {
            logger.error request.getParameter("error_description")
            response.sendRedirect(linkGenerator.getServerBaseURL())
            return null
        }

        String code = request.getParameter("code")
        if (code == null || code.length() == 0) {
            redirectToVkontakte(request, response)
            return null
        }

        try {
            VkontakteAuthToken securityToken = vkontakteAuthUtilsService.createAuthToken(code)

            securityToken.authenticated = true
            Authentication auth = getAuthenticationManager().authenticate(securityToken)
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

    private void redirectToVkontakte(HttpServletRequest request, HttpServletResponse response) {
        String authorizeUrl = vkontakteAuthUtilsService.prepareRedirectUrl()
        response.sendRedirect(authorizeUrl)
    }

}
