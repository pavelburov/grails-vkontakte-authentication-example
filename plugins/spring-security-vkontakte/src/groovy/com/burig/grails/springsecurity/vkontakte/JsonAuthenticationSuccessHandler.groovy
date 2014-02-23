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

import grails.converters.JSON
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.web.authentication.AuthenticationSuccessHandler

import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 *
 * @author Pavel Burov
 */
class JsonAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        VkontakteAuthToken token = authentication as VkontakteAuthToken

        Map data = [
                authenticated: true,
                userId: token.getUserId(),
                roles: token.authorities?.collect { it.authority }
        ]

        if (token.principal != null && UserDetails.isAssignableFrom(token.principal.class)) {
            data.username = token.principal.username
            data.enabled = token.principal.enabled
        }

        JSON json = new JSON(data)
        json.render(response)
    }
}
