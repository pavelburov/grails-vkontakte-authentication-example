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

import org.apache.log4j.Logger
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UsernameNotFoundException

/**
 *
 * @author Pavel Burov
 */
public class VkontakteAuthProvider implements AuthenticationProvider {

    private static def log = Logger.getLogger(this)

    VkontakteAuthDao vkontakteAuthDao

    boolean createNew = true

    public Authentication authenticate(Authentication authentication) {
        VkontakteAuthToken token = authentication as VkontakteAuthToken

        def user = vkontakteAuthDao.findUser(token)

        if (user == null) {
            if (createNew) {
                log.info "Create new Vkontakte user with userId ${token.getUserId()}"
                user = vkontakteAuthDao.create(token)
                if (!user) {
                    throw new UsernameNotFoundException("Cannot create user for Vkontakte '${token.getUserId()}'")
                }
            } else {
                log.error "User ${token.getUserId()} doesn't exist, and creation of a new user is disabled."
                log.debug "To enabled auto creation of users set 'grails.plugins.springsecurity.vkontakte.autoCreate.enabled' to true"
                throw new UsernameNotFoundException("Vkontakte user with userId '${token.getUserId()}' doesn't exist")
            }
        } else {
            vkontakteAuthDao.updateToken(user, token)
        }

        Object appUser = vkontakteAuthDao.getAppUser(user)
        Object principal = vkontakteAuthDao.getPrincipal(appUser)

        token.details = null
        token.principal = principal
        if (UserDetails.isAssignableFrom(principal.class)) {
            token.authorities = ((UserDetails) principal).getAuthorities()
        } else {
            token.authorities = vkontakteAuthDao.getRoles(appUser)
        }

        return token
    }

    public boolean supports(Class<? extends Object> authentication) {
        return VkontakteAuthToken.isAssignableFrom(authentication);
    }
}
