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

import org.springframework.security.core.GrantedAuthority

public interface VkontakteAuthDao<F, A> {

    /**
     * Tries to find existing user for Vkontakte Token
     * @param token information about current authnetication
     * @return existing user, or null if there is no user for specified userId
     */
    F findUser(VkontakteAuthToken token)

    /**
     * Called when logged in Vkontakte user doesn't exists in current database
     * @param token information about current authnetication
     * @return just created user
     */
    F create(VkontakteAuthToken token)

    /**
     * Returns `principal` that will be stored into Security Context. It's good if it
     * implements {@link org.springframework.security.core.userdetails.UserDetails UserDetails} or
     * {@link java.security.Principal Principal}.
     *
     * Btw, it's ok to return same object here.
     *
     * @param user current app user (main spring security core domain instance)
     * @return user to put into Security Context
     */
    Object getPrincipal(A user)

    /**
     * Return main (spring security user domain) for given Vkontakte user. If it's same domain, just return
     * passed argument.
     *
     * @param user instance of Vkontakte domain
     * @return instance of spring security domain
     */
    A getAppUser(F user)

    /**
     * Returns Vkontakte user for given spring security user.
     *
     * @param user instance of spring security domain
     * @return instance of Vkontakte user domain
     */
    F getProvidedUser(A user)

        /**
     * Roles for current user
     *
     * @param user current user
     * @return roles for user
     */
    Collection<GrantedAuthority> getRoles(F user)

    /**
     *
     * @param user target user
     * @return false when user have invalid token, or don't have token
     */
    Boolean hasValidToken(F user)

    /**
     * Setup a new Vkontakte Access Token if needed. Could be called with existing token, so
     * implementation should check this case.
     *
     * @param user target user
     * @param token valid access token
     */
    void updateToken(F user, VkontakteAuthToken token)

    /**
     *
     * @param user target user
     * @return current access_token, or null if not exists
     */
    String getAccessToken(F user)
}
