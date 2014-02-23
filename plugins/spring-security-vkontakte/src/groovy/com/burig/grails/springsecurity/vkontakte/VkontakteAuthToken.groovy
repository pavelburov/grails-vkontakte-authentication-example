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

import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority

/**
 *
 * @author Pavel Burov
 */
public class VkontakteAuthToken extends AbstractAuthenticationToken implements Authentication, Serializable {

    public static final String REQUEST_PARAMETER_CODE = "session[sig]"

    VkontakteAccessToken accessToken
    String code

    Map userDetails

    Object principal

    Collection<GrantedAuthority> authorities

    def VkontakteAuthToken() {
        super([] as Collection<GrantedAuthority>);
    }

    public Long getUserId() {
        return accessToken?.userId;
    }

    public Object getCredentials() {
        return getUserId()
    }

    String toString() {
        return "Principal: $principal, userId: ${getUserId()}, roles: ${authorities.collect { it.authority }}"
    }

}
