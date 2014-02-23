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

import java.util.concurrent.TimeUnit

/**
 *
 * @author Pavel Burov
 */
class VkontakteAccessToken implements Serializable {

    public static final String REQUEST_PARAMETER_USER_ID = "session[user][id]"
    public static final String REQUEST_PARAMETER_ACCESS_TOKEN = "session[sid]"
    public static final String REQUEST_PARAMETER_EXPIRE = "session[expire]"

    Long userId
    String accessToken
    Date expireAt

    String toString() {
        return "Access token: ${accessToken}, expires at ${expireAt}"
    }

    public static Date convertToExpireAt(Long expiresIn) {
        if (expiresIn) {
            return new Date(System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(expiresIn))
        }
        return null
    }
}
