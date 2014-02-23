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
import org.springframework.context.i18n.LocaleContextHolder

/**
 *
 * @author Pavel Burov
 */
class VkontakteAuthTagLib {

    static namespace = 'vkontakteAuth'

    static final String MARKER = 'com.burig.grails.springsecurity.vkontakte.VkontakteAuthTagLib.init'

    def springSecurityService

    /**
     * Initialize Vkontakte Open API. See: http://vk.com/dev/openapi
     *
     * @attr async - use or not asynchronous initialization. Default: false
     */
    def init = { attrs, body ->
        Boolean init = request.getAttribute(MARKER)
        if (init == null) {
            init = false
        }

        Boolean async = attrs.async ?: false

        def conf = SpringSecurityUtils.securityConfig.vkontakte
        def appId = conf.appId

        if (!init) {
            if (async) {
                out << g.render(plugin: 'spring-security-vkontakte', template: '/templates/vkAsyncInit', model: [appId: appId])
            } else {
                r.require(module: 'vk-openapi')
                out << r.script([:], "VK.init({apiId: '${appId}'});")
            }

            request.setAttribute(MARKER, true)
        }
    }

    /**
     * Puts Vkontakte connect button.
     *
     * @emptyTag
     *
     * @attr img - url to image for connect button
     */
    def connect = { attrs, body ->
        String language = LocaleContextHolder.locale.language
        def writer = getOut()
        def conf = SpringSecurityUtils.securityConfig.vkontakte
        String target = conf.filters.redirect.processUrl
        String bodyValue = body()
        if (bodyValue == null || bodyValue.trim().length() == 0) {
            String imgUrl
            if (attrs.img) {
                imgUrl = attrs.img
            } else if (conf.taglib."${language}".button.img) {
                imgUrl = resource(file: conf.taglib."${language}".button.img)
            } else if (conf.taglib."${language}".button.defaultImg) {
                imgUrl = resource(file: conf.taglib."${language}".button.defaultImg, plugin: 'spring-security-vkontakte')
            } else {
                imgUrl = resource(file: conf.taglib.en.button.defaultImg, plugin: 'spring-security-vkontakte')
            }
            bodyValue = img(attrs, imgUrl)
        }
        Closure newBody = {
            return bodyValue
        }
        writer << link([uri: target], newBody)
    }

    /**
     * Puts Vkontakte connect button using Open API. See: http://vk.com/dev/openapi
     *
     * @attr id REQUIRED button id
     * @attr permissions bit mask of required permissions. See: http://vk.com/dev/permissions
     */
    def button = { attrs, body ->
        def conf = SpringSecurityUtils.securityConfig.vkontakte

        out << init(attrs, body)

        String id = attrs.id ?: 'vkontakte_login_button'
        String permissions = attrs.permissions ?: "0"
        String url = g.createLink(uri: conf.filters.openApi.processUrl, absolute: true)
        String callback = "${id}_callback"

        r.require(module: 'jquery')

        Map model = [callback: callback, url: url]
        out << g.render(plugin: 'spring-security-vkontakte', template: '/templates/vkontakteCallback', model: model)
        out << """<div id="${id}" onclick="VK.Auth.login(${callback}, ${permissions});"></div>"""
        out << r.script([:], "VK.UI.button('${id}');")
    }

    /**
     * Renders the user's "$firstName $lastName" if logged in.
     */
    def username = { attrs, body ->
        if (springSecurityService.isLoggedIn()) {
            if (springSecurityService.getAuthentication() instanceof VkontakteAuthToken) {
                String firstName = sec.loggedInUserInfo(field: 'firstName', '')
                String lastName = sec.loggedInUserInfo(field: 'lastName', '')

                if (firstName && lastName) {
                    out << "$firstName $lastName".encodeAsHTML()
                } else {
                    out << sec.username()
                }
            } else {
                out << sec.username()
            }
        }
    }

    private static String img(Map attrs, String src) {
        String language = LocaleContextHolder.locale.language
        def conf = SpringSecurityUtils.securityConfig.vkontakte

        StringBuilder buf = new StringBuilder()
        buf.append('<img src="').append(src).append('" ')
        Map used = [:]
        attrs.entrySet().each { Map.Entry it ->
            String attr = it.key
            if (attr.startsWith('img-')) {
                attr = attr.substring('img-'.length())
                used[attr] = it.value?.toString()
            }
        }
        if (!used.alt) {
            used.alt = conf.taglib."${language}".button.text ?: conf.taglib.en.button.text
        }
        used.entrySet().each { Map.Entry it ->
            buf.append(it.key).append('="').append(it.value).append('" ')
        }
        buf.append("/>")
        return buf.toString()
    }
}
