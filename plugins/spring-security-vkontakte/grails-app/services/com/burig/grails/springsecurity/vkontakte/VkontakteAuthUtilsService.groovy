package com.burig.grails.springsecurity.vkontakte

import grails.converters.JSON
import grails.plugin.springsecurity.SpringSecurityUtils
import org.codehaus.groovy.grails.web.mapping.LinkGenerator

class VkontakteAuthUtilsService {
    LinkGenerator grailsLinkGenerator

    VkontakteAuthToken createAuthToken(String code) {
        VkontakteAccessToken accessToken = getAccessToken(code)
        Map userDetails = getUserDetails(accessToken.userId as String)
        VkontakteAuthToken securityToken = new VkontakteAuthToken(
                accessToken: accessToken,
                code: code,
                userDetails: userDetails
        )

        return securityToken
    }

    VkontakteAccessToken getAccessToken(String code) {
        String redirectUri = getAbsoluteRedirectUrl()
        def conf = SpringSecurityUtils.securityConfig.vkontakte

        Map params = [
                client_id: conf.appId,
                client_secret: conf.secret,
                code: code,
                redirect_uri: redirectUri,
        ]
        String authUrl = "https://oauth.vk.com/access_token?" + encodeParams(params)
        return requestAccessToken(authUrl)
    }

    Map getUserDetails(String userId) {
        Map params = [
                user_id: userId,
        ]

        String url = "https://api.vk.com/method/users.get?" + encodeParams(params)

        String response = new URL(url).readLines().first()
        def data = JSON.parse(response)
        Map result = [:]

        if (data.response) {
            result = data.response.first() as Map
        } else {
            if (data.error) {
                log.error("users.get error error_code: '${data.error.error_code}' error_msg '${data.error.error_msg}'")
            }
        }

        return result
    }

    private String getAbsoluteRedirectUrl() {
        def conf = SpringSecurityUtils.securityConfig.vkontakte
        String authFilter = conf.filters.redirect.processUrl
        return grailsLinkGenerator.link(uri: authFilter, absolute: true)
    }

    private VkontakteAccessToken requestAccessToken(String authUrl) {
        try {
            URL url = new URL(authUrl)
            String response = url.readLines().first()
            def data = JSON.parse(response)
            VkontakteAccessToken token = new VkontakteAccessToken()
            if (data.access_token) {
                token.accessToken = data.access_token
                token.userId = data.user_id
            } else {
                log.error("No access_token in response: $response")
            }
            if (data.expires_in) {
                if (data.expires_in =~ /^\d+$/) {
                    token.expireAt = VkontakteAccessToken.convertToExpireAt(data.expires_in as Long)
                } else {
                    log.warn("Invalid 'expires' value: $data.expires")
                }
            } else {
                log.error("No expires in response: $response")
            }
            return token
        } catch (IOException e) {
            log.error("Can't read data from Vkontakte", e)
            return null
        }
    }

    String prepareRedirectUrl() {
        String authPath = getAbsoluteRedirectUrl()
        def conf = SpringSecurityUtils.securityConfig.vkontakte
        List scope = conf.permissions

        Map data = [
                client_id: conf.appId,
                redirect_uri: authPath,
                response_type: "code",
                scope: scope?.join(','),
        ]
        log.debug("Redirect to ${data.redirect_uri}")
        String url = "https://oauth.vk.com/authorize?" + encodeParams(data)
        return url
    }

    private static String encodeParams(Map params) {
        return params.entrySet().each { Map.Entry<String, Object> it ->
            [
                    URLEncoder.encode(it.key, 'UTF-8'),
                    URLEncoder.encode(it.value ? it.value.toString() : '', 'UTF-8'),
            ].join('=')
        }.join('&')
    }
}
