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

import com.burig.grails.springsecurity.vkontakte.DefaultVkontakteAuthDao
import com.burig.grails.springsecurity.vkontakte.JsonAuthenticationFailureHandler
import com.burig.grails.springsecurity.vkontakte.JsonAuthenticationSuccessHandler
import com.burig.grails.springsecurity.vkontakte.VkontakteAuthFilter
import com.burig.grails.springsecurity.vkontakte.VkontakteAuthProvider
import com.burig.grails.springsecurity.vkontakte.VkontakteOpenAPIAuthFilter
import grails.plugin.springsecurity.SpringSecurityUtils
import grails.util.Environment
import grails.util.Metadata
import org.apache.commons.logging.LogFactory
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler

class SpringSecurityVkontakteGrailsPlugin {
    // the plugin version
    def version = "1.0-SNAPSHOT"
    // the version or versions of Grails the plugin is designed for
    def grailsVersion = "2.2 > *"
    // resources that are excluded from plugin packaging
    def pluginExcludes = [
            "grails-app/views/error.gsp"
    ]

    Map dependsOn = ['springSecurityCore': '2.0-RC2> *']
    def observe = ["springSecurityCore"]

    def title = 'Vkontakte Authentication for Spring Security'
    def author = "Pavel Burov"
    def authorEmail = "burovpavel@gmail.com"
    def description = 'Vkontakte authentication support for the Spring Security plugin.'

    def license = "APACHE"

    // URL to the plugin's documentation
    def documentation = "http://pavelburov.github.io/grails-spring-security-vkontakte"
    // Location of the plugin's issue tracker.
    def issueManagement = [system: "GitHub", url: "https://github.com/pavelburov/grails-spring-security-vkontakte/issues"]
    // Online location of the plugin's browseable source code.
    def scm = [url: "https://github.com/pavelburov/grails-spring-security-vkontakte"]

    def doWithSpring = {
        if (!this.hasProperty('log')) {
            println 'WARN: No such property: log for class: SpringSecurityVkontakteGrailsPlugin'
            println 'WARN: Running from a unit test?'
            println 'WARN: Introducing a log property for plugin'
            this.metaClass.log = LogFactory.getLog(SpringSecurityVkontakteGrailsPlugin)
        }

        if (Environment.current == Environment.TEST) {
            if (Metadata.getCurrent().getApplicationName() == 'spring-security-vkontakte') {
                println "Test mode. Skipping initial plugin initialization"
                return
            } else {
                log.debug("Run in test mode")
            }
        }

        def conf = SpringSecurityUtils.securityConfig
        if (!conf) {
            println 'ERROR: There is no Spring Security configuration'
            println 'ERROR: Stop configuring Spring Security Vkontakte'
            return
        }

        println 'Configuring Spring Security Vkontakte ...'
        SpringSecurityUtils.loadSecondaryConfig 'DefaultVkontakteSecurityConfig'
        conf = SpringSecurityUtils.securityConfig // have to get again after overlaying Config

        String _vkontakteDaoName

        _vkontakteDaoName = conf?.vkontakte?.bean?.dao ?: null
        if (_vkontakteDaoName == null) {
            _vkontakteDaoName = 'vkontakteAuthDao'

            if (!conf.vkontakte.domain.className) {
                log.error("Don't have vkontakte user class configuration. Please configure 'grails.plugins.springsecurity.vkontakte.domain.className' value")
            }

            vkontakteAuthDao(DefaultVkontakteAuthDao) {
                userConnectionPropertyName = conf.vkontakte.domain.userConnectionPropertyName
                userIdPropertyName = conf.vkontakte.domain.userIdPropertyName
                rolesPropertyName = conf.userLookup.authoritiesPropertyName
                providedUserDomainClassName = conf.vkontakte.domain.className
                userDomainClassName = conf.userLookup.userDomainClassName
                userDetailsService = ref('vkontakteUserDetailsService')
                defaultRoleNames = conf.vkontakte.autoCreate.roles
            }
        } else {
            log.info("Using provided Vkontakte Auth DAO bean: $_vkontakteDaoName")
        }

        SpringSecurityUtils.registerProvider 'vkontakteAuthProvider'
        Boolean _createNew = conf.vkontakte.autoCreate.enabled as Boolean ?: false
        vkontakteAuthProvider(VkontakteAuthProvider) {
            vkontakteAuthDao = ref(_vkontakteDaoName)
            createNew = _createNew
        }

        vkontakteAuthenticationSuccessHandler(SavedRequestAwareAuthenticationSuccessHandler) {
            defaultTargetUrl = conf.vkontakte.filters.redirect.successHandler.defaultTargetUrl
            alwaysUseDefaultTargetUrl = conf.vkontakte.filters.redirect.successHandler.alwaysUseDefaultTargetUrl
            targetUrlParameter = conf.vkontakte.filters.redirect.successHandler.targetUrlParameter
            useReferer = conf.vkontakte.filters.redirect.successHandler.useReferer
        }

        vkontakteAuthenticationFailureHandler(SimpleUrlAuthenticationFailureHandler) {
            defaultFailureUrl = conf.vkontakte.filters.redirect.failureHandler.defaultFailureUrl
            useForward = conf.vkontakte.filters.redirect.failureHandler.useForward
            allowSessionCreation = conf.vkontakte.filters.redirect.failureHandler.allowSessionCreation
        }

        SpringSecurityUtils.registerFilter('vkontakteAuthFilter', conf.vkontakte.filters.redirect.position as int)
        String redirectSuccessHandler = conf.vkontakte.filters.redirect.authenticationSuccessHandler
        String redirectFailureHandler = conf.vkontakte.filters.redirect.authenticationFailureHandler
        vkontakteAuthFilter(VkontakteAuthFilter, conf.vkontakte.filters.redirect.processUrl) {
            authenticationManager = ref('authenticationManager')
            rememberMeServices = ref('rememberMeServices')
            vkontakteAuthUtilsService = ref('vkontakteAuthUtilsService')
            if (redirectSuccessHandler) {
                authenticationSuccessHandler = ref(redirectSuccessHandler)
            } else {
                authenticationSuccessHandler = ref('vkontakteAuthenticationSuccessHandler')
            }
            if (redirectFailureHandler) {
                authenticationFailureHandler = ref(redirectFailureHandler)
            } else {
                authenticationFailureHandler = ref('vkontakteAuthenticationFailureHandler')
            }
        }

        String openApiSuccessHandler = conf.vkontakte.filters.openApi.authenticationSuccessHandler
        String openApiFailureHandler = conf.vkontakte.filters.openApi.authenticationFailureHandler
        SpringSecurityUtils.registerFilter('vkontakteOpenAPIAuthFilter', conf.vkontakte.filters.openApi.position as int)
        vkontakteOpenAPIAuthFilter(VkontakteOpenAPIAuthFilter, conf.vkontakte.filters.openApi.processUrl) {
            authenticationManager = ref('authenticationManager')
            rememberMeServices = ref('rememberMeServices')
            vkontakteAuthUtilsService = ref('vkontakteAuthUtilsService')
            if (openApiSuccessHandler) {
                authenticationSuccessHandler = ref(openApiSuccessHandler)
            } else {
                authenticationSuccessHandler = new JsonAuthenticationSuccessHandler()
            }
            if (openApiFailureHandler) {
                authenticationFailureHandler = ref(openApiFailureHandler)
            } else {
                authenticationFailureHandler = new JsonAuthenticationFailureHandler()
            }
        }

        println '... finished configuring Spring Security Vkontakte'
    }

}
