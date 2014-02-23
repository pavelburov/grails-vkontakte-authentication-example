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
import grails.plugin.springsecurity.userdetails.GormUserDetailsService
import org.apache.log4j.Logger
import org.codehaus.groovy.grails.commons.GrailsApplication
import org.codehaus.groovy.grails.plugins.support.aware.GrailsApplicationAware
import org.springframework.beans.factory.InitializingBean
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.dao.OptimisticLockingFailureException
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.GrantedAuthorityImpl
import org.springframework.security.core.userdetails.UserDetails

import java.util.concurrent.TimeUnit

/**
 *
 * @author Pavel Burov
 */
class DefaultVkontakteAuthDao implements VkontakteAuthDao<Object, Object>, InitializingBean, ApplicationContextAware, GrailsApplicationAware {

    private static def log = Logger.getLogger(this)

    GrailsApplication grailsApplication
    ApplicationContext applicationContext
    def userDetailsService

    String userConnectionPropertyName = 'user'

    String rolesPropertyName

    List<String> defaultRoleNames = ['ROLE_USER', 'ROLE_VKONTAKTE']

    def vkontakteAuthService

    String userIdPropertyName

    /**
     * Name of plugin provided user domain class
     */
    String providedUserDomainClassName

    /**
     * Name of spring security provided user domain class
     */
    String userDomainClassName

    private boolean isSameDomain() {
        return getProvidedUserDomainClass() == getUserDomainClass()
    }

    private Class getProvidedUserDomainClass() {
        return grailsApplication.getDomainClass(providedUserDomainClassName)?.clazz
    }

    private Class getUserDomainClass() {
        return grailsApplication.getDomainClass(userDomainClassName)?.clazz
    }

    Object getProvidedUser(Object appUser) {
        if (vkontakteAuthService && appUser != null && vkontakteAuthService.respondsTo('getProvidedUser', appUser.class)) {
            return vkontakteAuthService.getProvidedUser(appUser)
        }
        if (isSameDomain()) {
            return appUser
        } else {
            Object loaded = null
            Class DomainClass = getProvidedUserDomainClass()
            DomainClass.withTransaction { status ->
                loaded = DomainClass.findWhere((userConnectionPropertyName): appUser)
            }
            return loaded
        }
    }

    Object getAppUser(Object providedUser) {
        if (vkontakteAuthService && providedUser != null && vkontakteAuthService.respondsTo('getAppUser', providedUser.class)) {
            return vkontakteAuthService.getAppUser(providedUser)
        }
        if (providedUser == null) {
            log.warn("Passed providedUser is null")
            return null
        }
        if (isSameDomain()) {
            return providedUser
        } else {
            Object result = null
            getProvidedUserDomainClass().withTransaction { status ->
                providedUser.merge()
                result = providedUser.getProperty(userConnectionPropertyName)
            }
            return result
        }
    }

    Object findUser(VkontakteAuthToken token) {
        if (vkontakteAuthService && vkontakteAuthService.respondsTo('findUser', Long)) {
            return vkontakteAuthService.findUser(token)
        }
        Object user = null
        Class DomainClass = getProvidedUserDomainClass()
        DomainClass.withTransaction { status ->
            user = DomainClass.findWhere("${userIdPropertyName}": token.getUserId())
            if (user == null) {
                return user
            }
            if (!isSameDomain()) {
                if (userConnectionPropertyName != null && userConnectionPropertyName.length() > 0) {
                    // load the User object to memory prevent LazyInitializationException
                    Object appUser = user.getProperty(userConnectionPropertyName)
                    if (appUser == null) {
                        log.warn("No appUser for providedUser ${user}. Property ${userConnectionPropertyName} have null value")
                    }
                } else {
                    log.error("userConnectionPropertyName is not configured")
                }
            }
        }
        return user
    }

    Object create(VkontakteAuthToken token) {
        if (vkontakteAuthService && vkontakteAuthService.respondsTo('create', VkontakteAuthToken)) {
            return vkontakteAuthService.create(token)
        }

        def securityConf = SpringSecurityUtils.securityConfig
        Class DomainClass = getProvidedUserDomainClass()

        def user = DomainClass.newInstance()
        user.setProperty("${userIdPropertyName}", token.getUserId())
        if (user.hasProperty('accessToken')) {
            user.setProperty('accessToken', token.accessToken?.accessToken)
        }
        if (user.hasProperty('accessTokenExpires')) {
            user.setProperty('accessTokenExpires', token.accessToken?.expireAt)
        }

        if (token.userDetails) {
            if (user.hasProperty('firstName')) {
                user.setProperty('firstName', token.userDetails.first_name)
            }
            if (user.hasProperty('lastName')) {
                user.setProperty('lastName', token.userDetails.last_name)
            }
        }

        def appUser
        if (!isSameDomain()) {
            if (vkontakteAuthService && vkontakteAuthService.respondsTo('createAppUser', DomainClass, VkontakteAuthToken)) {
                appUser = vkontakteAuthService.createAppUser(user, token)
            } else {
                Class AppUserDomainClass = getUserDomainClass()

                appUser = AppUserDomainClass.newInstance()
                if (vkontakteAuthService && vkontakteAuthService.respondsTo('prepopulateAppUser', AppUserDomainClass, VkontakteAuthToken)) {
                    vkontakteAuthService.prepopulateAppUser(appUser, token)
                } else {
                    appUser.setProperty(securityConf.userLookup.usernamePropertyName, "vkontakte_${token.getUserId()}")
                    appUser.setProperty(securityConf.userLookup.passwordPropertyName, token.accessToken?.accessToken)
                    appUser.setProperty(securityConf.userLookup.enabledPropertyName, true)
                    appUser.setProperty(securityConf.userLookup.accountExpiredPropertyName, false)
                    appUser.setProperty(securityConf.userLookup.accountLockedPropertyName, false)
                    appUser.setProperty(securityConf.userLookup.passwordExpiredPropertyName, false)
                }
                AppUserDomainClass.withTransaction {
                    appUser.save(flush: true, failOnError: true)
                }
            }
            user[userConnectionPropertyName] = appUser
        } else {
            appUser = user
        }

        if (vkontakteAuthService && vkontakteAuthService.respondsTo('onCreate', DomainClass, VkontakteAuthToken)) {
            vkontakteAuthService.onCreate(user, token)
        }

        DomainClass.withTransaction {
            user.save(flush: true, failOnError: true)
        }

        if (vkontakteAuthService && vkontakteAuthService.respondsTo('afterCreate', DomainClass, VkontakteAuthToken)) {
            vkontakteAuthService.afterCreate(user, token)
        }

        if (vkontakteAuthService && vkontakteAuthService.respondsTo('createRoles', DomainClass)) {
            vkontakteAuthService.createRoles(user)
        } else {
            Class<?> PersonRole = grailsApplication.getDomainClass(securityConf.userLookup.authorityJoinClassName)?.clazz
            Class<?> Authority = grailsApplication.getDomainClass(securityConf.authority.className)?.clazz
            String authorityNameField = securityConf.authority.nameField
            String findByField = authorityNameField[0].toUpperCase() + authorityNameField.substring(1)
            PersonRole.withTransaction { status ->
                defaultRoleNames.each { String roleName ->
                    def auth = Authority."findBy${findByField}"(roleName)
                    if (auth) {
                        PersonRole.create(appUser, auth)
                    } else {
                        log.error("Can't find authority for name '$roleName'")
                    }
                }
            }

        }

        return user
    }

    Object getPrincipal(Object user) {
        if (vkontakteAuthService && user != null && vkontakteAuthService.respondsTo('getPrincipal', user.class)) {
            return vkontakteAuthService.getPrincipal(user)
        }
        if (userDetailsService) {
            return userDetailsService.createUserDetails(user, getRoles(user))
        }
        return user
    }

    Collection<GrantedAuthority> getRoles(Object user) {
        if (vkontakteAuthService && user != null && vkontakteAuthService.respondsTo('getRoles', user.class)) {
            return vkontakteAuthService.getRoles(user)
        }

        if (user == null) {
            return []
        }

        if (UserDetails.isAssignableFrom(user.class)) {
            return ((UserDetails) user).getAuthorities()
        }

        def conf = SpringSecurityUtils.securityConfig
        Class<?> PersonRole = grailsApplication.getDomainClass(conf.userLookup.authorityJoinClassName)?.clazz
        if (!PersonRole) {
            log.error("Can't load roles for user $user. Reason: can't find ${conf.userLookup.authorityJoinClassName} class")
            return []
        }
        Collection roles = []
        PersonRole.withTransaction { status ->
            roles = user?.getProperty(rolesPropertyName)
        }
        if (!roles) {
            roles = []
        }
        if (roles.empty) {
            return roles
        }
        return roles.collect {
            if (it instanceof String) {
                return new GrantedAuthorityImpl(it.toString())
            } else {
                new GrantedAuthorityImpl(it.getProperty(conf.authority.nameField))
            }
        }
    }

    Boolean hasValidToken(Object providedUser) {
        if (vkontakteAuthService && providedUser != null && vkontakteAuthService.respondsTo('hasValidToken', providedUser.class)) {
            return vkontakteAuthService.hasValidToken(providedUser)
        }
        if (providedUser.hasProperty('accessToken')) {
            if (providedUser.getProperty('accessToken') == null) {
                return false
            }
        }
        if (providedUser.hasProperty('accessTokenExpires')) {
            if (providedUser.getProperty('accessTokenExpires') == null) {
                return false
            }
            Date goodExpiration = new Date(System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(15))
            Date currentExpires = providedUser.getProperty('accessTokenExpires')
            if (currentExpires.before(goodExpiration)) {
                return false
            }
        } else {
            log.warn("Domain ${providedUser.class} don't have 'acccessTokenExpires' field, can't check accessToken expiration. And it's very likely that your database contains expired tokens")
        }
        return true
    }

    void updateToken(Object providedUser, VkontakteAuthToken token) {
        if (vkontakteAuthService && providedUser != null && vkontakteAuthService.respondsTo('updateToken', providedUser.class, VkontakteAuthToken)) {
            vkontakteAuthService.updateToken(providedUser, token)
            return
        }
        if (token.accessToken == null) {
            log.error("No access token $token")
            return
        }
        if (token.accessToken.accessToken == null) {
            log.warn("Update to empty accessToken for user $providedUser")
        }
        log.debug("Update access token to $token.accessToken for $providedUser")
        getProvidedUserDomainClass().withTransaction {
            try {
                boolean updated = false
                if (!providedUser.isAttached()) {
                    providedUser.attach()
                }
                if (providedUser.hasProperty('accessToken')) {
                    if (providedUser.getProperty('accessToken') != token.accessToken.accessToken) {
                        updated = true
                        providedUser.setProperty('accessToken', token.accessToken.accessToken)
                    }
                }
                if (updated && providedUser.hasProperty('accessTokenExpires')) {
                    if (!equalDates(providedUser.getProperty('accessTokenExpires'), token.accessToken.expireAt)) {
                        if (token.accessToken.expireAt != null || token.accessToken.accessToken == null) {
                            //allow null only if both expireAt and accessToken are null
                            updated = true
                            providedUser.setProperty('accessTokenExpires', token.accessToken.expireAt)
                        } else {
                            log.warn("Provided accessToken.expiresAt value is null. Skip update")
                        }
                    } else {
                        log.warn("A new accessToken have same token but different expires: $token")
                    }
                }

                if (token.userDetails) {
                    if (providedUser.hasProperty('firstName')) {
                        if (providedUser.getProperty('firstName') != token.userDetails.first_name) {
                            updated = true
                            providedUser.setProperty('firstName', token.userDetails.first_name)
                        }
                    }
                    if (providedUser.hasProperty('lastName')) {
                        if (providedUser.getProperty('lastName') != token.userDetails.last_name) {
                            updated = true
                            providedUser.setProperty('lastName', token.userDetails.last_name)
                        }
                    }
                }

                if (updated) {
                    providedUser.save()
                }
            } catch (OptimisticLockingFailureException e) {
                log.warn("Seems that token was updated in another thread (${e.message}). Skip")
            } catch (Throwable e) {
                log.error("Can't update token", e)
            }
        }
    }

    boolean equalDates(Object x, Object y) {
        long xtime = dateToLong(x)
        long ytime = dateToLong(y)
        return xtime >= 0 && ytime >= 0 && Math.abs(xtime - ytime) < 1000 //for dates w/o millisecond
    }

    long dateToLong(Object date) {
        if (date == null) {
            return -1
        }
        if (date instanceof Date) { //java.sql.Timestamp extends Date
            return date.time
        }
        if (date instanceof Number) {
            return date.toLong()
        }
        log.warn("Cannot convert date: $date (class: ${date.class})")
        return -1
    }

    String getAccessToken(Object providedUser) {
        if (vkontakteAuthService && providedUser != null && vkontakteAuthService.respondsTo('getAccessToken', providedUser.class)) {
            return vkontakteAuthService.getAccessToken(providedUser)
        }
        if (providedUser.hasProperty('accessToken')) {
            if (providedUser.hasProperty('accessTokenExpires')) {
                Date currentExpires = providedUser.getProperty('accessTokenExpires')
                if (currentExpires == null) {
                    log.debug("Current access token don't have expiration timeout, and should be updated")
                    return null
                }
                if (currentExpires.before(new Date())) {
                    log.debug("Current access token is expired, and cannot be used anymore")
                    return null
                }
            }
            return providedUser.getProperty('accessToken')
        }
        return null
    }

    void afterPropertiesSet() {
        if (!vkontakteAuthService) {
            if (applicationContext.containsBean('vkontakteAuthService')) {
                log.debug("Use provided vkontakteAuthService")
                vkontakteAuthService = applicationContext.getBean('vkontakteAuthService')
            }
        }

        //validate configuration

        List serviceMethods = []
        if (vkontakteAuthService) {
            vkontakteAuthService.metaClass.methods.each {
                serviceMethods << it.name
            }
        }

        def conf = SpringSecurityUtils.securityConfig
        if (!serviceMethods.contains('getRoles')) {
            Class AppUserDomainClass = getUserDomainClass()
            if (AppUserDomainClass == null || !UserDetails.isAssignableFrom(AppUserDomainClass)) {
                if (!conf.userLookup.authorityJoinClassName) {
                    log.error("Don't have 'User' class configuration. Please configure 'grails.plugins.springsecurity.userLookup.userDomainClassName' value")
                } else if (!grailsApplication.getDomainClass(conf.userLookup.userDomainClassName)) {
                    log.error("Can't find 'User' class (${conf.userLookup.userDomainClassName}). Please configure 'grails.plugins.springsecurity.userLookup.userDomainClassName' value")
                }
            }
        }

        if (userDetailsService != null) {
            if (!(userDetailsService.respondsTo('createUserDetails'))) {
                log.error("UserDetailsService from spring-security-core don't have method 'createUserDetails()'")
                userDetailsService = null
            } else if (!(userDetailsService instanceof GormUserDetailsService)) {
                log.warn("UserDetailsService from spring-security-core isn't instance of GormUserDetailsService, but: ${userDetailsService.class}")
            }
        } else {
            log.warn("No UserDetailsService bean from spring-security-core")
        }
    }
}
