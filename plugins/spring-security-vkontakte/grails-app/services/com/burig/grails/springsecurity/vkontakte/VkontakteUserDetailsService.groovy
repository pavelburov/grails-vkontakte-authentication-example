package com.burig.grails.springsecurity.vkontakte

import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.userdetails.GormUserDetailsService
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UserDetails

class VkontakteUserDetailsService extends GormUserDetailsService {

    @Override
    protected UserDetails createUserDetails(Object user, Collection<GrantedAuthority> authorities) {

        def conf = SpringSecurityUtils.securityConfig

        String usernamePropertyName = conf.userLookup.usernamePropertyName
        String passwordPropertyName = conf.userLookup.passwordPropertyName
        String enabledPropertyName = conf.userLookup.enabledPropertyName
        String accountExpiredPropertyName = conf.userLookup.accountExpiredPropertyName
        String accountLockedPropertyName = conf.userLookup.accountLockedPropertyName
        String passwordExpiredPropertyName = conf.userLookup.passwordExpiredPropertyName

        String username = user."$usernamePropertyName"
        String password = user."$passwordPropertyName"
        boolean enabled = enabledPropertyName ? user."$enabledPropertyName" : true
        boolean accountExpired = accountExpiredPropertyName ? user."$accountExpiredPropertyName" : false
        boolean accountLocked = accountLockedPropertyName ? user."$accountLockedPropertyName" : false
        boolean passwordExpired = passwordExpiredPropertyName ? user."$passwordExpiredPropertyName" : false

        VkontakteUserDetails userDetails = new VkontakteUserDetails(username, password, enabled, !accountExpired, !passwordExpired,
                !accountLocked, authorities, user.id)

        VkontakteAuthDao vkDao = grailsApplication.mainContext.getBean('vkontakteAuthDao') as VkontakteAuthDao
        def vkUser = vkDao.getProvidedUser(user)

        userDetails.firstName = vkUser.firstName
        userDetails.lastName = vkUser.lastName

        return userDetails
    }
}
