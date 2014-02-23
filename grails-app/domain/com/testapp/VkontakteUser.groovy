package com.testapp

import com.testapp.User

class VkontakteUser {

    Long vkId
    String accessToken
    Date accessTokenExpires

    String firstName
    String lastName

    static belongsTo = [user: User]

    static constraints = {
        vkId unique: true
        firstName(nullable: true)
        lastName(nullable: true)
   }
}
