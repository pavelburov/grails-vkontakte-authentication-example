import grails.plugin.springsecurity.SecurityFilterPosition

security {

    vkontakte {

        appId = "Invalid"
        secret = 'Invalid'

        domain {
            className = 'VkontakteUser'
            // property name to hold Vkontakte user id
            userIdPropertyName = "vkId"
            // property name to connect with Spring Security User domain class
            userConnectionPropertyName = "user"
        }

        taglib {
            en {
                button {
                    text = "Login with Vkontakte"
                    defaultImg = "/images/vkontakte_button_en.png"
                }
            }
            ru {
                button {
                    text = "Войти через ВКонтакте"
                    defaultImg = "/images/vkontakte_button_ru.png"
                }
            }
        }

        autoCreate {
            enabled = true
            roles = ['ROLE_USER', 'ROLE_VKONTAKTE']
        }

        permissions = []

        filters {
            redirect {
                processUrl = "/j_spring_security_vkontakte_check"
                position = SecurityFilterPosition.OPENID_FILTER.order + 1
                authenticationSuccessHandler = ""
                authenticationFailureHandler = ""
                successHandler {
                    defaultTargetUrl = '/'
                    alwaysUseDefaultTargetUrl = false
                    targetUrlParameter = null
                    useReferer = false
                }
                failureHandler {
                    defaultFailureUrl = '/'
                    useForward = false
                    allowSessionCreation = true
                }
            }
            openApi {
                processUrl = "/j_spring_security_vkontakte_open_api_check"
                position = SecurityFilterPosition.OPENID_FILTER.order + 2
                authenticationSuccessHandler = ""
                authenticationFailureHandler = ""
            }
        }

    }
}
