includeTargets << grailsScript('Init')
includeTargets << grailsScript('_GrailsBootstrap')
includeTargets << new File("$springSecurityCorePluginDir", 'scripts/_S2Common.groovy')

templateDir = "$springSecurityVkontaktePluginDir/src/templates"

target(s2InitVkontakte: 'Initializes Vkontakte artifacts for the Spring Security Vkontakte plugin') {
    depends([checkVersion, configureProxy, packageApp, classpath])

    if (!configure()) {
        return 1
    }

    copyData()
    fillConfig()

    printMessage "**********************************************************************************************  "
    printMessage "How to use:"
    printMessage "  put <vkontakteAuth:connect /> tag into your GSP, where you want to sign in user with Vkontakte"
    printMessage "**********************************************************************************************  "
}

private boolean configure() {
    Class SpringSecurityUtils = classLoader.loadClass('grails.plugin.springsecurity.SpringSecurityUtils')
    def securityConfig = SpringSecurityUtils.securityConfig

    def pluginConfig = [:]
    def configFile = new File("$springSecurityVkontaktePluginDir/grails-app/conf/DefaultVkontakteSecurityConfig.groovy")
    if (configFile.exists()) {
        def conf = new ConfigSlurper().parse(configFile.text)
        pluginConfig = conf.security.vkontakte
    } else {
        errorMessage "Configuration file '$configFile.path' not found"
    }

    ant.input(
            message: "Do you want to create VkontakteUser domain class? (y/n):",
            addproperty: 'vkontakte.createDomain',
            defaultvalue: 'n'
    )

    if (ant.antProject.properties['vkontakte.createDomain'].toLowerCase() == 'y') {
        ant.input(
                message: "Enter name of domain class that will be created for you:",
                addproperty: 'vkontakte.domain.ClassName',
                defaultvalue: pluginConfig.domain.className
        )
    } else {
        ant.input(
                message: "Enter name of existing domain class that you want to use:",
                addproperty: 'vkontakte.domain.ClassName',
                defaultvalue: pluginConfig.domain.className
        )
    }

    String domainClassName = ant.antProject.properties['vkontakte.domain.ClassName']
    String domainPackageName, domainClassSimpleName
    (domainPackageName, domainClassSimpleName) = splitClassName(domainClassName)

    String userClassName = securityConfig.userLookup.userDomainClassName
    String userPackageName, userClassSimpleName
    (userPackageName, userClassSimpleName) = splitClassName(userClassName)

    String userConnectionPropertyName = pluginConfig.domain.userConnectionPropertyName
    String userIdPropertyName = pluginConfig.domain.userIdPropertyName

    templateAttributes = [
            packageName: domainPackageName,
            className: domainClassName,
            classSimpleName: domainClassSimpleName,
            userIdPropertyName: userIdPropertyName,
            userConnectionPropertyName: userConnectionPropertyName,
            userClassName: userClassName,
            userClassSimpleName: userClassSimpleName,
    ]

    return true
}

private void fillConfig() {
    def config = [:]
    String code

    config['vkontakte.domain.className'] = templateAttributes.className

    code = "vkontakte.appId"
    ant.input(message: "Enter your Vkontakte App Id:", addproperty: code)
    config[code] = ant.antProject.properties[code]

    code = "vkontakte.secret"
    ant.input(message: "Enter your Vkontakte App Secret:", addproperty: code)
    config[code] = ant.antProject.properties[code]

    def configFile = new File(appDir as String, 'conf/Config.groovy')
    if (configFile.exists()) {
        configFile.withWriterAppend {
            it.writeLine ""
            config.entrySet().each { Map.Entry conf ->
                it.writeLine "grails.plugin.springsecurity.$conf.key = '$conf.value'"
            }
        }
    }
}

private void copyData() {
    if (ant.antProject.properties['vkontakte.createDomain'].toLowerCase() == 'y') {
        String dir = packageToDir(templateAttributes['packageName'])
        generateFile "$templateDir/VkontakteUser.groovy.template", "$appDir/domain/${dir}${templateAttributes.classSimpleName}.groovy"
    } else if (ant.antProject.properties['vkontakte.createDomain'].toLowerCase() == 'n') {
        // nothing to do
    } else {
        printMessage "Skip VkontakteUser domain configuration"
    }
}

setDefaultTarget(s2InitVkontakte)
