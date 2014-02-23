Example for Vkontakte Authentication plugin for Grails
====================================================

How to run
----------

Setup an Vkontakte App, configure app by adding into `Config.groovy`

```
grails.plugin.springsecurity.vkontakte.appId = "%APP_ID%"
grails.plugin.springsecurity.vkontakte.secret = "%APP_SECRET%"
```

Configure `hosts` to use your Vkontakte App domain.
You can make a fake domain like `dev.myapp.com`, by putting into `/etc/hosts` the following line:

```
127.0.0.1 dev.myapp.com
```

If you already have line starting with `127.0.0.1`, just add your `dev.myapp.com` at the end of the line.

See more details about hosts file, and location of the file for different operation systems see: [hosts (file)](http://en.wikipedia.org/wiki/Hosts_(file))

and then you can:

```
grails run-app
```

open:

```
http://dev.myapp.com:8080/vkontakte-authentication-example
```

Links
-----

  * [Plugin sources](https://github.com/pavelburov/grails-spring-security-vkontakte)
  * [Plugin documentation](http://pavelburov.github.io/grails-spring-security-vkontakte)

Author
------

Pavel Burov (burovpavel@gmail.com)
