<%@ page contentType="text/html;charset=UTF-8" %>
<html>
  <head>
    <meta name="layout" content="main" />
    <title>demo</title>
  </head>

  <body>
    <sec:ifNotLoggedIn>
      <div style="margin: 10px;">
        <vkontakteAuth:connect />
      </div>

      <div style="margin: 10px;">
        <g:link params="[lang: 'en']">en</g:link>
        <g:link params="[lang: 'ru']">ru</g:link>
      </div>

      <div style="margin: 10px;">
        <vkontakteAuth:button id="login_button" />
      </div>
    </sec:ifNotLoggedIn>
    <sec:ifLoggedIn>
      <div style="margin: 10px;">
        Welcome <vkontakteAuth:username />! (<g:link uri="/j_spring_security_logout">Logout</g:link>)
      </div>
    </sec:ifLoggedIn>
  </body>
</html>
