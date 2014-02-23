<r:script>
  function ${callback}(response) {
    if (response.session) {
      var jqxhr = jQuery.ajax({
        url: "${url}",
        type: 'POST',
        data: response
      });
      jqxhr.done(function(data, textStatus, xhr) {
        if (data.authenticated) {
          location.reload();
        } else {
          alert(data.message);
        }
      });
      jqxhr.fail(function(xhr, textStatus, errorThrown) {
        alert(textStatus);
      });
    } else {
      alert('${g.message(code: 'plugin.SpringSecurityVkontakte.message.authorization.canceled')}');
    }
  }
</r:script>
