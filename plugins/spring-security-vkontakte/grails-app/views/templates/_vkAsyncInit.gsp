<div id="vk_api_transport"></div>
<r:script type="text/javascript">
  window.vkAsyncInit = function() {
    VK.init({
      apiId: ${appId}
    });
  };

  setTimeout(function() {
    var el = document.createElement("script");
    el.type = "text/javascript";
    el.src = "//vk.com/js/api/openapi.js";
    el.async = true;
    document.getElementById("vk_api_transport").appendChild(el);
  }, 0);
</r:script>
