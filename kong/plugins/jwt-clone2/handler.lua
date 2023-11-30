local http = require("resty.http")

local plugin = {
  PRIORITY = 1000, -- set the plugin priority, which determines plugin execution order
  VERSION = "0.1", -- version in X.Y.Z format. Check hybrid-mode compatibility requirements.
}


-- runs in the 'access_by_lua_block'
function plugin:access(plugin_conf)


  -- your custom code here
  local auth_header = kong.request.get_header(plugin_conf.auth_header)
  if not auth_header then
    kong.response.exit(403, "Unauthenticated!")
  end

  -- kong.service.request.set_header(plugin_conf.request_header, "this is on a request")
  local httpc = http.new()

  local res, err = httpc:request_uri(plugin_conf.auth_url, {
    method = "GET",
    body = "token="..auth_header,
    headers = {
      ["Content-Type"] = "application/text",
    },
  })
  if not res then
    ngx.log(ngx.ERR, "request failed: ", err)
    return kong.response.exit(500, "Internal server error")
  end


  kong.log.inspect(res)
end --]]

return plugin
