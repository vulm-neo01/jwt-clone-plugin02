local jwt_decoder = require "kong.plugins.jwt.jwt_parser"
local ngx_re_gmatch = ngx.re.gmatch
local cjson = require "cjson"

local plugin = {
  PRIORITY = 2000, -- set the plugin priority, which determines plugin execution order
  VERSION = "0.1.0-1", -- version in X.Y.Z format. Check hybrid-mode compatibility requirements.
}

local function retrieve_token(request, conf)
  local request_headers = request.get_headers()
  local authorization_header = request_headers["authorization"]

  if not request_headers then
    return kong.response.exit(500, "jwt-auth -- Authorization header is empty")
  end

  if not authorization_header then
    return kong.response.exit(500, "jwt-auth -- Authorization header is missing")
  end

  if authorization_header then
    local iterator, iter_err = ngx_re_gmatch(authorization_header, "\\s*[Bb]earer\\s+(.+)")

    if not iterator then
      return nil, iter_err
    end

    local m, err = iterator()

    if err then
      return nil, err
    end

    if m and #m > 0 then
      return m[1]
    end
  end
end


-- runs in the 'access_by_lua_block'
function plugin:access(plugin_conf)
  local set_header = kong.service.request.set_header

  local token, err = retrieve_token(kong.request, plugin_conf)

  if err then
    return kong.response.exit(500, "jwt-auth -- Error when retrieving token")
  end
  kong.log.debug(token)

  local network_type = plugin_conf.network_type or ""
  local zone_id = plugin_conf.zone_id or ""
  local lang = plugin_conf.lang or ""
  local ips = plugin.verified_IPs or {}
  local blocked_devices = plugin.blocked_devices or {}

  local request_ip = kong.client.get_forwarded_ip()

  local isIPMatch = false

  for _, ip in ipairs(ips) do
      if ip == request_ip then
          isIPMatch = true
          break
      end
  end

  if isIPMatch then
      kong.response.exit(403, "jwt-auth - Forbidden: IP not allowed")
  end

  if token then

  end

  kong.response.set_header("X-Forwarded-Request-IP", kong.client.get_forwarded_ip())
  kong.response.set_header("X-Request-IP", kong.client.get_ip())
  kong.response.set_header("Config-Zone-id", plugin_conf.zone_id)
  kong.response.set_header("Config-Network-type", plugin_conf.network_type)
  kong.response.set_header("Config-Language", plugin_conf.lang)
  kong.response.set_header("Config-list-Ip", plugin_conf.verified_IPs[1])
end

return plugin
