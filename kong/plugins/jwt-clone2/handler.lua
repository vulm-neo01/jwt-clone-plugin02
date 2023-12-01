local jwt_decoder = require "kong.plugins.jwt.jwt_parser"
local ngx_re_gmatch = ngx.re.gmatch

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
  -- local set_header = kong.service.request.set_header
  local token, err1 = retrieve_token(kong.request, plugin_conf)

  if err1 then
    return kong.response.exit(500, "jwt-auth -- Error when retrieving token")
  end
  kong.log.debug(token)

  local network_type = plugin_conf.network_type or ""
  local zone_id = plugin_conf.zone_id or ""
  local lang = plugin_conf.lang or ""
  local ips = plugin_conf.verified_IPs or {}
  local blocked_devices = plugin_conf.blocked_devices or {}

  local request_ip = kong.client.get_forwarded_ip()

  local isIPMatch = false

  kong.log.debug("Request IP: ", request_ip)
  for _, ip in ipairs(ips) do
      kong.log.debug("Checking IP: ", ip)
      if ip == request_ip then
          isIPMatch = true
          break
      end
  end

  if not isIPMatch then
      kong.response.exit(403, "jwt-auth - Forbidden: IP not allowed: "..request_ip)
  end

  if token then
    local jwt, err2 = jwt_decoder:new(token)
    if err2 then
      kong.log.err("Fail to decode token!")
      return kong.response.exit(500, "jwt-auth - Token was found, but failed to decoded")
    end

    local jwt_claims = jwt.claims
    local headers = kong.request.get_headers()
    kong.log.debug(jwt_claims)

    local isBlockedDevice = false
    local dvi = jwt_claims.dvi
    local userId = jwt_claims.userId or ""
    local profileId = jwt_claims.profileId or ""
    local gname = jwt_claims.gname or ""
    local contentFilter = jwt_claims.contentFilter or ""

    if not dvi then
      kong.log.err("Cant find device code!")
      return kong.response.exit(500, "jwt-auth - Cant find device code from token")
    end

    kong.log.debug("DVI:"..dvi)
    for _, block_dvi in ipairs(blocked_devices) do
      kong.log.debug("Dvi blocked: "..block_dvi)
      if dvi == block_dvi then
        isBlockedDevice = true
        break
      end
    end

    if isBlockedDevice then
      kong.response.exit(403, "Device is blocked")
    end

    kong.log.debug(headers)

    kong.response.set_header("Zone-id", zone_id)
    kong.response.set_header("User-Id", userId)
    kong.response.set_header("Profile-Id", profileId)
    kong.response.set_header("Content-Filter",contentFilter)
    kong.response.set_header("Gname",gname)
    kong.response.set_header("dvi",dvi)
    kong.response.set_header("Network-type", network_type)
    kong.response.set_header("X-Forwarded-Request-IP", kong.client.get_forwarded_ip())
    kong.response.set_header("X-Request-IP", kong.client.get_ip())
    kong.response.set_header("Language", lang)
  end
end

return plugin
