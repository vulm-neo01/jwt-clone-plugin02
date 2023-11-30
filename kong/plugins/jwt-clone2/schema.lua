local typedefs = require "kong.db.schema.typedefs"


local PLUGIN_NAME = "jwt-clone2"

local schema = {
  name = PLUGIN_NAME,
  fields = {
    -- the 'fields' array is the top-level entry with fields defined by Kong
    { consumer = typedefs.no_consumer },  -- this plugin cannot be configured on a consumer (typical for auth plugins)
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          {
            zone_id = {
              description = "Zone identification",
              type = "string",
              default = "vn001",
            },
          },
          {
            network_type = {
              description = "Network type defined here: Viettel, Vina, Mobifone,...",
              type = "string",
              default = "viettel",
            },
          },
          {
            lang = {
              description = "Language can using",
              type = "string",
              default = "en",
            },
          },
          {
            verified_IPs = {
              description = "List of Ip that can send request to system.",
              type = "array",
              elements = {
                type = "string",
              },
              default = {"10.1.1.1"}
            }
          },
          {
            blocked_devices = {
              description = "List of device is blocked",
              type = "array",
              elements = {
                type = "string",
              },
              default = {"iphone"}
            }
          },
        }
      },
    },
  },
}

return schema
