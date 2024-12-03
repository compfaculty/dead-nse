local stdnse = require "stdnse"
local http = require "http"
local json = require "json"

description = [[
Fetch Geo IP information for the target IP using the ip-api.com API.
]]

author = "Your Name"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery"}

-- This rule ensures the script runs against any target with a valid IP address
hostrule = function(host)
    return host.ip ~= nil
end

-- The action function is the main function of the script
action = function(host)
    local ip = host.ip
    local url = "http://ip-api.com/json/" .. ip

    stdnse.print_debug(1, "Querying IP: %s", ip)

    -- Use get_url to handle the full URL properly
    local response = http.get_url(url)

    if not response or response.status ~= 200 then
        return "Failed to retrieve GeoIP information. HTTP request failed."
    end

    -- Capture both the status and parsed JSON object from json.parse
    local parse_success, geo_info = json.parse(response.body)

    -- Check if parsing was successful
    if not parse_success then
        return "Failed to parse GeoIP information: " .. geo_info  -- geo_info will contain the error message
    end

    -- Check if the API returned a success status
    if geo_info.status ~= "success" then
        return "GeoIP lookup failed for IP: " .. ip .. ". API response: " .. (geo_info.message or "Unknown error")
    end

    -- Return GeoIP information
    return string.format("GeoIP Info for %s:\nCountry: %s\nRegion: %s\nCity: %s\nLatitude: %s\nLongitude: %s\nISP: %s", 
                         ip, geo_info.country, geo_info.regionName, geo_info.city, 
                         geo_info.lat, geo_info.lon, geo_info.isp)
end
