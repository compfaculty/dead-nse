local nmap = require "nmap"
local shortport = require "shortport"
local http = require "http"
local upnp = require "upnp"
local snmp = require "snmp"
local stdnse = require "stdnse"

description = [[
    Script to identify if a device is a router by scanning multiple services, such as HTTP, UPnP, and SNMP. 
    It detects router models and manufacturer information from various sources, including RouterOS and other networking devices.
    Usage:
    nmap --script router_detection.lua -iL ip_list.txt
]]

author = "HackerGPT&AlexG"
license = "Same as Nmap"
categories = {"discovery"}

-- Define user options for HTTP, UPnP, and SNMP
portrule = shortport.port_or_service({80, 443, 1900, 161}, {"http", "https", "upnp", "snmp"})

-- Expanded table of router models, including RouterOS and similar devices
local known_routers = {
    -- Zyxel
    ["Zyxel Keenetic Omni II"] = "Zyxel",
    ["Zyxel VMG3625-T50B"] = "Zyxel",
    ["Zyxel VMG3925-B10B"] = "Zyxel",

    -- TP-Link
    ["TP-Link Archer C7"] = "TP-Link",
    ["TP-Link Deco X60"] = "TP-Link",
    ["TP-Link TL-WR841N"] = "TP-Link",

    -- D-Link
    ["D-Link DIR-815"] = "D-Link",
    ["D-Link DIR-825"] = "D-Link",
    ["D-Link DIR-882"] = "D-Link",

    -- Netgear
    ["Netgear Nighthawk R7000"] = "Netgear",
    ["Netgear Orbi RBR50"] = "Netgear",
    ["Netgear Nighthawk AX12"] = "Netgear",

    -- Huawei
    ["Huawei HG8245H"] = "Huawei",
    ["Huawei EchoLife HG8145V"] = "Huawei",

    -- MikroTik (RouterOS Devices)
    ["MikroTik hAP ac2"] = "MikroTik RouterOS",
    ["MikroTik RB750Gr3"] = "MikroTik RouterOS",
    ["MikroTik CCR1009"] = "MikroTik RouterOS",
    ["MikroTik RB4011iGS+5HacQ2HnD-IN"] = "MikroTik RouterOS",

    -- Ubiquiti (RouterOS-like)
    ["Ubiquiti UniFi AP"] = "Ubiquiti",
    ["Ubiquiti EdgeRouter X"] = "Ubiquiti",
    ["Ubiquiti EdgeSwitch"] = "Ubiquiti",

    -- Fortinet
    ["Fortinet FortiGate 60E"] = "Fortinet",

    -- Cisco Devices (including routers and switches)
    ["Cisco RV340"] = "Cisco",
    ["Cisco ISR 4331"] = "Cisco",
    ["Cisco Catalyst 2960"] = "Cisco",
    ["Cisco Meraki MX64"] = "Cisco Meraki",
    ["Cisco ASA 5505"] = "Cisco",

    -- Juniper Networks
    ["Juniper SRX300"] = "Juniper Networks",
    ["Juniper MX5"] = "Juniper Networks",
    ["Juniper EX2300"] = "Juniper Networks",

    -- Tenda
    ["Tenda AC6"] = "Tenda",
    ["Tenda AC10"] = "Tenda",

    -- Linksys
    ["Linksys E1200"] = "Linksys",
    ["Linksys E2500"] = "Linksys",

    -- Netis
    ["Netis WF2419E"] = "Netis",
    ["Netis N2"] = "Netis",

    -- ZTE
    ["ZTE ZXHN H298A"] = "ZTE",
    ["ZTE F660"] = "ZTE",

    -- ASUS
    ["ASUS RT-AC68U"] = "ASUS",
    ["ASUS RT-AX88U"] = "ASUS",

    -- Nokia
    ["Nokia G-240W-A"] = "Nokia",

    -- Belkin
    ["Belkin N300"] = "Belkin",

    -- Synology
    ["Synology RT2600ac"] = "Synology",

    -- DrayTek
    ["DrayTek Vigor 2925"] = "DrayTek",
    ["DrayTek Vigor 2762"] = "DrayTek",
}

-- Function to determine if the device is a router using HTTP headers
local function check_http_router(host, port)
    local response, err = http.get(host, port, "/")
    if not response then
        return false, nil
    end
    local server_header = tostring(response.header["server"] or "nil")
    local www_authenticate_header = tostring(response.header["www-authenticate"] or "nil")
    
    for model, vendor in pairs(known_routers) do
        if server_header:lower():find(model:lower()) or www_authenticate_header:lower():find(model:lower()) then
            return true, model
        end
    end
    return false, nil
end

-- Function to determine if the device is a router using UPnP
local function check_upnp_router(host)
    local status, result = upnp.discover(host)
    if status and result then
        for _, device in pairs(result) do
            if device.type and device.type:lower():find("internetgatewaydevice") then
                local manufacturer = device.manufacturer or "Unknown"
                local model = device.model or "Unknown"
                return true, string.format("%s %s", manufacturer, model)
            end
        end
    end
    return false, nil
end

-- Function to determine if the device is a router using SNMP (e.g., sysDescr OID)
local function check_snmp_router(host)
    local community = "public"
    local session, err = snmp.open(host.ip, community)
    if not session then
        return false, nil
    end

    local result = session:get(".1.3.6.1.2.1.1.1.0")  -- sysDescr OID
    if result then
        for model, vendor in pairs(known_routers) do
            if result:lower():find(model:lower()) then
                return true, model
            end
        end
    end
    session:close()
    return false, nil
end

-- Main action function
action = function(host, port)
    -- First, attempt router detection via HTTP
    local is_router_http, router_model_http = check_http_router(host, port)
    if is_router_http then
        stdnse.print_debug(1, "Host %s identified as a router via HTTP: %s", tostring(host.ip), router_model_http)
        print("Host: " .. tostring(host.ip) .. " - Router Model: " .. router_model_http)
        return
    end

    -- Next, try detecting router via UPnP (common on routers)
    local is_router_upnp, router_model_upnp = check_upnp_router(host)
    if is_router_upnp then
        stdnse.print_debug(1, "Host %s identified as a router via UPnP: %s", tostring(host.ip), router_model_upnp)
        print("Host: " .. tostring(host.ip) .. " - Router Model: " .. router_model_upnp)
        return
    end

    -- Lastly, attempt to identify router via SNMP
    local is_router_snmp, router_model_snmp = check_snmp_router(host)
    if is_router_snmp then
        stdnse.print_debug(1, "Host %s identified as a router via SNMP: %s", tostring(host.ip), router_model_snmp)
        print("Host: " .. tostring(host.ip) .. " - Router Model: " .. router_model_snmp)
        return
    end

    stdnse.print_debug(1, "Host %s is not identified as a router.", tostring(host.ip))
end
