local nmap = require "nmap"
local shortport = require "shortport"

description = [[
This script runs Nuclei on ports 80 and 443 of each target host.
]]

author = "Your Name"

-- Define which ports the script applies to
portrule = shortport.port_or_service({80, 443}, {"http", "https"})

action = function(host, port)
    local target_ip = host.ip
    local target_port = port.number

    -- Build the Nuclei command
    local nuclei_cmd = string.format("/root/go/bin/nuclei -u %s:%d", target_ip, target_port)

    -- Execute the command and capture the output
    local result = os.execute(nuclei_cmd)

    -- Return the result of the nuclei scan
    return result
end
