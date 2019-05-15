local trim15 = require("trim")
local http = require("socket.http")
local ltn12 = require("ltn12")

-- Convert Centreon severity to Evanios severity
local function get_evanios_severity(alert_type, alert_severity)
  local evanios_severity = 5
  
  -- EVANIOS SEVERITY
  -- 6 = HARMLESS
  -- 5 = INFO
  -- 4 = WARNING
  -- 3 = MINOR
  -- 2 = MAJOR
  -- 1 = CRITICAL
  
  -- CENTREON SEVERITY (HOST)
  -- 2 = UNREACHABLE
  -- 1 = DOWN
  -- 0 = UP
  
  -- CENTREON SEVERITY (SERVICE)
  -- 3 = UNKNOWN
  -- 2 = CRITICAL
  -- 1 = WARNING
  -- 0 = OK
  
  if alert_type == "HOST" then
    if alert_severity == 2 then
      evanios_severity = 1
    elseif alert_severity == 1 then
      evanios_severity = 1
    elseif alert_severity == 0 then
      evanios_severity = 6
    end
  elseif alert_type == "SERVICE" then
    if alert_severity == 3 then
      evanios_severity = 3
    elseif alert_severity == 2 then
      evanios_severity = 1
    elseif alert_severity == 1 then
      evanios_severity = 4
    elseif alert_severity == 0 then
      evanios_severity = 6
    end
  end
  
  return evanios_severity
end

-- Convert state type id to state type string (SOFT/HARD)
local function get_centreon_state_type(state_type)
  local state_type_str
  
  if state_type == 0 then
    state_type_str = "SOFT"
  elseif state_type == 1 then
    state_type_str = "HARD"
  else
    state_type_str = "UNKNOWN"
  end
  
  return state_type_str
end

-- Convert state id to state string
local function get_centreon_severity(state, alert_type)
  local severity
  
  if alert_type == "HOST" then
    if state == 0 then
      severity = "UP"
    elseif state == 1 then
      severity = "DOWN"
    elseif state == 2 then
      severity = "UNREACHABLE"
    else
      severity = "UNKNOWN"
    end
  elseif alert_type == "SERVICE" then
    if state == 0 then
      severity = "OK"
    elseif state == 1 then
      severity = "WARNING"
    elseif state == 2 then
      severity = "CRITICAL"
    else
      severity = "UNKNOWN"
    end
  end
  
  return severity
end

local function cleanAndTrim(text)
  local clean_text = trim(text)
  clean_text = string.gsub(clean_text, '&','&amp;')
  clean_text = string.gsub(clean_text, '<','&lt;')
  clean_text = string.gsub(clean_text, '>','&gt;')
  clean_text = string.gsub(clean_text, '"','&quot;')
  clean_text = string.gsub(clean_text, '\'','&apos;')
  
  return clean_text      
end

-- Generate XML to send it to Evanios
local function generate_xml(hostname, service_description, hostgroups, d, target)
  local xml
  local evanios_severity
  local event_type
  local state_type
  local centreon_severity
  local downtime = 0
  
  if not service_description then
    evanios_severity = get_evanios_severity("HOST", d.state)
    event_type = "HOST"
    service_description = "PING"
  else
    evanios_severity = get_evanios_severity("SERVICE", d.state)
    event_type = "SERVICE"
  end
  
  state_type = get_centreon_state_type(d.state_type)
  centreon_severity = get_centreon_severity(d.state, event_type)
  centreon_last_severity = get_centreon_severity(d.last_hard_state, event_type)
  
  broker_log:info(2, "generate_xml / scheduled_downtime_depth="..tostring(d.scheduled_downtime_depth))
  if d.scheduled_downtime_depth == 1 then
    downtime = 1
  end
  
  xml = "<?xml version='1.0' encoding='utf-8'?>\n"
  xml = xml.."<events>\n"
  if target == "secondary" then
    xml = xml.."  <passkey>"..evanios["secondary_key"].."</passkey>\n"
  else
    xml = xml.."  <passkey>"..evanios["primary_key"].."</passkey>\n"
  end
  xml = xml.."  <event>\n"
  xml = xml.."    <u_ev_event_type>u_nagios_events</u_ev_event_type>\n"
  xml = xml.."    <u_severity>"..evanios_severity.."</u_severity>\n"
  xml = xml.."    <u_nag_eventtype>"..event_type.."</u_nag_eventtype>\n"
  xml = xml.."    <u_nag_hostname>"..hostname.."</u_nag_hostname>\n"
  xml = xml.."    <u_nag_hostaddress>N/A</u_nag_hostaddress>\n"
  xml = xml.."    <u_nag_hostgroups>"..hostgroups.."</u_nag_hostgroups>\n"
  xml = xml.."    <u_nag_servicename>"..service_description.."</u_nag_servicename>\n"
  xml = xml.."    <u_nag_output>"..cleanAndTrim(d.output).."</u_nag_output>\n"
  xml = xml.."    <u_nag_statetype>"..state_type.."</u_nag_statetype>\n"
  xml = xml.."    <u_nag_state>"..centreon_severity.."</u_nag_state>\n"
  xml = xml.."    <u_nag_laststate>"..centreon_last_severity.."</u_nag_laststate>\n"
  xml = xml.."    <u_nag_eventid>N/A</u_nag_eventid>\n"
  xml = xml.."    <u_nag_problemid>N/A</u_nag_problemid>\n"
  xml = xml.."    <u_nag_currentattempt>"..d.check_attempt.."</u_nag_currentattempt>\n"
  xml = xml.."    <u_nag_maxattempts>"..d.max_check_attempts.."</u_nag_maxattempts>\n"
  xml = xml.."    <u_nag_stateid>"..d.state.."</u_nag_stateid>\n"
  xml = xml.."    <u_nag_laststateid>N/A</u_nag_laststateid>\n"
  xml = xml.."    <u_nag_source>"..evanios["poller"].."</u_nag_source>\n"
  xml = xml.."    <u_extrastr1>CENTREON</u_extrastr1>\n"
  xml = xml.."    <u_extranum1>"..downtime.."</u_extranum1>\n"
  xml = xml.."    <u_category>N/A</u_category>\n"
  xml = xml.."    <u_subcategory>N/A</u_subcategory>\n"
  xml = xml.."  </event>\n"
  xml = xml.."</events>\n"
  
  return xml
end

-- Send to Evanios
local function send_event(xml, target)
  local evanios_url
  local address = evanios[target.."_address"]
  local port = evanios[target.."_port"]
  local ssl = evanios[target.."_ssl"]
  
  broker_log:info(2, "send_event / address="..address)
  broker_log:info(2, "send_event / port="..tostring(port))
  broker_log:info(2, "send_event / ssl="..tostring(ssl))
  
  if ssl then
    evanios_url = "https://"
  else
    evanios_url = "http://"
  end
  
  evanios_url = evanios_url..address..":"..port.."/eventlistener/createEvent"
  
  broker_log:info(2, "send_event / evanios_url="..evanios_url)
  
  local http_post_data = ""
  local http_result_body = {}
  
  local hr_result, hr_code, hr_header, hr_s = http.request{
    url = evanios_url,
    method = "POST",
    -- sink is where the request result's body will go
    sink = ltn12.sink.table(http_result_body),
    -- request body needs to be formatted as a LTN12 source
    source = ltn12.source.string(xml),
    headers = {
      -- mandatory for POST request with body
      ["content-length"] = string.len(xml),
      ["connection"] = "close",
      ["content-type"] = "text/xml",
      ["EV-APPNAME"] = "centreon_to_evanios",
      ["EV-APPVER"] = "1.0",
      ["EV-CERTNAME"] = "none"
    }
  }
  
  if hr_code == 200 then
    return 0
  else
    broker_log:error(1, "send_event / HTTP POST request failed with return code " .. hr_code)
    for i, v in ipairs(http_result_body) do
      broker_log:error(1, "send_event / HTTP POST request return message line " .. i .. ' is "' .. v .. '"')
    end
    return 1
  end
end

-- Init default values for Evanios
local function init_defaults(conf)
  evanios = {
    primary_address = "",
    primary_key     = "",
    primary_port    = 4012,
    primary_table   = "u_event",
    primary_ssl     = false,
    secondary_address = "",
    secondary_key     = "",
    secondary_port    = 4012,
    secondary_table   = "u_event",
    secondary_ssl     = false,
    poller            = ""
  }
  
  if conf['ev_primary_address'] then
    evanios["primary_address"] = conf['ev_primary_address']
  end
  
  if conf['ev_primary_key'] then
    evanios["primary_key"] = conf['ev_primary_key']
  end
  
  if conf['ev_primary_port'] then
    evanios["primary_port"] = conf['ev_primary_port']
  end
  
  if conf['ev_primary_table'] then
    evanios["primary_table"] = conf['ev_primary_table']
  end
  
  if conf['ev_primary_ssl'] then
    evanios["primary_ssl"] = conf['ev_primary_ssl']
  end
  
  if conf['ev_secondary_address'] then
    evanios["secondary_address"] = conf['ev_secondary_address']
  end
  
  if conf['ev_secondary_key'] then
    evanios["secondary_key"] = conf['ev_secondary_key']
  end
  
  if conf['ev_secondary_port'] then
    evanios["secondary_port"] = conf['ev_secondary_port']
  end
  
  if conf['ev_secondary_table'] then
    evanios["secondary_table"] = conf['ev_secondary_table']
  end
  
  if conf['ev_secondary_ssl'] then
    evanios["secondary_ssl"] = conf['ev_secondary_ssl']
  end
  
  if conf['poller'] then
    evanios["poller"] = conf['poller']
  end
  
  broker_log:info(2, "ev_primary_address="..evanios["primary_address"])
  broker_log:info(2, "ev_primary_key="..evanios["primary_key"])
  broker_log:info(2, "ev_primary_port="..evanios["primary_port"])
  broker_log:info(2, "ev_primary_table="..evanios["primary_table"])
  broker_log:info(2, "ev_primary_ssl="..tostring(evanios["primary_ssl"]))
  broker_log:info(2, "ev_secondary_address="..evanios["secondary_address"])
  broker_log:info(2, "ev_secondary_key="..evanios["secondary_key"])
  broker_log:info(2, "ev_secondary_port="..evanios["secondary_port"])
  broker_log:info(2, "ev_secondary_table="..evanios["secondary_table"])
  broker_log:info(2, "ev_secondary_ssl="..tostring(evanios["secondary_ssl"]))
  broker_log:info(2, "poller="..evanios["poller"])
end

-- Init function
function init(conf)
  local log_file = conf['log_file']
  if not log_file then
    log_file = "/var/log/centreon-broker/evanios.log"
  end
  
  local log_debug = conf['log_debug']
  if not log_debug then
    log_severity = 1
  else
    if log_debug == 1 then
      log_severity = 2
    else
      log_severity = 1
    end
  end
  
  broker_log:set_parameters(log_severity, log_file)
  
  init_defaults(conf)
  
  if evanios["primary_address"] == "" or evanios["primary_key"] == "" then
    error("Primary address and/or primary key not defined")
  end
  
  if evanios["poller"] == "" then
    error("Poller not defined")
  end

  broker_log:info(2, "test")
end

-- Write function
function write(d)
  broker_log:info(2, "test2")
  local hostname = broker_cache:get_hostname(d.host_id)
  if not hostname then
    broker_log:warning(1, "Unable to get the name of the host, please restart centengine")
    hostname = d.host_id
  end
  broker_log:info(2, "write / hostname="..hostname)
  
  local hostgroups = broker_cache:get_hostgroups(d.host_id)
  local hostgroups_str = ""
  if not hostgroups then
    broker_log:warning(1, "Unable to get the hostgroups of the host, please restart centengine")
  end
  
  for k1,v1 in pairs(hostgroups) do
    for k2,v2 in pairs(v1) do
      if tostring(k2) == "group_name" then
        if hostgroups_str ~= "" then
          hostgroups_str = hostgroups_str..","
        end
        hostgroups_str = hostgroups_str..tostring(v2)
      end
    end
  end
  
  if hostgroups_str == "" then
    hostgroups_str = "NONE"
  end
  
  local xml_primary, xml_secondary, service_description
  if d.element == 14 and d.acknowledged == false and d.state_type ~= 0 then
    xml_primary = generate_xml(hostname, nil, hostgroups_str, d, "primary")
    xml_secondary = generate_xml(hostname, nil, hostgroups_str, d, "secondary")
  elseif d.element == 24 and d.acknowledged == false and d.state_type ~= 0 then
    service_description = broker_cache:get_service_description(d.host_id, d.service_id)
    if not service_description then
      broker_log:warning(1, "Unable to get description of service, please restart centengine")
      service_description = d.service_id
    end
    xml_primary = generate_xml(hostname, service_description, hostgroups_str, d, "primary")
    xml_secondary = generate_xml(hostname, service_description, hostgroups_str, d, "secondary")
  end
  
  if xml_primary then
    broker_log:info(2, "write / xml_primary:"..xml_primary)
    local send_result = send_event(xml_primary, "primary")
    if send_result == 0 then
      broker_log:info(1, "write / Send alert for host "..hostname.." / service "..tostring(service_description).." to Evanios server "..evanios["primary_address"]..":"..evanios["primary_port"]..", table "..evanios["primary_table"]..", ssl "..tostring(evanios["primary_ssl"]))
    else
      broker_log:error(1, "write / Unable to send alert for host "..hostname.." / service "..tostring(service_description).." to Evanios server "..evanios["primary_address"]..":"..evanios["primary_port"]..", table "..evanios["primary_table"]..", ssl "..tostring(evanios["primary_ssl"]))
    end
  end
  
  if xml_secondary and evanios["secondary_address"] ~= "" and evanios["secondary_key"] ~= "" then
    broker_log:info(2, "write / xml_secondary:"..xml_secondary)
    local send_result = send_event(xml_secondary, "secondary")
    if send_result == 0 then
      broker_log:info(1, "write / Send alert for host "..hostname.." / service "..tostring(service_description).." to Evanios server "..evanios["secondary_address"]..":"..evanios["secondary_port"]..", table "..evanios["secondary_table"]..", ssl "..tostring(evanios["secondary_ssl"]))
    else
      broker_log:error(1, "write / Unable to send alert for host "..hostname.." / service "..tostring(service_description).." to Evanios server "..evanios["secondary_address"]..":"..evanios["secondary_port"]..", table "..evanios["secondary_table"]..", ssl "..tostring(evanios["secondary_ssl"]))
    end
  end
  
  return true
end

-- Filter function
function filter(category, element)
  -- Get only host status and services status from NEB category
  if category == 1 and (element == 14 or element == 24) then
    return true
  end
    return false
end
