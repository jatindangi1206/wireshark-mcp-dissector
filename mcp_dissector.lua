-- MCP (Model Context Protocol) Dissector
-- Author: Jatin Dangi
-- Date: April 19, 2025
-- Description: A Wireshark dissector for the Model Context Protocol

-- Create the protocol object
local mcp = Proto("mcp", "Model Context Protocol")

-- Define protocol fields
local f_message_type = ProtoField.uint8("mcp.type", "Message Type", base.DEC, {
    [0x01] = "Control Message",
    [0x02] = "Data Message",
    [0xFF] = "Error Message"
})
local f_session_id = ProtoField.uint16("mcp.session_id", "Session ID", base.HEX)
local f_flags = ProtoField.uint8("mcp.flags", "Flags", base.HEX)
local f_flag_urgent = ProtoField.bool("mcp.flags.urgent", "Urgent", 8, nil, 0x80)
local f_flag_ack = ProtoField.bool("mcp.flags.ack", "Acknowledgment", 8, nil, 0x40)
local f_flag_error = ProtoField.bool("mcp.flags.error", "Error", 8, nil, 0x20)
local f_flag_final = ProtoField.bool("mcp.flags.final", "Final Fragment", 8, nil, 0x10)
local f_payload_length = ProtoField.uint16("mcp.payload_length", "Payload Length", base.DEC)
local f_payload = ProtoField.bytes("mcp.payload", "Payload Data")
local f_timestamp = ProtoField.uint32("mcp.timestamp", "Timestamp", base.DEC)
local f_seq_num = ProtoField.uint16("mcp.seq_num", "Sequence Number", base.DEC)
local f_source_id = ProtoField.uint16("mcp.source_id", "Source ID", base.HEX)
local f_target_id = ProtoField.uint16("mcp.target_id", "Target ID", base.HEX)

-- Register all fields
mcp.fields = {
    f_message_type, f_session_id, f_flags,
    f_flag_urgent, f_flag_ack, f_flag_error, f_flag_final,
    f_payload_length, f_payload, f_timestamp,
    f_seq_num, f_source_id, f_target_id
}

-- Dissector function
function mcp.dissector(tvb, pinfo, tree)
    -- Check if we have enough data for at least the header (assuming 12 bytes for header)
    local tvb_len = tvb:len()
    if tvb_len < 12 then
        -- Not enough data, request more if this is TCP
        if pinfo.port_type == 2 then -- TCP
            pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
            pinfo.desegment_offset = 0
            return
        else
            -- For non-TCP, just try to dissect what we have
            return
        end
    end
    
    -- Set the protocol column
    pinfo.cols.protocol = "MCP"
    
    -- Create the main subtree for MCP
    local subtree = tree:add(mcp, tvb(), "Model Context Protocol")
    
    -- Initialize our offset for tracking the current position
    local offset = 0
    
    -- Create the header subtree
    local header_tree = subtree:add(mcp, tvb(offset, 12), "MCP Header")
    
    -- Message Type (1 byte)
    local msg_type = tvb(offset, 1):uint()
    header_tree:add(f_message_type, tvb(offset, 1))
    offset = offset + 1
    
    -- Session ID (2 bytes)
    header_tree:add(f_session_id, tvb(offset, 2))
    offset = offset + 2
    
    -- Flags (1 byte)
    local flags_tree = header_tree:add(f_flags, tvb(offset, 1))
    flags_tree:add(f_flag_urgent, tvb(offset, 1))
    flags_tree:add(f_flag_ack, tvb(offset, 1))
    flags_tree:add(f_flag_error, tvb(offset, 1))
    flags_tree:add(f_flag_final, tvb(offset, 1))
    offset = offset + 1
    
    -- Sequence Number (2 bytes)
    header_tree:add(f_seq_num, tvb(offset, 2))
    offset = offset + 2
    
    -- Timestamp (4 bytes)
    header_tree:add(f_timestamp, tvb(offset, 4))
    offset = offset + 4
    
    -- Source ID (1 byte)
    header_tree:add(f_source_id, tvb(offset, 1))
    offset = offset + 1
    
    -- Target ID (1 byte)
    header_tree:add(f_target_id, tvb(offset, 1))
    offset = offset + 1
    
    -- Payload Length (2 bytes)
    local payload_length = tvb(offset, 2):uint()
    header_tree:add(f_payload_length, tvb(offset, 2))
    offset = offset + 2
    
    -- Check if we have the complete payload
    if tvb_len < offset + payload_length then
        -- Not enough data, request more if this is TCP
        if pinfo.port_type == 2 then -- TCP
            pinfo.desegment_len = (offset + payload_length) - tvb_len
            pinfo.desegment_offset = 0
            return
        else
            -- For non-TCP, just try to dissect what we have
            payload_length = tvb_len - offset
        end
    end
    
    -- Process payload according to message type
    if payload_length > 0 then
        if msg_type == 0x01 then -- Control Message
            local control_tree = subtree:add(mcp, tvb(offset, payload_length), "Control Data")
            control_tree:add(f_payload, tvb(offset, payload_length))
        elseif msg_type == 0x02 then -- Data Message
            local data_tree = subtree:add(mcp, tvb(offset, payload_length), "Payload Data")
            data_tree:add(f_payload, tvb(offset, payload_length))
        elseif msg_type == 0xFF then -- Error Message
            local error_tree = subtree:add(mcp, tvb(offset, payload_length), "Error Data")
            error_tree:add(f_payload, tvb(offset, payload_length))
        else -- Unknown message type
            subtree:add(f_payload, tvb(offset, payload_length))
        end
    end
    
    -- Return the size of this packet
    return offset + payload_length
end

-- Function to try determining if a packet is MCP
function heuristic_checker(tvb, pinfo, tree)
    -- Require at least 12 bytes for our check (minimum header size)
    if tvb:len() < 12 then return false end
    
    -- Check if the message type is one of our valid types
    local msg_type = tvb(0, 1):uint()
    if msg_type ~= 0x01 and msg_type ~= 0x02 and msg_type ~= 0xFF then
        return false
    end
    
    -- Additional heuristic checks could go here
    -- For example, check payload length against actual data size
    local payload_len = tvb(10, 2):uint()
    if payload_len > 8192 then -- Arbitrary sanity check
        return false
    end
    
    -- If we've passed our checks, dissect as MCP
    mcp.dissector(tvb, pinfo, tree)
    return true
end

-- Register our heuristic dissector
mcp:register_heuristic("tcp", heuristic_checker)
mcp:register_heuristic("udp", heuristic_checker)

-- Register the dissector with specific TCP and UDP ports
-- Replace these with the actual ports used by your MCP implementation
local tcp_port_table = DissectorTable.get("tcp.port")
tcp_port_table:add(8765, mcp) -- Example port, replace with your MCP port

local udp_port_table = DissectorTable.get("udp.port")
udp_port_table:add(8765, mcp) -- Example port, replace with your MCP port

-- Return the dissector for use by other scripts
return mcp
