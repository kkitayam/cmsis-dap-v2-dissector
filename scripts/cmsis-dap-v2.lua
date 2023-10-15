cmsis_dap_v2 = Proto("USBDAP", "USB CMSIS-DAP protocol")

local field_usb_transfer_type = Field.new("usb.transfer_type")
local field_usb_endpointdir = Field.new("usb.endpoint_address.direction")
local field_usb_device_address = Field.new("usb.device_address")


local id_vals = {
   [0x01] = "Vendor Name",
   [0x02] = "Product Name",
   [0x03] = "Serial Number",
   [0x04] = "CMSIS-DAP Protocol Version",
   [0x05] = "Target Device Vendor",
   [0x06] = "Target Device Name",
   [0x07] = "Target Board Vendor",
   [0x08] = "Target Board Name",
   [0x09] = "Product Firmware Version",
   [0xF0] = "Capabilities",
   [0xF1] = "Test Domain Timer",
   [0xFB] = "UART Receive Buffer Size",
   [0xFC] = "UART Transmit Buffer Size",
   [0xFD] = "SWO Trace Buffer Size",
   [0xFE] = "Packet Count",
   [0xFF] = "Packet Size"
}

local command_vals = {
  [ 0] = "Info",
  [ 1] = "HostStatus",
  [ 2] = "Connect",
  [ 3] = "Disconnect",
  [ 4] = "TransferConfigure",
  [ 5] = "Transfer",
  [ 6] = "TransferBlock",
  [ 7] = "TransferAbort",
  [ 8] = "WriteABORT",
  [ 9] = "Delay",
  [10] = "ResetTarget",
  [16] = "SWJ_Pins",
  [17] = "SWJ_Clock",
  [18] = "SWJ_Sequence",
  [19] = "SWD_Configure",
  [20] = "JTAG_Sequence",
  [21] = "JTAG_Configure",
  [22] = "JTAG_IDCOODE",
  [23] = "SWO_Transport",
  [24] = "SWO_Mode",
  [25] = "SWO_Baudrate",
  [26] = "SWO_Control",
  [27] = "SWO_Status",
  [28] = "SWO_Data",
  [29] = "SWD_Sequence",
  [30] = "SWO_ExtendedStatus",
  [31] = "UART_Transport",
  [32] = "UART_Configure",
  [33] = "UART_Transfer",
  [34] = "UART_Control",
  [35] = "UART_Status",
  [126] = "QueueCommands",
  [127] = "ExecuteCommands"
}

local port_vals = {[0] = "Default", [1] = "SWD", [2] = "JTAG"}

local ack_vals = {[1] = "OK", [2] = "WAIT", [3] = "FAULT", [4] = "NO_ACKT"}

cmsis_dap_v2.fields.req = ProtoField.framenum("cmsis_dap.request", "Request", base.NONE, frametype.REQUEST)
cmsis_dap_v2.fields.res = ProtoField.framenum("cmsis_dap.response", "Response", base.NONE, frametype.RESPONSE)

local reqest  = ProtoField.uint8("cmsis_dap.command", "Command", base.HEX, command_vals)
local command = ProtoField.uint8("cmsis_dap.command", "Command", base.HEX, command_vals)
local info_id = ProtoField.uint8("cmsis_dap.info.id", "Id", base.HEX, id_vals)
local info_len = ProtoField.uint8("cmsis_dap.info.len", "Len", base.DEC_HEX)
local info_name = ProtoField.string("cmsis_dap.info.name", "Name")
local hs_type = ProtoField.uint8("cmsis_dap.host_status.type", "Type", base.HEX, {[0] = "Connect", [1] = "Running"})
local hs_status = ProtoField.uint8("cmsis_dap.host_status.status", "Status", base.HEX, {[0] = "False", [1] = "True"})
local swj_clk = ProtoField.uint32("cmsis_dap.swj_clock", "Clock", base.DEC_HEX)
local swj_seq_cnt = ProtoField.uint8("cmsis_dap.swj_sequence.count", "Bit Count", base.DEC_HEX)
local swj_seq_dat = ProtoField.bytes("cmsis_dap.swj_sequence.data", "Bit Data")
local swd_cfg = ProtoField.uint8("cmsis_dap.swd_config", "Configuration", base.HEX)
local swd_tcp = ProtoField.uint8("cmsis_dap.swd_config.turnaround_clock_period", "Turnaround clock period", base.HEX, {[0] = "1 clock cycle", [1] = "2 clock cycles", [2] = "3 clock cycles", [3] = "4 clock cycles"}, 0x3)
local swd_dp = ProtoField.uint8("cmsis_dap.swd_config.data_phase", "DataPhase", base.HEX, {[0] = "Do not generate Data Phase on WAIT/FAULT", [1] = "Always generate Data Phase"}, 0x4)
local port = ProtoField.uint8("cmsis_dap.connect.port", "Port", base.HEX, port_vals)
local dap_index = ProtoField.uint8("cmsis_dap.dap_index", "DAP Index", base.DEC_HEX)
local write_abort = ProtoField.uint32("cmsis_dap.write_abort", "Abort", base.DEC_HEX)
local dap_delay = ProtoField.uint32("cmsis_dap.delay", "Delay", base.DEC_HEX)
local xfer_ic = ProtoField.uint8("cmsis_dap.transfer_config.idle_cycles", "Idle Cycles", base.DEC_HEX)
local xfer_wr = ProtoField.uint8("cmsis_dap.transfer_config.wait_retry", "WAIT Retry", base.DEC_HEX)
local xfer_mr = ProtoField.uint8("cmsis_dap.transfer_config.match_retry", "Match Retry", base.DEC_HEX)
local xfer_cnt = ProtoField.uint8("cmsis_dap.transfer.count", "Count", base.DEC_HEX)
local xfer = ProtoField.bytes("cmsis_dap.transfer", "Transfer")
local xfer_req = ProtoField.uint8("cmsis_dap.transfer.request", "Request", base.HEX)
local xfer_apndp = ProtoField.uint8("cmsis_dap.transfer.request.ap_n_dp", "APnDP", base.HEX, {[0] = "Debug Port", [1] = "Access Port"}, 0x1)
local xfer_rnw = ProtoField.uint8("cmsis_dap.transfer.request.r_n_w", "RnW", base.HEX, {[0] = "Write Register", [1] = "Read Register"}, 0x2)
local xfer_a23 = ProtoField.uint8("cmsis_dap.transfer.request.a23", "A[2:3]", base.HEX, nil, 0xC)
local xfer_match = ProtoField.uint8("cmsis_dap.transfer.request.match", "Match", base.HEX, {[0] = "Normal Read Register", [1] = "Read Register with Value Match"}, 0x10)
local xfer_mask = ProtoField.uint8("cmsis_dap.transfer.request.mask", "Mask", base.HEX, {[0] = "Normal Write Register", [1] = "Write Match Mask (instead of Register)"}, 0x20)
local xfer_ts = ProtoField.uint8("cmsis_dap.transfer.request.timestamp", "Timestamp", base.HEX, {[0] = "No time stamp", [1] = "Include time stamp value from Test Domain Timer before every Transfer Data word"}, 0x80)
local xfer_wdat = ProtoField.uint32("cmsis_dap.transfer.write.data", "Write", base.DEC_HEX)
local xfer_mskdat = ProtoField.uint32("cmsis_dap.transfer.mask.data", "Mask data", base.DEC_HEX)
local xfer_mchdat = ProtoField.uint32("cmsis_dap.transfer.match.data", "Match data", base.DEC_HEX)
local xfer_blk_cnt = ProtoField.uint16("cmsis_dap.transfer_block.count", "Count", base.DEC_HEX)
local xfer_rsp = ProtoField.uint8("cmsis_dap.transfer.response", "Response", base.HEX)
local xfer_ack = ProtoField.uint8("cmsis_dap.transfer.response.ack", "Acknowledge", base.HEX, ack_vals, 0x7)
local xfer_perr = ProtoField.uint8("cmsis_dap.transfer.response.protocol_error", "Protocol Error", base.HEX, {[0]="Pass", [1]="Error"}, 0x8)
local xfer_miss = ProtoField.uint8("cmsis_dap.transfer.response.value_mismatch", "Value Mismtch", base.HEX, {[0]="Pass", [1]="Error"}, 0x10)
local xfer_rdat = ProtoField.uint32("cmsis_dap.transfer.read.data", "Read", base.DEC_HEX)

cmsis_dap_v2.fields = {command, info_id, info_len, hs_type, hs_status,
                       swj_clk, swj_seq_cnt, swj_seq_dat,
                       swd_cfg, swd_tcp, swd_dp,
                       port, write_abort, dap_delay,
                       dap_index, xfer_cnt, xfer,
                       xfer_ic, xfer_wr, xfer_mr,
                       xfer_req, xfer_apndp, xfer_rnw, xfer_a23, xfer_match, xfer_mask, xfer_ts,
                       xfer_wdat, xfer_mskdat, xfer_mchdat, xfer_blk_cnt,
                       xfer_rsp, xfer_ack, xfer_perr, xfer_miss, xfer_rdat}

local CMSIS_DAP_COMMANDS = {
   DAP_INFO                = 0,
   DAP_HOST_STATUS         = 1,
   DAP_CONNECT             = 2,
   DAP_DISCONNECT          = 3,
   DAP_TRANSFER_CONFIGURE  = 4,
   DAP_TRANSFER            = 5,
   DAP_TRANSFER_BLOCK      = 6,
   DAP_TRANSFER_ABORT      = 7,
   DAP_WRITE_ABORT         = 8,
   DAP_DELAY               = 9,
   DAP_RESET_TARGET        = 10,
   DAP_SWJ_PINS            = 16,
   DAP_SWJ_CLOCK           = 17,
   DAP_SWJ_SEQUENCE        = 18,
   DAP_SWD_CONFIGURE       = 19,
   DAP_JTAG_SEQUENCE       = 20,
   DAP_JTAG_CONFIGURE      = 21,
   DAP_JTAG_IDCODE         = 22,
   DAP_SWO_TRANSPORT       = 23,
   DAP_SWO_MODE            = 24,
   DAP_SWO_BAUDRATE        = 25,
   DAP_SWO_CONTROL         = 26,
   DAP_SWO_STATUS          = 27,
   DAP_SWO_DATA            = 28,
   DAP_SWD_SEQUENCE        = 29,
   DAP_SWD_EXTENDED_STATUS = 30,
   DAP_UART_TRANSPORT      = 31,
   DAP_UART_CONFIGURE      = 32,
   DAP_UART_TRANSFER       = 33,
   DAP_UART_CONTROL        = 34,
   DAP_UART_STATUS         = 35,
   DAP_QUEUE_COMMANDS      = 126,
   DAP_EXECUTE_COMMANDS    = 127
}

convlist = {}

function parse_out_transfer(cnt, buffer, tree)
   local pos = 0
   local text = ""
   for i = 1, cnt do
      local tr = buffer(pos, 1):le_uint()
      local is_write = (bit.band(tr, 0x2) == 0)
      local is_match = (bit.band(tr, 0x10) ~= 0)
      local is_mask = (bit.band(tr, 0x20) ~= 0)

      local subtree = tree:add_le(xfer_req, buffer(pos, 1))
      subtree:add_le(xfer_apndp, buffer(pos, 1))
      subtree:add_le(xfer_rnw, buffer(pos, 1))
      subtree:add_le(xfer_a23, buffer(pos, 1))
      subtree:add_le(xfer_match, buffer(pos, 1))
      subtree:add_le(xfer_mask, buffer(pos, 1))
      subtree:add_le(xfer_ts, buffer(pos, 1))
      pos = pos + 1

      if is_write then
         tree:add_le(xfer_wdat, buffer(pos, 4))
         pos = pos + 4
         text = text .. "W"
      else
         text = text .. "R"
      end
      if is_mask then
         tree:add_le(xfer_mskdat, buffer(pos, 4))
         pos = pos + 4
      end
      if is_match then
         tree:add_le(xfer_mchdat, buffer(pos, 4))
         pos = pos + 4
      end
   end
   return text
end

function parse_in_transfer(cnt, buffer, tree)
   local ack = buffer(0, 1):le_uint()

   local subtree = tree:add_le( xfer_rsp, buffer(0, 1))
   subtree:add_le( xfer_ack, buffer(0, 1))
   subtree:add_le( xfer_perr, buffer(0, 1))
   subtree:add_le( xfer_miss, buffer(0, 1))
end

function parse_out_transfer_block(cnt, buffer, tree)
   local tr = buffer(0, 1):le_uint()
   local is_read = (bit.band(tr, 0x2) ~= 0)

   local subtree = tree:add_le(xfer_req, buffer(0, 1))
   subtree:add_le(xfer_apndp, buffer(0, 1))
   subtree:add_le(xfer_rnw, buffer(0, 1))
   subtree:add_le(xfer_a23, buffer(0, 1))

   if is_read then
      return "Read"
   end
   local pos = 1
   for i = 1, cnt do
      tree:add_le(xfer_wdat, buffer(pos, 4))
      pos = pos + 4
   end
   return "Write"
end

function parse_in_transfer_block(cnt, buffer, tree)
   local ack = buffer(0, 1):le_uint()

   local subtree = tree:add_le( xfer_rsp, buffer(0, 1))
   subtree:add_le( xfer_ack, buffer(0, 1))
   subtree:add_le( xfer_perr, buffer(0, 1))

   if buffer:len() <= 1 then
      return "Write"
   end

   local pos = 1
   for i = 1, cnt do
      tree:add_le( xfer_rdat, buffer(pos, 4))
      pos = pos + 4
   end
   return "Read"
end

function cmsis_dap_v2.dissector(buffer, pinfo, tree)
   len = buffer:len()
   if len == 0 then return end

   local xfer = field_usb_transfer_type().value
   local dev_adr = field_usb_device_address().value
   local is_request = (field_usb_endpointdir().value == 0)

   if convlist[dev_adr] == nil then
      convlist[dev_adr] = {}
      convlist[dev_adr].seq = {} -- frame number to sequence number
      convlist[dev_adr].req = {} -- sequence number to request frame number
      convlist[dev_adr].res = {} -- sequence number to response frame number
   end

   print(tostring(pinfo.number) .. " xfer " .. tostring(xfer) .. " adr " .. tostring(dev_adr) .. " req " .. tostring(is_request))

   local seq_num = -1
   if is_request then
      if convlist[dev_adr].req[pinfo.number] == nil then
         table.insert(convlist[dev_adr].req, pinfo.number)
         seq_num = #convlist[dev_adr].req
         convlist[dev_adr].seq[pinfo.number] = seq_num
      else
         seq_num = convlist[dev_adr].seq[pinfo.number]
      end
   else
      if convlist[dev_adr].res[pinfo.number] == nil then
         table.insert(convlist[dev_adr].res, pinfo.number)
         seq_num = #convlist[dev_adr].res
         convlist[dev_adr].seq[pinfo.number] = seq_num
      else
         seq_num = convlist[dev_adr].seq[pinfo.number]
      end
   end

   local subtree = tree:add(cmsis_dap_v2, buffer(), "CMSIS-DAP")
   local cmd = buffer(0, 1):le_uint()

   subtree:add_le( command, buffer(0, 1))
   if is_request then
      if convlist[dev_adr].res[seq_num] ~= nil then
         subtree:add( cmsis_dap_v2.fields.res, convlist[dev_adr].res[seq_num])
      end
      info_text = command_vals[buffer(0,1):le_uint()] .. " Request "
      if cmd == CMSIS_DAP_COMMANDS.DAP_INFO then
         info_text = info_text .. id_vals[buffer(1,1):le_uint()]
         subtree:add_le( info_id, buffer(1, 1))
      elseif cmd == CMSIS_DAP_COMMANDS.DAP_HOST_STATUS then
         subtree:add_le( hs_type, buffer(1, 1))
         subtree:add_le( hs_status, buffer(2, 1))
      elseif cmd == CMSIS_DAP_COMMANDS.DAP_CONNECT then
         subtree:add_le( port, buffer(1, 1))
         info_text = info_text .. port_vals[buffer(1, 1):le_uint()]
      elseif cmd == CMSIS_DAP_COMMANDS.DAP_WRITE_ABORT then
         subtree:add_le( dap_index, buffer(1, 1))
         subtree:add_le( write_abort, buffer(2, 4))
      elseif cmd == CMSIS_DAP_COMMANDS.DAP_DELAY then
         subtree:add_le( dap_delay, buffer(1, 2))
      elseif cmd == CMSIS_DAP_COMMANDS.DAP_SWJ_CLOCK then
         subtree:add_le( swj_clk, buffer(1, 4))
         info_text = info_text .. tostring(buffer(1, 4):le_uint()) .. "Hz"
      elseif cmd == CMSIS_DAP_COMMANDS.DAP_SWJ_SEQUENCE then
         subtree:add_le( swj_seq_cnt, buffer(1, 1))
         subtree:add_le( swj_seq_dat, buffer(2))
      elseif cmd == CMSIS_DAP_COMMANDS.DAP_SWD_CONFIGURE then
         local cfgtree = subtree:add_le( swd_cfg, buffer(1, 1))
         cfgtree:add_le( swd_tcp, buffer(1, 1))
         cfgtree:add_le( swd_dp, buffer(1, 1))
      elseif cmd == CMSIS_DAP_COMMANDS.DAP_TRANSFER_CONFIGURE then
         subtree:add_le( xfer_ic, buffer(1, 1))
         subtree:add_le( xfer_wr, buffer(2, 2))
         subtree:add_le( xfer_mr, buffer(4, 2))
      elseif cmd == CMSIS_DAP_COMMANDS.DAP_TRANSFER then
         subtree:add_le( dap_index, buffer(1, 1))
         subtree:add_le( xfer_cnt, buffer(2, 1))
         local cnt = buffer(2, 1):le_uint()
         local text = parse_out_transfer(cnt, buffer(3), subtree:add( xfer, buffer(3)))
         info_text = info_text .. tostring(cnt) .. " word(s) " .. text
      elseif cmd == CMSIS_DAP_COMMANDS.DAP_TRANSFER_BLOCK then
         subtree:add_le( xfer_blk_cnt, buffer(2, 2))
         local cnt = buffer(2, 2):le_uint()
         local text = parse_out_transfer_block(cnt, buffer(4), subtree)
         info_text = info_text .. tostring(cnt) .. " word(s) " .. text
      end
      pinfo.cols.info = info_text
   else
      subtree:add( cmsis_dap_v2.fields.req, convlist[dev_adr].req[seq_num])
      info_text = command_vals[buffer(0,1):le_uint()] .. " Response "
      if cmd == CMSIS_DAP_COMMANDS.DAP_INFO then
         subtree:add_le( info_len, buffer(1, 1))
         local len = buffer(1, 1):le_uint()
      elseif cmd == CMSIS_DAP_COMMANDS.DAP_TRANSFER then
         local ack = bit.band(buffer(2, 1):le_uint(), 0x7)
         subtree:add_le( xfer_cnt, buffer(1, 1))
         local cnt = buffer(1, 1):le_uint()
         local text = parse_in_transfer(cnt, buffer(2), subtree)
         info_text = info_text .. ack_vals[ack] .. " " .. tostring(cnt) .. " word(s)"
      elseif cmd == CMSIS_DAP_COMMANDS.DAP_TRANSFER_BLOCK then
         local ack = buffer(3, 1):le_uint()
         subtree:add_le( xfer_blk_cnt, buffer(1, 2))
         local cnt = buffer(1, 2):le_uint()
         local text = parse_in_transfer_block(cnt, buffer(3), subtree)
         info_text = info_text .. ack_vals[ack] .. " "  .. tostring(cnt) .. " word(s) " .. text
      end
      pinfo.cols.info = info_text
   end
end

DissectorTable.get("usb.bulk"):add(0xff, cmsis_dap_v2)
