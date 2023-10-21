local convlist = {}
local dap = Proto("USBDAP", "USB CMSIS-DAP protocol")

local usb_fields = {
   transfer_type = Field.new("usb.transfer_type"),
   endpointdir = Field.new("usb.endpoint_address.direction"),
   device_address = Field.new("usb.device_address"),
}

local vals = {
   id = {
      VENDOR_NAME = 1,
      PRODUCT_NAME = 2,
      SERIAL_NUMBER = 3,
      CMSIS_DAP_PROTOCOL_VERSION = 4,
      TARGET_DEVICE_VENDOR = 5,
      TARGET_DEVICE_NAME = 6,
      TARGET_BOARD_VENDOR = 7,
      TARGET_BOARD_NAME = 8,
      PRODUCT_FIRMWARE_VERSION = 9,
      CAPABILITIES = 0xF0,
      TEST_DOMAIN_TIMER_= 0xF1,
      UART_RECEIVE_BUFFER_SIZE = 0xFB,
      UART_TRANSMIT_BUFFER_SIZE = 0xFC,
      SWO_TRACE_BUFFER_SIZE = 0xFD,
      PACKET_COUNT = 0xFE,
      PACKET_SIZE = 0xFF,
   },
   command = {
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
   },
}

local names = {
   id = {
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
   },
   command = {
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
   },
   response = {[0] = "DAP_OK", [0xFF] = "DAP_ERROR"},
   port = {[0] = "Default", [1] = "SWD", [2] = "JTAG"},
   ack = {[1] = "OK", [2] = "WAIT", [3] = "FAULT", [4] = "NO_ACKT"},
   led = {[0] = "Connect", [1] = "Running"},
   imp = {[0] = "Not implemented", [1] = "Implemented"},
}

dap.fields.req = ProtoField.framenum("cmsis_dap.request", "Request", base.NONE, frametype.REQUEST)
dap.fields.res = ProtoField.framenum("cmsis_dap.response", "Response", base.NONE, frametype.RESPONSE)
dap.fields.cmd = ProtoField.uint8("cmsis_dap.command", "Command", base.HEX, names.command)
dap.fields.res_st = ProtoField.uint8("cmsis_dap.status", "Status", base.HEX, names.response)
dap.fields.id  = ProtoField.uint8("cmsis_dap.info.id", "Id", base.HEX, names.id)
dap.fields.len = ProtoField.uint8("cmsis_dap.info.len", "Len", base.DEC_HEX)
dap.fields.vendor = ProtoField.string("cmsis_dap.info.vendor", "Vendor Name")
dap.fields.product = ProtoField.string("cmsis_dap.info.product", "Product Name")
dap.fields.serial = ProtoField.string("cmsis_dap.info.serial", "Serial Number")
dap.fields.dap_ver = ProtoField.string("cmsis_dap.info.protocol_version", "CMSIS-DAP Protocol Version")
dap.fields.dev_vendor = ProtoField.string("cmsis_dap.info.target.device.vendor", "Target Device Vendor")
dap.fields.dev_name = ProtoField.string("cmsis_dap.info.target.device.name", "Target Device Name")
dap.fields.board_vendor = ProtoField.string("cmsis_dap.info.target.board.vendor", "Target Board Vendor")
dap.fields.board_name = ProtoField.string("cmsis_dap.info.target.board.name", "Target Board Name")
dap.fields.fw_version = ProtoField.string("cmsis_dap.info.target.board.name", "Product Firmware Version")
dap.fields.fw_version = ProtoField.string("cmsis_dap.info.target.board.name", "Product Firmware Version")
dap.fields.caps = ProtoField.uint8("cmsis_dap.info.caps", "Capabilities", base.HEX)
dap.fields.impswd = ProtoField.uint8("cmsis_dap.info.swd", "SWD", base.HEX, names.imp, 0x1)
dap.fields.impjtag = ProtoField.uint8("cmsis_dap.info.jtag", "JTAG", base.HEX, names.imp, 0x2)
dap.fields.swoua = ProtoField.uint8("cmsis_dap.info.swo_uart", "SWO UART", base.HEX, names.imp, 0x4)
dap.fields.swoman = ProtoField.uint8("cmsis_dap.info.swo_manchester", "SWO Manchester", base.HEX, names.imp, 0x8)
dap.fields.atomic = ProtoField.uint8("cmsis_dap.info.atomic", "Atomic Commands", base.HEX, names.imp, 0x10)
dap.fields.tmr = ProtoField.uint8("cmsis_dap.info.timer", "Test Domain Timer", base.HEX, names.imp, 0x20)
dap.fields.swostm = ProtoField.uint8("cmsis_dap.info.swo_streaming", "SWO Streaming Trace", base.HEX, names.imp, 0x40)
dap.fields.ua = ProtoField.uint8("cmsis_dap.info.uart", "UART Communication Port", base.HEX, names.imp, 0x80)
dap.fields.usbcom = ProtoField.uint8("cmsis_dap.info.usb_com", "USB COM Port", base.HEX, names.imp, 0x1)
dap.fields.pktcnt = ProtoField.uint8("cmsis_dap.info.packet.count", "Packet Count")
dap.fields.pktsz = ProtoField.uint16("cmsis_dap.info.packet.size", "Packet Size")
dap.fields.hs_type = ProtoField.uint8("cmsis_dap.host_status.type", "Type", base.HEX, names.led)
dap.fields.hs_status = ProtoField.uint8("cmsis_dap.host_status.status", "Status", base.HEX, {[0] = "False", [1] = "True"})
dap.fields.swj_output = ProtoField.uint8("cmsis_dap.swj.pin.output", "Pin Output", base.HEX)
dap.fields.swj_select = ProtoField.uint8("cmsis_dap.swj.pin.select", "Pin Select", base.HEX)
dap.fields.swj_input = ProtoField.uint8("cmsis_dap.swj.pin.input", "Pin Input", base.HEX)
dap.fields.swj_tck = ProtoField.uint8("cmsis_dap.swj.pin.swclk_tck", "SWCLK/TCK", base.HEX, nil, 0x1)
dap.fields.swj_tms = ProtoField.uint8("cmsis_dap.swj.pin.swdio_tms", "SWDIO/TMS", base.HEX, nil, 0x2)
dap.fields.swj_tdi = ProtoField.uint8("cmsis_dap.swj.pin.tdi", "TDI", base.HEX, nil, 0x4)
dap.fields.swj_tdo = ProtoField.uint8("cmsis_dap.swj.pin.tdo", "TDO", base.HEX, nil, 0x8)
dap.fields.swj_ntrst = ProtoField.uint8("cmsis_dap.swj.pin.ntrst", "nTRST", base.HEX, nil, 0x20)
dap.fields.swj_nreset = ProtoField.uint8("cmsis_dap.swj.pin.nreset", "nRESET", base.HEX, nil, 0x80)
dap.fields.swj_wait = ProtoField.uint32("cmsis_dap.swj.pin.wait", "Pin Wait", base.DEC_HEX)
dap.fields.swj_clk = ProtoField.uint32("cmsis_dap.swj_clock", "Clock", base.DEC_HEX)
dap.fields.swj_seq_cnt = ProtoField.uint8("cmsis_dap.swj_sequence.count", "Bit Count", base.DEC_HEX)
dap.fields.swj_seq_dat = ProtoField.bytes("cmsis_dap.swj_sequence.data", "Bit Data")
dap.fields.swd_cfg = ProtoField.uint8("cmsis_dap.swd_config", "Configuration", base.HEX)
dap.fields.swd_tcp = ProtoField.uint8("cmsis_dap.swd_config.turnaround_clock_period", "Turnaround clock period", base.HEX, {[0] = "1 clock cycle", [1] = "2 clock cycles", [2] = "3 clock cycles", [3] = "4 clock cycles"}, 0x3)
dap.fields.swd_dp = ProtoField.uint8("cmsis_dap.swd_config.data_phase", "DataPhase", base.HEX, {[0] = "Do not generate Data Phase on WAIT/FAULT", [1] = "Always generate Data Phase"}, 0x4)
dap.fields.port = ProtoField.uint8("cmsis_dap.connect.port", "Port", base.HEX, names.port)
dap.fields.dap_index = ProtoField.uint8("cmsis_dap.dap_index", "DAP Index", base.DEC_HEX)
dap.fields.write_abort = ProtoField.uint32("cmsis_dap.write_abort", "Abort", base.DEC_HEX)
dap.fields.dap_delay = ProtoField.uint32("cmsis_dap.delay", "Delay", base.DEC_HEX)
dap.fields.execute = ProtoField.uint8("cmsis_dap.execute", "Execute", base.DEC_HEX)
dap.fields.xfer_ic = ProtoField.uint8("cmsis_dap.transfer_config.idle_cycles", "Idle Cycles", base.DEC_HEX)
dap.fields.xfer_wr = ProtoField.uint8("cmsis_dap.transfer_config.wait_retry", "WAIT Retry", base.DEC_HEX)
dap.fields.xfer_mr = ProtoField.uint8("cmsis_dap.transfer_config.match_retry", "Match Retry", base.DEC_HEX)
dap.fields.xfer_cnt = ProtoField.uint8("cmsis_dap.transfer.count", "Count", base.DEC_HEX)
dap.fields.xfer = ProtoField.bytes("cmsis_dap.transfer", "Transfer")
dap.fields.xfer_req = ProtoField.uint8("cmsis_dap.transfer.request", "Request", base.HEX)
dap.fields.xfer_apndp = ProtoField.uint8("cmsis_dap.transfer.request.ap_n_dp", "APnDP", base.HEX, {[0] = "Debug Port", [1] = "Access Port"}, 0x1)
dap.fields.xfer_rnw = ProtoField.uint8("cmsis_dap.transfer.request.r_n_w", "RnW", base.HEX, {[0] = "Write Register", [1] = "Read Register"}, 0x2)
dap.fields.xfer_a23 = ProtoField.uint8("cmsis_dap.transfer.request.a23", "A[2:3]", base.HEX, nil, 0xC)
dap.fields.xfer_match = ProtoField.uint8("cmsis_dap.transfer.request.match", "Match", base.HEX, {[0] = "Normal Read Register", [1] = "Read Register with Value Match"}, 0x10)
dap.fields.xfer_mask = ProtoField.uint8("cmsis_dap.transfer.request.mask", "Mask", base.HEX, {[0] = "Normal Write Register", [1] = "Write Match Mask (instead of Register)"}, 0x20)
dap.fields.xfer_ts = ProtoField.uint8("cmsis_dap.transfer.request.timestamp", "Timestamp", base.HEX, {[0] = "No time stamp", [1] = "Include time stamp value from Test Domain Timer before every Transfer Data word"}, 0x80)
dap.fields.xfer_wdat = ProtoField.uint32("cmsis_dap.transfer.write.data", "Write", base.DEC_HEX)
dap.fields.xfer_mskdat = ProtoField.uint32("cmsis_dap.transfer.mask.data", "Mask data", base.DEC_HEX)
dap.fields.xfer_mchdat = ProtoField.uint32("cmsis_dap.transfer.match.data", "Match data", base.DEC_HEX)
dap.fields.xfer_blk_cnt = ProtoField.uint16("cmsis_dap.transfer_block.count", "Count", base.DEC_HEX)
dap.fields.xfer_rsp = ProtoField.uint8("cmsis_dap.transfer.response", "Response", base.HEX)
dap.fields.xfer_ack = ProtoField.uint8("cmsis_dap.transfer.response.ack", "Acknowledge", base.HEX, names.ack, 0x7)
dap.fields.xfer_perr = ProtoField.uint8("cmsis_dap.transfer.response.protocol_error", "Protocol Error", base.HEX, {[0]="Pass", [1]="Error"}, 0x8)
dap.fields.xfer_miss = ProtoField.uint8("cmsis_dap.transfer.response.value_mismatch", "Value Mismtch", base.HEX, {[0]="Pass", [1]="Error"}, 0x10)
dap.fields.xfer_rdat = ProtoField.uint32("cmsis_dap.transfer.read.data", "Read", base.DEC_HEX)

function dissect_response(buffer, tree)
   tree:add( dap.fields.res_st, buffer(0, 1))
   return names.response[buffer(0, 1):le_uint()]
end

function dissect_info(is_request, buffer, tree, convinf)
   if is_request then
      local id = buffer(0,1):le_uint()
      tree:add_le( dap.fields.id, buffer(0, 1))
      convinf.id = id
      return names.id[id]
   end

   tree:add_le( dap.fields.len, buffer(0, 1))
   local id = convinf.id
   local len = buffer(0,1):le_uint()
   if 0 == len then
      return names.id[id]
   end
   if vals.id.VENDOR_NAME == id then
      tree:add( dap.fields.vendor, buffer(1))
   elseif vals.id.PRODUCT_NAME == id then
      tree:add( dap.fields.product, buffer(1))
   elseif vals.id.SERIAL_NUMBER == id then
      tree:add( dap.fields.serial, buffer(1))
   elseif vals.id.CMSIS_DAP_PROTOCOL_VERSION == id then
      tree:add( dap.fields.dap_ver, buffer(1))
   elseif vals.id.TARGET_DEVICE_VENDOR == id then
      tree:add( dap.fields.dev_vendor, buffer(1))
   elseif vals.id.TARGET_DEVICE_NAME == id then
      tree:add( dap.fields.dev_name, buffer(1))
   elseif vals.id.TARGET_BOARD_VENDOR == id then
      tree:add( dap.fields.board_vendor, buffer(1))
   elseif vals.id.TARGET_BOARD_NAME == id then
      tree:add( dap.fields.board_name, buffer(1))
   elseif vals.id.PRODUCT_FIRMWARE_VERSION == id then
      tree:add( dap.fields.fw_version, buffer(1))
   elseif vals.id.CAPABILITIES == id then
      local subtree = tree:add_le( dap.fields.caps, buffer(1))
      if len > 0 then
         subtree:add_le( dap.fields.impswd, buffer(1, 1))
         subtree:add_le( dap.fields.impjtag, buffer(1, 1))
         subtree:add_le( dap.fields.swoua, buffer(1, 1))
         subtree:add_le( dap.fields.swoman, buffer(1, 1))
         subtree:add_le( dap.fields.atomic, buffer(1, 1))
         subtree:add_le( dap.fields.tmr, buffer(1, 1))
         subtree:add_le( dap.fields.swostm, buffer(1, 1))
         subtree:add_le( dap.fields.ua, buffer(1, 1))
      end
      if len > 1 then
         subtree:add_le( dap.fields.usbcom, buffer(2, 1))
      end
   elseif vals.id.TEST_DOMAIN_TIMER_== id then
   elseif vals.id.UART_RECEIVE_BUFFER_SIZE == id then
   elseif vals.id.UART_TRANSMIT_BUFFER_SIZE == id then
   elseif vals.id.SWO_TRACE_BUFFER_SIZE == id then
   elseif vals.id.PACKET_COUNT == id then
      tree:add_le( dap.fields.pktcnt, buffer(1, 1))
   elseif vals.id.PACKET_SIZE == id then
      tree:add_le( dap.fields.pktsz, buffer(1, 2))
   end
   return names.id[id]
end

function dissect_host_status(is_request, buffer, tree)
   if is_request then
      tree:add_le( dap.fields.hs_type, buffer(0, 1))
      tree:add_le( dap.fields.hs_status, buffer(1, 1))
      return names.led[buffer(0, 1):le_uint()]
   else
      -- TODO: add expert info
      return ""
   end
end

function dissect_dap_connect(is_request, buffer, tree)
   tree:add_le( dap.fields.port, buffer(0, 1))
   return names.port[buffer(0, 1):le_uint()]
end

function dissect_dap_disconnect(is_request, buffer, tree)
   if is_request then
      -- TODO: add expert info
      return ""
   else
      return dissect_response(buffer, tree)
   end
end

function dissect_transfer_configure(is_request, buffer, tree)
   if is_request then
      tree:add_le( dap.fields.xfer_ic, buffer(0, 1))
      tree:add_le( dap.fields.xfer_wr, buffer(1, 2))
      tree:add_le( dap.fields.xfer_mr, buffer(3, 2))
      return ""
   else
      return dissect_response(buffer, tree)
   end
end

function parse_out_transfer(cnt, buffer, tree)
   local pos = 0
   local text = ""
   for i = 1, cnt do
      local tr = buffer(pos, 1):le_uint()
      local is_write = (bit.band(tr, 0x2) == 0)
      local is_match = (bit.band(tr, 0x10) ~= 0)
      local is_mask = (bit.band(tr, 0x20) ~= 0)

      local subtree = tree:add_le(dap.fields.xfer_req, buffer(pos, 1))
      subtree:add_le(dap.fields.xfer_apndp, buffer(pos, 1))
      subtree:add_le(dap.fields.xfer_rnw, buffer(pos, 1))
      subtree:add_le(dap.fields.xfer_a23, buffer(pos, 1))
      subtree:add_le(dap.fields.xfer_match, buffer(pos, 1))
      subtree:add_le(dap.fields.xfer_mask, buffer(pos, 1))
      subtree:add_le(dap.fields.xfer_ts, buffer(pos, 1))
      pos = pos + 1

      if is_write then
         tree:add_le(dap.fields.xfer_wdat, buffer(pos, 4))
         pos = pos + 4
         text = text .. "W"
      else
         text = text .. "R"
      end
      if is_mask then
         tree:add_le(dap.fields.xfer_mskdat, buffer(pos, 4))
         pos = pos + 4
      end
      if is_match then
         tree:add_le(dap.fields.xfer_mchdat, buffer(pos, 4))
         pos = pos + 4
      end
   end
   return text
end

function parse_in_transfer(cnt, buffer, tree)
   local ack = buffer(0, 1):le_uint()

   local subtree = tree:add_le(dap.fields.xfer_rsp, buffer(0, 1))
   subtree:add_le(dap.fields.xfer_ack, buffer(0, 1))
   subtree:add_le(dap.fields.xfer_perr, buffer(0, 1))
   subtree:add_le(dap.fields.xfer_miss, buffer(0, 1))
end

function dissect_transfer_block(is_request, buffer, tree, convinf)
   if is_request then
      tree:add_le( dap.fields.dap_index, buffer(0, 1))
      tree:add_le( dap.fields.xfer_blk_cnt, buffer(1, 2))
      local cnt = buffer(1, 2):le_uint()
      local is_read = (bit.band(buffer(3, 1):le_uint(), 0x2) ~= 0)
      local subtree = tree:add_le(dap.fields.xfer_req, buffer(3, 1))
      subtree:add_le(dap.fields.xfer_apndp, buffer(3, 1))
      subtree:add_le(dap.fields.xfer_rnw, buffer(3, 1))
      subtree:add_le(dap.fields.xfer_a23, buffer(3, 1))
      if is_read then
         return tostring(cnt) .. " word(s) " .. "Read"
      end
      local pos = 4
      for i = 1, cnt do
         tree:add_le(dap.fields.xfer_wdat, buffer(pos, 4))
         pos = pos + 4
      end
      return tostring(cnt) .. " word(s) " .. "Write"
   else
      tree:add_le( dap.fields.xfer_blk_cnt, buffer(0, 2))
      local cnt = buffer(0, 2):le_uint()
      local ack = buffer(2, 1):le_uint()
      local subtree = tree:add_le( dap.fields.xfer_rsp, buffer(2, 1))
      subtree:add_le( dap.fields.xfer_ack, buffer(2, 1))
      subtree:add_le( dap.fields.xfer_perr, buffer(2, 1))

      if buffer:len() <= 3 then
         return names.ack[ack] .. " "  .. tostring(cnt) .. " word(s) " .. "Write"
      end
      local pos = 3
      for i = 1, cnt do
         tree:add_le( dap.fields.xfer_rdat, buffer(pos, 4))
         pos = pos + 4
      end
      return names.ack[ack] .. " "  .. tostring(cnt) .. " word(s) " .. "Read"
   end
end

function dissect_write_abort(is_request, buffer, tree)
   if is_request then
      tree:add_le( dap.fields.index, buffer(0, 1))
      tree:add_le( dap.fields.write_abort, buffer(1, 4))
      return ""
   else
      return dissect_response(buffer, tree)
   end
end

function dissect_dap_delay(is_request, buffer, tree)
   if is_request then
      tree:add_le( dap.fields.dap_delay, buffer(0, 2))
      return ""
   else
      return dissect_response(buffer, tree)
   end
end

function dissect_dap_reset_target(is_request, buffer, tree)
   if is_request then
      -- TODO: add expert info
      return ""
   else
      text = dissect_response(buffer, tree)
      tree:add_le( dap.fields.execute, buffer(1, 1))
      return text
   end
end

function dissect_swj_pins(is_request, buffer, tree)
   if is_request then
      local subtree = tree:add_le( dap.fields.swj_output, buffer(0, 1))
      subtree:add_le( dap.fields.swj_tck, buffer(0, 1))
      subtree:add_le( dap.fields.swj_tms, buffer(0, 1))
      subtree:add_le( dap.fields.swj_tdi, buffer(0, 1))
      subtree:add_le( dap.fields.swj_tdo, buffer(0, 1))
      subtree:add_le( dap.fields.swj_ntrst, buffer(0, 1))
      subtree:add_le( dap.fields.swj_nsrst, buffer(0, 1))
      local subtree = tree:add_le( dap.fields.swj_select, buffer(1, 1))
      subtree:add_le( dap.fields.swj_tck, buffer(1, 1))
      subtree:add_le( dap.fields.swj_tms, buffer(1, 1))
      subtree:add_le( dap.fields.swj_tdi, buffer(1, 1))
      subtree:add_le( dap.fields.swj_tdo, buffer(1, 1))
      subtree:add_le( dap.fields.swj_ntrst, buffer(1, 1))
      subtree:add_le( dap.fields.swj_nsrst, buffer(1, 1))
      tree:add_le( dap.fields.swj_wait, buffer(2, 4))
      return ""
   else
      local subtree = tree:add_le( dap.fields.swj_input, buffer(0, 1))
      subtree:add_le( dap.fields.swj_tck, buffer(0, 1))
      subtree:add_le( dap.fields.swj_tms, buffer(0, 1))
      subtree:add_le( dap.fields.swj_tdi, buffer(0, 1))
      subtree:add_le( dap.fields.swj_tdo, buffer(0, 1))
      subtree:add_le( dap.fields.swj_ntrst, buffer(0, 1))
      subtree:add_le( dap.fields.swj_nsrst, buffer(0, 1))
   end
end

function dissect_swj_clk(is_request, buffer, tree)
   if is_request then
      tree:add_le( dap.fields.swj_clk, buffer(0, 4))
      return tostring(buffer(0, 4):le_uint()) .. "Hz"
   else
      return dissect_response(buffer, tree)
   end
end

function dissect_swj_seq(is_request, buffer, tree)
   if is_request then
      tree:add_le( dap.fields.swj_seq_cnt, buffer(0, 1))
      tree:add_le( dap.fields.swj_seq_dat, buffer(1))
      return ""
   else
      return dissect_response(buffer, tree)
   end
end

function dissect_swd_configure(is_request, buffer, tree)
   if is_request then
      local subtree = tree:add_le( dap.fields.swd_cfg, buffer(0, 1))
      tree:add_le( dap.fields.swd_tcp, buffer(0, 1))
      tree:add_le( dap.fields.swd_dp, buffer(0, 1))
      return ""
   else
      return dissect_response(buffer, tree)
   end
end

function dap.dissector(buffer, pinfo, tree)
   len = buffer:len()
   if len == 0 then return end

   local xfer = usb_fields.transfer_type().value
   local dev_adr = usb_fields.device_address().value
   local is_request = (usb_fields.endpointdir().value == 0)

   local seq_num = -1
   if pinfo.visited == false then
      if convlist[dev_adr] == nil then
         convlist[dev_adr] = {}
         convlist[dev_adr].seq = {} -- frame number to sequence number
         convlist[dev_adr].req = {} -- sequence number to request frame number
         convlist[dev_adr].res = {} -- sequence number to response frame number
         convlist[dev_adr].inf = {} -- command information to dissect response buffer
      end
      if is_request then
         table.insert(convlist[dev_adr].req, pinfo.number)
         seq_num = #convlist[dev_adr].req
         convlist[dev_adr].seq[pinfo.number] = seq_num
         convlist[dev_adr].inf[seq_num] = {}
      else
         table.insert(convlist[dev_adr].res, pinfo.number)
         seq_num = #convlist[dev_adr].res
         convlist[dev_adr].seq[pinfo.number] = seq_num
      end
   else
      if is_request then
         seq_num = convlist[dev_adr].seq[pinfo.number]
      else
         seq_num = convlist[dev_adr].seq[pinfo.number]
      end
   end

   local subtree = tree:add(dap, buffer(), "CMSIS-DAP")
   local cmd = buffer(0, 1):le_uint()
   if is_request then
      info_text = names.command[cmd] .. " Request "
      if convlist[dev_adr].res[seq_num] ~= nil then
         subtree:add( dap.fields.res, convlist[dev_adr].res[seq_num])
      end
   else
      info_text = names.command[cmd] .. " Response "
      subtree:add( dap.fields.req, convlist[dev_adr].req[seq_num])
   end

   subtree:add_le( dap.fields.cmd, buffer(0, 1))
   if cmd == vals.command.DAP_INFO then
      info_text = info_text .. dissect_info(is_request, buffer(1), subtree, convlist[dev_adr].inf[seq_num])
   elseif cmd == vals.command.DAP_HOST_STATUS then
      info_text = info_text .. dissect_host_status(is_request, buffer(1), subtree)
   elseif cmd == vals.command.DAP_CONNECT then
      info_text = info_text .. dissect_dap_connect(is_request, buffer(1), subtree)
   elseif cmd == vals.command.DAP_DISCONNECT then
      info_text = info_text .. dissect_dap_disconnect(is_request, buffer(1), subtree)
   elseif cmd == vals.command.DAP_TRANSFER_CONFIGURE then
      info_text = info_text .. dissect_transfer_configure(is_request, buffer(1), subtree)
   elseif cmd == vals.command.DAP_TRANSFER then
      if is_request then
         subtree:add_le( dap.fields.dap_index, buffer(1, 1))
         subtree:add_le( dap.fields.xfer_cnt, buffer(2, 1))
         local cnt = buffer(2, 1):le_uint()
         local text = parse_out_transfer(cnt, buffer(3), subtree:add( dap.fields.xfer, buffer(3)))
         info_text = info_text .. tostring(cnt) .. " word(s) " .. text
      else
         subtree:add_le( dap.fields.xfer_cnt, buffer(1, 1))
         local cnt = buffer(1, 1):le_uint()
         local ack = bit.band(buffer(2, 1):le_uint(), 0x7)
         local text = parse_in_transfer(cnt, buffer(2), subtree)
         info_text = info_text .. names.ack[ack] .. " " .. tostring(cnt) .. " word(s)"
      end
   elseif cmd == vals.command.DAP_TRANSFER_BLOCK then
      info_text = info_text .. dissect_transfer_block(is_request, buffer(1), subtree, convlist[dev_adr].inf[seq_num])
   elseif cmd == vals.command.DAP_TRANSFER_ABORT then
      -- TODO: add handling
   elseif cmd == vals.command.DAP_WRITE_ABORT then
      info_text = info_text .. dissect_write_abort(is_request, buffer(1), subtree)
   elseif cmd == vals.command.DAP_DELAY then
      info_text = info_text .. dissect_dap_delay(is_request, buffer(1), subtree)
   elseif cmd == vals.command.DAP_RESET_TARGET then
      info_text = dissect_dap_reset_target(is_request, buffer(1), tree)
   elseif cmd == vals.command.DAP_SWJ_PINS then
      info_text = dissect_swj_pins(is_request, buffer(1), tree)
   elseif cmd == vals.command.DAP_SWJ_CLOCK then
      info_text = info_text .. dissect_swj_clk(is_request, buffer(1), subtree)
   elseif cmd == vals.command.DAP_SWJ_SEQUENCE then
      info_text = info_text .. dissect_swj_seq(is_request, buffer(1), subtree)
   elseif cmd == vals.command.DAP_SWD_CONFIGURE then
      info_text = info_text .. dissect_swd_configure(is_request, buffer(1), subtree)
   elseif cmd == vals.command.DAP_JTAG_SEQUENCE then
      -- TODO: add handling
   elseif cmd == vals.command.DAP_JTAG_CONFIGURE then
      -- TODO: add handling
   elseif cmd == vals.command.DAP_JTAG_IDCODE then
      -- TODO: add handling
   elseif cmd == vals.command.DAP_SWO_TRANSPORT then
      -- TODO: add handling
   elseif cmd == vals.command.DAP_SWO_MODE then
      -- TODO: add handling
   elseif cmd == vals.command.DAP_SWO_BAUDRATE then
      -- TODO: add handling
   elseif cmd == vals.command.DAP_SWO_CONTROL then
      -- TODO: add handling
   elseif cmd == vals.command.DAP_SWO_STATUS then
      -- TODO: add handling
   elseif cmd == vals.command.DAP_SWO_DATA then
      -- TODO: add handling
   elseif cmd == vals.command.DAP_SWO_DATA then
      -- TODO: add handling
   elseif cmd == vals.command.DAP_SWD_SEQUENCE then
      -- TODO: add handling
   elseif cmd == vals.command.DAP_SWD_EXTENDED_STATUS then
      -- TODO: add handling
   elseif cmd == vals.command.DAP_UART_TRANSPORT then
      -- TODO: add handling
   elseif cmd == vals.command.DAP_UART_CONFIGURE then
      -- TODO: add handling
   elseif cmd == vals.command.DAP_UART_TRANSFER then
      -- TODO: add handling
   elseif cmd == vals.command.DAP_UART_CONTROL then
      -- TODO: add handling
   elseif cmd == vals.command.DAP_UART_STATUS then
      -- TODO: add handling
   elseif cmd == vals.command.DAP_QUEUE_COMMANDS then
      -- TODO: add handling
   elseif cmd == vals.command.DAP_EXECUTE_COMMANDS then
      -- TODO: add handling
   end
   pinfo.cols.info = info_text

end

DissectorTable.get("usb.bulk"):add(0xff, dap)
