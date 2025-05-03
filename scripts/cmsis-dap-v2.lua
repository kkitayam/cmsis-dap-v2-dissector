local DEBUG = false

local convlist = {}
local fragments = {}
local dap = Proto("USBDAP", "USB CMSIS-DAP protocol")

local usb_fields = {
  device_address   = Field.new("usb.device_address"),
  endpoint_address = Field.new("usb.endpoint_address"),
  endpointdir      = Field.new("usb.endpoint_address.direction"),
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
    DAP_SWO_EXTENDED_STATUS = 30,
    DAP_UART_TRANSPORT      = 31,
    DAP_UART_CONFIGURE      = 32,
    DAP_UART_TRANSFER       = 33,
    DAP_UART_CONTROL        = 34,
    DAP_UART_STATUS         = 35,
    DAP_QUEUE_COMMANDS      = 126,
    DAP_EXECUTE_COMMANDS    = 127,
  },
  type = {
    PKT_UNK = -1,
    PKT_SYN = 0,
    PKT_OVF = 1,
    PKT_LTS = 2,
    PKT_GTS = 3,
    PKT_EXT = 4,
    PKT_DWT = 5,
    PKT_ITM = 6,
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
    [0xFF] = "Packet Size",
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
    [127] = "ExecuteCommands",
  },
  response = {[0] = "DAP_OK", [0xFF] = "DAP_ERROR"},
  port = {[0] = "Default", [1] = "SWD", [2] = "JTAG"},
  ack = {[1] = "OK", [2] = "WAIT", [3] = "FAULT", [4] = "NO_ACKT"},
  led = {[0] = "Connect", [1] = "Running"},
  imp = {[0] = "Not implemented", [1] = "Implemented"},
  err = {[0]="Pass", [1]="Error"},
  sh = {[0]="ITM", [1]="DWT"},
  type = { [-1] = "UNK", [0] = "SYN", [1] = "OVF", [2] = "LTS", [3] = "GTS", [4] = "EXT", [5] = "DWT", [6] = "ITM"},
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
dap.fields.fw_version = ProtoField.string("cmsis_dap.info.firmware.version", "Product Firmware Version")
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
dap.fields.uarxbufsz = ProtoField.uint32("cmsis_dap.info.uart.rx_bufsz", "UART Receive Buffer Size")
dap.fields.uatxbufsz = ProtoField.uint32("cmsis_dap.info.uart.tx_bufsz", "UART Transmit Buffer Size")
dap.fields.swobufsz = ProtoField.uint32("cmsis_dap.info.swo_bufsz", "SWO Buffer Size")
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
dap.fields.swo_trans = ProtoField.uint8("cmsis_dap.swo_transport", "Transport", base.HEX, {[0] = "None", [1] = "Read trace data via DAP_SWO_Data command", [2] = "Send trace data via separate USB bulk endpoint"})
dap.fields.swo_mode = ProtoField.uint8("cmsis_dap.swo_mode", "Mode", base.HEX, {[0] = "Off", [1] = "UART", [2] = "Manchester"})
dap.fields.swo_baud = ProtoField.uint8("cmsis_dap.swo_baud", "Baudrate", base.DEC_HEX)
dap.fields.swo_ctrl = ProtoField.uint8("cmsis_dap.swo_ctrl", "Control", base.HEX, {[0] = "Stop", [1] = "Start"})
dap.fields.swo_sts = ProtoField.uint8("cmsis_dap.swo_sts", "Trace Status", base.HEX)
dap.fields.swo_act = ProtoField.uint8("cmsis_dap.swo_act", "Trace Capture", base.HEX, {[0] = "Inactive", [1] = "Active"}, 0x1)
dap.fields.swo_err = ProtoField.uint8("cmsis_dap.swo_err", "Trace Stream Error", base.HEX, names.err, 0x40)
dap.fields.swo_ovr = ProtoField.uint8("cmsis_dap.swo_ovr", "Trace Buffer Overrun", base.HEX, names.err, 0x80)
dap.fields.swo_cnt = ProtoField.uint32("cmsis_dap.swo_cnt", "Trace Count", base.DEC_HEX)
dap.fields.swo_dat = ProtoField.uint8("cmsis_dap.swo_data", "Trace Data", base.DEC_HEX)
dap.fields.swo_ext_sts = ProtoField.uint8("cmsis_dap.swo_ext_sts", "Control", base.HEX)
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
dap.fields.xfer_mskdat = ProtoField.uint32("cmsis_dap.transfer.mask.data", "Mask", base.DEC_HEX)
dap.fields.xfer_mchdat = ProtoField.uint32("cmsis_dap.transfer.match.data", "Match", base.DEC_HEX)
dap.fields.xfer_blk_cnt = ProtoField.uint16("cmsis_dap.transfer_block.count", "Count", base.DEC_HEX)
dap.fields.xfer_rsp = ProtoField.uint8("cmsis_dap.transfer.response", "Response", base.HEX)
dap.fields.xfer_ack = ProtoField.uint8("cmsis_dap.transfer.response.ack", "Acknowledge", base.HEX, names.ack, 0x7)
dap.fields.xfer_perr = ProtoField.uint8("cmsis_dap.transfer.response.protocol_error", "Protocol Error", base.HEX, names.err, 0x8)
dap.fields.xfer_miss = ProtoField.uint8("cmsis_dap.transfer.response.value_mismatch", "Value Mismtch", base.HEX, names.err, 0x10)
dap.fields.xfer_rdat = ProtoField.uint32("cmsis_dap.transfer.read.data", "Read", base.DEC_HEX)

dap.fields.swo_reassembled = ProtoField.framenum("cmsis_dap.swo_reassemble", "Reassembled", base.NONE, frametype.NONE)
dap.fields.swo_pkt_sync = ProtoField.bytes("cmsis_dap.swo_sync", "Syncronization packet")
dap.fields.swo_pkt_ovf = ProtoField.bytes("cmsis_dap.swo_ovf", "Overflow packet")
dap.fields.swo_pkt_lts = ProtoField.bytes("cmsis_dap.swo_lts", "Local timestamp packet")
dap.fields.swo_pkt_gts = ProtoField.bytes("cmsis_dap.swo_gts", "Global timestamp packet")
dap.fields.swo_pkt_ext = ProtoField.bytes("cmsis_dap.swo_ext", "Extension")
dap.fields.swo_pkt_itm = ProtoField.bytes("cmsis_dap.swo_itm", "ITM packet")
dap.fields.swo_pkt_dwt = ProtoField.bytes("cmsis_dap.swo_dwt", "DWT packet")
dap.fields.swo_pkt_hdr = ProtoField.uint8("cmsis_dap.swo_pkt.header", "Header", base.HEX)
dap.fields.swo_pkt_size = ProtoField.uint8("cmsis_dap.swo_pkt.size", "Packet size", base.DEC, {[1] = "2 bytes", [2] = "3 bytes", [3] = "5 bytes"}, 0x3)
dap.fields.swo_pkt_itm_or_dwt = ProtoField.uint8("cmsis_dap.swo_pkt.itm_or_dwt", "Category", base.DEC, nil, 0x4)
dap.fields.swo_pkt_source = ProtoField.uint8("cmsis_dap.swo_pkt.source", "Source ID / Port", base.DEC, nil, 0xF8)
dap.fields.swo_pkt_payload = ProtoField.uint32("cmsis_dap.swo_pkt.payload", "Payload", base.DEC_HEX)
dap.fields.swo_pkt_timestamp = ProtoField.uint32("cmsis_dap.swo_pkt.timestamp",    "Timestamp",     base.DEC)

dap.fields.swo_pkt_lts_type = ProtoField.uint8("cmsis_dap.swo_pkt.lts.type", "Local timestamp format", base.HEX, {[0] = "single-byte", [1] = "2 to 5 bytes"}, 0x80)
dap.fields.swo_pkt_lts_ts = ProtoField.uint8("cmsis_dap.swo_pkt.lts.ts", "Timestamp", base.DEC, nil, 0x30)
dap.fields.swo_pkt_sh = ProtoField.uint8("cmsis_dap.swo_pkt.source", "Source", base.DEC, names.sh, 0x4)
dap.fields.swo_pkt_page = ProtoField.uint8("cmsis_dap.swo_pkt.page", "Stimulus port page", base.DEC, nil, 0x70)

dap.fields.swo_evt_cpi = ProtoField.uint8("cmsis_dap.swo_pkt.dwt.event.cpi", "CPICNT", base.HEX, nil, 0x1)
dap.fields.swo_evt_exc = ProtoField.uint8("cmsis_dap.swo_pkt.dwt.event.exc", "EXCCNT", base.HEX, nil, 0x2)
dap.fields.swo_evt_sleep = ProtoField.uint8("cmsis_dap.swo_pkt.dwt.event.sleep", "SLEEPCNT", base.HEX, nil, 0x4)
dap.fields.swo_evt_lsu = ProtoField.uint8("cmsis_dap.swo_pkt.dwt.event.lsu", "LSUCNT", base.HEX, nil, 0x8)
dap.fields.swo_evt_fold = ProtoField.uint8("cmsis_dap.swo_pkt.dwt.event.fold", "FOLDCNT", base.HEX, nil, 0x10)
dap.fields.swo_evt_cyc = ProtoField.uint8("cmsis_dap.swo_pkt.dwt.event.cyc", "POSTCNT", base.HEX, nil, 0x20)

dap.fields.swo_exc_num = ProtoField.uint16("cmsis_dap.swo_pkt.dwt.except.num", "Exception number", base.HEX, nil, 0x1FF)
dap.fields.swo_exc_fn = ProtoField.uint16("cmsis_dap.swo_pkt.dwt.except.fn", "Function", base.HEX, {[1] = "Entered", [2] = "Exited", [3] = "Returned"}, 0x3000)

dap.experts.zl = ProtoExpert.new("cmsis_dap.zero_length", "Zero length", expert.group.MALFORMED, expert.severity.WARN)
dap.experts.lost = ProtoExpert.new("cmsis_dap.packet_lost", "Relative packet lost", expert.group.PROTOCOL, expert.severity.WARN)
dap.experts.malformed = ProtoExpert.new("cmsis_dap.malformed", "Malformed CMSIS-DAP Packet", expert.group.MALFORMED, expert.severity.ERROR)

local function debug_print(...)
  if DEBUG then
    print(...)
  end
end

local function dissect_response(buffer, tree)
  tree:add(dap.fields.res_st, buffer(0, 1))
  return names.response[buffer(0, 1):le_uint()]
end

local function dissect_info(is_request, buffer, tree, convinf)
  if is_request then
    local id = buffer(0,1):le_uint()
    tree:add_le(dap.fields.id, buffer(0, 1))
    convinf.id = id
    return names.id[id]
  end

  tree:add_le(dap.fields.len, buffer(0, 1))
  local id = convinf.id
  local len = buffer(0,1):le_uint()

  if 0 == len then
    return names.id[id]
  end

  if vals.id.VENDOR_NAME == id then
    tree:add(dap.fields.vendor, buffer(1))
  elseif vals.id.PRODUCT_NAME == id then
    tree:add(dap.fields.product, buffer(1))
  elseif vals.id.SERIAL_NUMBER == id then
    tree:add(dap.fields.serial, buffer(1))
  elseif vals.id.CMSIS_DAP_PROTOCOL_VERSION == id then
    tree:add(dap.fields.dap_ver, buffer(1))
  elseif vals.id.TARGET_DEVICE_VENDOR == id then
    tree:add(dap.fields.dev_vendor, buffer(1))
  elseif vals.id.TARGET_DEVICE_NAME == id then
    tree:add(dap.fields.dev_name, buffer(1))
  elseif vals.id.TARGET_BOARD_VENDOR == id then
    tree:add(dap.fields.board_vendor, buffer(1))
  elseif vals.id.TARGET_BOARD_NAME == id then
    tree:add(dap.fields.board_name, buffer(1))
  elseif vals.id.PRODUCT_FIRMWARE_VERSION == id then
    tree:add(dap.fields.fw_version, buffer(1))
  elseif vals.id.CAPABILITIES == id then
    local subtree = tree:add_le(dap.fields.caps, buffer(1))
    if len > 0 then
      subtree:add_le(dap.fields.impswd, buffer(1, 1))
      subtree:add_le(dap.fields.impjtag, buffer(1, 1))
      subtree:add_le(dap.fields.swoua, buffer(1, 1))
      subtree:add_le(dap.fields.swoman, buffer(1, 1))
      subtree:add_le(dap.fields.atomic, buffer(1, 1))
      subtree:add_le(dap.fields.tmr, buffer(1, 1))
      subtree:add_le(dap.fields.swostm, buffer(1, 1))
      subtree:add_le(dap.fields.ua, buffer(1, 1))
    end
    if len > 1 then
      subtree:add_le(dap.fields.usbcom, buffer(2, 1))
    end
  elseif vals.id.TEST_DOMAIN_TIMER_ == id then

  elseif vals.id.UART_RECEIVE_BUFFER_SIZE == id then
    tree:add(dap.fields.uarxbufsz, buffer(1, 4))
  elseif vals.id.UART_TRANSMIT_BUFFER_SIZE == id then
    tree:add(dap.fields.uatxbufsz, buffer(1, 4))
  elseif vals.id.SWO_TRACE_BUFFER_SIZE == id then
    tree:add(dap.fields.swobufsz, buffer(1, 4))  
  elseif vals.id.PACKET_COUNT == id then
    tree:add_le(dap.fields.pktcnt, buffer(1, 1))
  elseif vals.id.PACKET_SIZE == id then
    tree:add_le(dap.fields.pktsz, buffer(1, 2))
  end
  
  return names.id[id]
end

local function dissect_host_status(is_request, buffer, tree)
  if is_request then
    tree:add_le(dap.fields.hs_type, buffer(0, 1))
    tree:add_le(dap.fields.hs_status, buffer(1, 1))
    return names.led[buffer(0, 1):le_uint()]
  else
    tree:add_le(dap.fields.len, buffer(0, 1))
    if 0 ~= buffer(0, 1):le_uint() then
      tree:add_proto_expert_info(dap.experts.zl)
    end
    return ""
  end
end

local function dissect_dap_connect(is_request, buffer, tree)
  tree:add_le(dap.fields.port, buffer(0, 1))
  return names.port[buffer(0, 1):le_uint()]
end

local function dissect_dap_disconnect(is_request, buffer, tree)
  if is_request then
    -- TODO: Add expert info if necessary
    return ""
  else
    return dissect_response(buffer, tree)
  end
end

local function dissect_transfer_configure(is_request, buffer, tree)
  if is_request then
    tree:add_le(dap.fields.xfer_ic, buffer(0, 1))
    tree:add_le(dap.fields.xfer_wr, buffer(1, 2))
    tree:add_le(dap.fields.xfer_mr, buffer(3, 2))
    return ""
  else
    return dissect_response(buffer, tree)
  end
end

local function parse_out_transfer(cnt, buffer, tree)
  local pos = 0
  local text = ""
  local prev_is_write = -1 -- Previous access. 1:read 0:write
  local is_write = -1
  local consec = 0 -- Consecutive access count
  
  for i = 1, cnt do
    if prev_is_write ~= is_write then
      if consec > 1 then
        text = text .. tostring(consec)
      end
      consec = 0
    end

    local tr = buffer(pos, 1):le_uint()
    is_write = (bit.band(tr, 0x2) == 0)
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
      tree:add_le(is_mask and dap.fields.xfer_mskdat or dap.fields.xfer_wdat, buffer(pos, 4))
      pos = pos + 4
      if prev_is_write ~= is_write then
        text = text .. "W"
      end
    else
      if is_match then
        tree:add_le(dap.fields.xfer_mchdat, buffer(pos, 4))
        pos = pos + 4
      end
      if prev_is_write ~= is_write then
        text = text .. "R"
      end
    end
    consec = consec + 1
    prev_is_write = is_write
  end
  
  if consec > 1 then
    text = text .. tostring(consec)
  end
  
  return text
end

local function dissect_transfer(is_request, buffer, tree, convinf)
  if is_request then
    if buffer:len() < 2 then
      tree:add_proto_expert_info(dap.experts.malformed, "Transfer request buffer is too small")
      return "Malformed Request"
    end

    tree:add_le(dap.fields.dap_index, buffer(0, 1))
    tree:add_le(dap.fields.xfer_cnt, buffer(1, 1))
    local cnt = buffer(1, 1):le_uint()
    local text = parse_out_transfer(cnt, buffer(2), tree:add(dap.fields.xfer, buffer(2)))
    return tostring(cnt) .. " word(s) " .. text
  else
    tree:add_le(dap.fields.xfer_cnt, buffer(0, 1))
    local cnt = buffer(0, 1):le_uint()
    local ack = bit.band(buffer(1, 1):le_uint(), 0x7)
    local subtree = tree:add_le(dap.fields.xfer_rsp, buffer(1, 1))
    subtree:add_le(dap.fields.xfer_ack, buffer(1, 1))
    subtree:add_le(dap.fields.xfer_perr, buffer(1, 1))
    subtree:add_le(dap.fields.xfer_miss, buffer(1, 1))

    local pos = 2
    while pos < buffer:len() do
      tree:add_le(dap.fields.xfer_rdat, buffer(pos, 4))
      pos = pos + 4
    end
    return names.ack[ack] .. " " .. tostring(cnt) .. " word(s)"
  end
end

local function dissect_transfer_block(is_request, buffer, tree, convinf)
  if is_request then
    tree:add_le(dap.fields.dap_index, buffer(0, 1))
    tree:add_le(dap.fields.xfer_blk_cnt, buffer(1, 2))
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
    tree:add_le(dap.fields.xfer_blk_cnt, buffer(0, 2))
    local cnt = buffer(0, 2):le_uint()
    local ack = buffer(2, 1):le_uint()
    local subtree = tree:add_le(dap.fields.xfer_rsp, buffer(2, 1))
    subtree:add_le(dap.fields.xfer_ack, buffer(2, 1))
    subtree:add_le(dap.fields.xfer_perr, buffer(2, 1))

    if buffer:len() <= 3 then
      return names.ack[ack] .. " " .. tostring(cnt) .. " word(s) " .. "Write"
    end
    
    local pos = 3
    for i = 1, cnt do
      tree:add_le(dap.fields.xfer_rdat, buffer(pos, 4))
      pos = pos + 4
    end
    return names.ack[ack] .. " " .. tostring(cnt) .. " word(s) " .. "Read"
  end
end

local function dissect_write_abort(is_request, buffer, tree)
  if is_request then
    tree:add_le(dap.fields.dap_index, buffer(0, 1))
    tree:add_le(dap.fields.write_abort, buffer(1, 4))
    return ""
  else
    return dissect_response(buffer, tree)
  end
end

local function dissect_dap_delay(is_request, buffer, tree)
  if is_request then
    tree:add_le(dap.fields.dap_delay, buffer(0, 2))
    return ""
  else
    return dissect_response(buffer, tree)
  end
end

local function dissect_dap_reset_target(is_request, buffer, tree)
  if false == is_request then
    local text = dissect_response(buffer, tree)
    tree:add_le(dap.fields.execute, buffer(1, 1))
    return text
  end
  return ""
end

local function dissect_swj_pins(is_request, buffer, tree)
  if is_request then
    local subtree = tree:add_le(dap.fields.swj_output, buffer(0, 1))
    subtree:add_le(dap.fields.swj_tck, buffer(0, 1))
    subtree:add_le(dap.fields.swj_tms, buffer(0, 1))
    subtree:add_le(dap.fields.swj_tdi, buffer(0, 1))
    subtree:add_le(dap.fields.swj_tdo, buffer(0, 1))
    subtree:add_le(dap.fields.swj_ntrst, buffer(0, 1))
    subtree:add_le(dap.fields.swj_nreset, buffer(0, 1))
    
    local subtree = tree:add_le(dap.fields.swj_select, buffer(1, 1))
    subtree:add_le(dap.fields.swj_tck, buffer(1, 1))
    subtree:add_le(dap.fields.swj_tms, buffer(1, 1))
    subtree:add_le(dap.fields.swj_tdi, buffer(1, 1))
    subtree:add_le(dap.fields.swj_tdo, buffer(1, 1))
    subtree:add_le(dap.fields.swj_ntrst, buffer(1, 1))
    subtree:add_le(dap.fields.swj_nreset, buffer(1, 1))
    
    tree:add_le(dap.fields.swj_wait, buffer(2, 4))
  else
    local subtree = tree:add_le(dap.fields.swj_input, buffer(0, 1))
    subtree:add_le(dap.fields.swj_tck, buffer(0, 1))
    subtree:add_le(dap.fields.swj_tms, buffer(0, 1))
    subtree:add_le(dap.fields.swj_tdi, buffer(0, 1))
    subtree:add_le(dap.fields.swj_tdo, buffer(0, 1))
    subtree:add_le(dap.fields.swj_ntrst, buffer(0, 1))
    subtree:add_le(dap.fields.swj_nreset, buffer(0, 1))
  end
  return ""
end

local function dissect_swj_clk(is_request, buffer, tree)
  if is_request then
    tree:add_le(dap.fields.swj_clk, buffer(0, 4))
    return tostring(buffer(0, 4):le_uint()) .. "Hz"
  else
    return dissect_response(buffer, tree)
  end
end

local function dissect_swj_seq(is_request, buffer, tree)
  if is_request then
    tree:add_le(dap.fields.swj_seq_cnt, buffer(0, 1))
    tree:add_le(dap.fields.swj_seq_dat, buffer(1))
    return ""
  else
    return dissect_response(buffer, tree)
  end
end

local function dissect_swd_configure(is_request, buffer, tree)
  if is_request then
    local subtree = tree:add_le(dap.fields.swd_cfg, buffer(0, 1))
    subtree:add_le(dap.fields.swd_tcp, buffer(0, 1))
    subtree:add_le(dap.fields.swd_dp, buffer(0, 1))
    return ""
  else
    return dissect_response(buffer, tree)
  end
end

local function dissect_swo_transport(is_request, buffer, tree)
  if is_request then
    tree:add_le(dap.fields.swo_trans, buffer(0, 1))
    return ""
  else
    return dissect_response(buffer, tree)
  end
end
 
local function dissect_swo_mode(is_request, buffer, tree)
  if is_request then
    tree:add_le(dap.fields.swo_mode, buffer(0, 1))
    return ""
  else
    return dissect_response(buffer, tree)
  end
end

local function dissect_swo_baudrate(is_request, buffer, tree)
  if is_request then
    tree:add_le(dap.fields.swo_baud, buffer(0, 4))
    return tostring(buffer(0, 4):le_uint()) .. "bps"
  else
    tree:add_le(dap.fields.swo_baud, buffer(0, 4))
    return tostring(buffer(0, 4):le_uint()) .. "bps"
  end
end

local function dissect_swo_control(is_request, buffer, tree)
  if is_request then
    tree:add_le(dap.fields.swo_ctrl, buffer(0, 1))
    return ""
  else
    return dissect_response(buffer, tree)
  end
end
 
local function dissect_swo_status(is_request, buffer, tree)
  if is_request then
    return ""
  else
    local subtree = tree:add_le(dap.fields.swo_sts, buffer(0, 1))
    subtree:add_le(dap.fields.swo_act, buffer(0, 1))
    subtree:add_le(dap.fields.swo_err, buffer(0, 1))
    subtree:add_le(dap.fields.swo_ovr, buffer(0, 1))
    tree:add_le(dap.fields.swo_cnt, buffer(1))
    return ""
  end
end

local function dissect_swo_data(is_request, buffer, tree)
  if is_request then
    tree:add_le(dap.fields.swo_cnt, buffer(0, 2))
    return ""
  else
    local subtree = tree:add_le(dap.fields.swo_sts, buffer(0, 1))
    subtree:add_le(dap.fields.swo_act, buffer(0, 1))
    subtree:add_le(dap.fields.swo_err, buffer(0, 1))
    subtree:add_le(dap.fields.swo_ovr, buffer(0, 1))
    local cnt = buffer(1, 2):le_uint()
    tree:add_le(dap.fields.swo_cnt, buffer(1, 2))
    local pos = 2
    for i = 1, cnt do
      tree:add_le(dap.fields.swo_dat, buffer(pos, 1))
      pos = pos + 1
    end
    return tostring(cnt) .. " byte(s) " .. "Read"
  end
end

local function dissect_swd_sequence(is_request, buffer, tree)
  if is_request then
    tree:add_le(dap.fields.swj_seq_cnt, buffer(0, 1))
    tree:add_le(dap.fields.swj_seq_dat, buffer(1))
    return ""
  else
    return dissect_response(buffer, tree)
  end
end

local function dissect_swo_extended_status(is_request, buffer, tree)
  if is_request then
    tree:add_le(dap.fields.swo_ext_sts, buffer(0, 1))
    return ""
  else
   -- TODO: Add expert info if necessary
    return ""
  end
end

local function dissect_itm_and_dwt_packet(tvb, tree)
  local hdr = tvb(0, 1):uint()

  if hdr == 0x00 then
    -- Sync packet: 0x00 repeated ≥6 times
    if tvb:len() == 1 then return -5 end
    local cnt = 1
    while 0 == tvb(cnt, 1):uint() and cnt < tvb:len() - 1 do
      cnt = cnt + 1
    end
    if 0 == tvb(cnt, 1):uint() and cnt == tvb:len() - 1 then
      return tvb:len() < 6 and tvb:len() - 6 or -1
    end
    if cnt >= 5 and 0x80 == tvb(cnt, 1):uint() then
      -- Sync packet: 0x00 repeated ≥6 times
      cnt = cnt + 1
      if tree then
        local subtree = tree:add(dap.fields.swo_pkt_sync, tvb(0, cnt))
        subtree:add(dap.fields.swo_pkt_hdr, tvb(0, 1))
      end
      return cnt, 0
    else
      return cnt, -1 -- malformed packet
    end
  end

  -- Determine packet category by lower 2 bits (lsb)
  local lsb = bit.band(hdr, 0x03)
  if lsb == 0 then
    if hdr == 0x70 then
      -- Overflow packet
      if tree then
        local subtree = tree:add(dap.fields.swo_pkt_ovf, buffer(0, 1))
        subtree:add(dap.fields.swo_pkt_hdr, buffer(0, 1))
      end
      return 1, 1
    elseif 0 == bit.band(hdr, 0x0C) then
      -- Local timestamp packet
      if 0 == bit.band(hdr, 0x80) then
        -- Local timestamp: 1-byte
        if tree then
          local subtree = tree:add(dap.fields.swo_pkt_lts, tvb(0, 1))
          local subsubtree = subtree:add(dap.fields.swo_pkt_hdr, tvb(0, 1))
          subsubtree:add(dap.fields.swo_pkt_lts_type, tvb(0, 1))
          subsubtree:add(dap.fields.swo_pkt_lts_ts, tvb(0, 1))
        end
        return 1, 2
      else
        -- parse variable-length timestamp
        local ts = 0
        local shift = 0
        local offset = 1
        repeat
          if offset > 4 then return offset, -1 end -- malformed packet
          if offset >= tvb:len() then return offset - 5 end
          local b = tvb(offset, 1):uint()
          ts = ts + bit.lshift(bit.band(b, 0x7F), shift) -- accumulate timestamp
          shift = shift + 7
          offset = offset + 1
        until bit.band(b, 0x80) == 0
        if tree then
          local subtree = tree:add(dap.fields.swo_pkt_lts, tvb(0, offset - 1))
          local subsubtree = subtree:add(dap.fields.swo_pkt_hdr, tvb(0, 1))
          subsubtree:add(dap.fields.swo_pkt_lts_type, tvb(0, 1))
          subtree:add(dap.fields.swo_pkt_timestamp, tvb(1, offset - 1), ts)
        end
        return offset, 2
      end
    elseif 0x08 == bit.band(hdr, 0x0B) then
      -- Extension
      if 0 == bit.band(hdr, 0x80) then
        if tree then
          local subtree = tree:add(dap.fields.swo_pkt_ext, tvb(0, 1))
          subtree:add(dap.fields.swo_pkt_sh, tvb(0, 1))
          subtree:add(dap.fields.swo_pkt_page, tvb(0, 1))
        end
        return 1, 4
      else
        local ex = bit.band(hdr, 0x70) / 16
        local shift = 3
        local offset = 1
        repeat
          if offset >= tvb:len() then return offset - 5 end
          local b = tvb(offset, 1):uint()
          local v = offset < 4 and bit.band(b, 0x7F) or b
          ex = ex + v * (2 ^ shift)
          shift = shift + 7
          offset = offset + 1
        until bit.band(b, 0x80) == 0 or offset == 5
        if tree then
          local subtree = tree:add(dap.fields.swo_pkt_ext, tvb(0, offset))
          -- TODO: Add more fields
        end
        return offset, 4
      end
    elseif 0x94 == bit.band(hdr, 0xDC) then
      -- Global timestamp
      if 0x94 == hdr then
        local offset = 1
        repeat
          if offset >= tvb:len() then return offset - 5 end
          local b = tvb(offset, 1):uint()
          offset = offset + 1
        until bit.band(b, 0x80) == 0 or offset == 5
        return offset, 3
      else
        local offset = 1
        repeat
          if offset >= tvb:len() then return offset - 7 end
          local b = tvb(offset, 1):uint()
          offset = offset + 1
        until bit.band(b, 0x80) == 0 or offset == 7
        if offset == 5 or offset == 7 then
          return offset, 3
        else
          return offset, -1 -- malformed packet
        end
      end
    else
      -- handle error
      return 0
    end
  end

  -- Source packet: ITM/DWT data
  local payload_len = lsb == 3 and 4 or lsb  -- 1,2,4 bytes
  local packet_type = bit.band(hdr, 0x08) ~= 0 and 5 or 6
  if tvb:len() < 1 + payload_len then return tvb:len() - (1 + payload_len), packet_type end
  if tree then
    local is_hw = bit.band(hdr, 0x08) ~= 0
    local f = is_hw and dap.fields.swo_pkt_dwt or dap.fields.swo_pkt_itm
    local subtree = tree:add(f, tvb(0, payload_len + 1))
    local subsubtree = subtree:add(dap.fields.swo_pkt_hdr, tvb(0, 1))
    subsubtree:add(dap.fields.swo_pkt_size, tvb(0, 1))
    subsubtree:add(dap.fields.swo_pkt_itm_or_dwt, tvb(0, 1))
    subsubtree:add(dap.fields.swo_pkt_source, tvb(0, 1))
    subsubtree = subtree:add_le(dap.fields.swo_pkt_payload, tvb(1, payload_len))
    if 0x05 == hdr then
      -- Event counter packet
      subsubtree:add(dap.fields.swo_evt, tvb(1, 1))
      subsubtree:add(dap.fields.swo_evt_cpi, tvb(1, 1))
      subsubtree:add(dap.fields.swo_evt_exc, tvb(1, 1))
      subsubtree:add(dap.fields.swo_evt_sleep, tvb(1, 1))
      subsubtree:add(dap.fields.swo_evt_lsu, tvb(1, 1))
      subsubtree:add(dap.fields.swo_evt_fold, tvb(1, 1))
      subsubtree:add(dap.fields.swo_evt_cyc, tvb(1, 1))
    elseif 0x0e == hdr then
      -- Exception trace
      subsubtree:add_le(dap.fields.swo_exc_num, tvb(1, 2))
      subsubtree:add_le(dap.fields.swo_exc_fn, tvb(1, 2))
    end
  end
  return 1 + payload_len, packet_type
end

local function dissect_trace(tvb, pinfo, tree)
  local subtree
  if pinfo.visited then
    pinfo.cols.protocol = "USBDAP"
    subtree = tree:add(dap, ltvb, "CMSIS-DAP")
  end
  local dev_adr = usb_fields.device_address().value
  local frg = fragments[dev_adr]
  local ltvb = tvb
  if frg ~= nil then
    local seq_num = frg.seq[pinfo.number]
    -- print("frame number: ", pinfo.number, "seq_num: ", seq_num, "buffer: ", buffer, "len: ", buffer:len())
    if seq_num > 1 then
      local prev_frame = frg.res[seq_num - 1]
      if frg.rem[prev_frame] then
        local buffer = tvb:bytes()
        buffer:prepend(frg.rem[prev_frame])
        ltvb = buffer:tvb("SWO_Trace_" .. prev_frame .. "_" .. pinfo.number)

        if subtree then
          subtree:add(dap.fields.swo_reassembled, prev_frame)
        end
      end
      -- print("cur", pinfo.number, "prev", prev_frame, "buffer", buffer)
    end
    if subtree then
      local next_frame = frg.res[seq_num + 1]
      if next_frame and frg.rem[pinfo.number] then
        subtree:add(dap.fields.swo_reassembled, next_frame)
      end
    end
  end

  local pkts = ""
  local offset = 0
  local cnt = 0
  while offset < ltvb:len() do
    local pkt_len, pkt_type = dissect_itm_and_dwt_packet(ltvb(offset), subtree)
    if pkt_len <= 0 then break end
    offset = offset + pkt_len
    cnt = cnt + 1
    if pinfo.visited then
      pkts = pkts .. names.type[pkt_type] .. " "
    end
  end
  if pinfo.visited then
    pinfo.cols.info = "SWO_Data " .. cnt .. " packet(s) " .. pkts
  end
end


local function parse_trace(tvb, pinfo)
  local dev_adr = usb_fields.device_address().value
  local seq_num = nil
  if fragments[dev_adr] == nil then
    fragments[dev_adr] = {
      seq = {}, -- Mapping from frame number to sequence number
      res = {}, -- Mapping from sequence number to response frame number
      pkts = {}, -- Packet type array
      rem = {}, -- Remainder of bytes as ByteArray
    }
  end
  table.insert(fragments[dev_adr].res, pinfo.number)
  seq_num = #fragments[dev_adr].res
  fragments[dev_adr].seq[pinfo.number] = seq_num
  local ltvb = tvb
  -- print("frame number: ", pinfo.number, "seq_num: ", seq_num, "buffer: ", buffer, "len: ", buffer:len())
  if seq_num > 1 then
    local prev_frame = fragments[dev_adr].res[seq_num - 1]
    if fragments[dev_adr].rem[prev_frame] then
      local buffer = tvb:bytes()
      buffer:prepend(fragments[dev_adr].rem[prev_frame])
      ltvb = buffer:tvb("SWO_Trace_" .. prev_frame .. "_" .. pinfo.number)
    end
    -- print("cur", pinfo.number, "prev", prev_frame, "buffer", buffer)
  end
  local pkt_types = {}
  local offset = 0
  local cnt = 0
  while offset < ltvb:len() do
    local pkt_type
    local pkt_len
    pkt_len, pkt_type = dissect_itm_and_dwt_packet(ltvb(offset), nil)
    if pkt_len <= 0 then break end
    table.insert(pkt_types, {type = pkt_type, ofs_beg = offset, ofs_end = offset + pkt_len})
    offset = offset + pkt_len
    cnt = cnt + 1
  end
  -- print("saved desegement: ", pinfo.saved_can_desegment, " len: ", pinfo.desegment_len, "offset ", pinfo.desegment_offset)
  fragments[dev_adr].pkts[pinfo.number] = pkt_types
  -- print("frame", pinfo.number, "packet type", table.unpack(pkt_types))
  if offset < ltvb:len() then
    -- print("frame number: ", pinfo.number, "remaining data: ", ltvb:bytes(offset), " len: ", ltvb:len() - offset)
    fragments[dev_adr].rem[pinfo.number] = ltvb:bytes(offset)
    -- print("frame ", pinfo.number, " Remaining data: ", fragments[dev_adr].rem[pinfo.number])
  end
end

function dap.dissector(buffer, pinfo, tree)
  --debug_print("len: " .. buffer:len())
  local len = buffer:len()
  if len == 0 then return end

  local dev_adr = usb_fields.device_address().value
  local ep_adr = usb_fields.endpoint_address().value
  local is_request = (usb_fields.endpointdir().value == 0)

  local cmd = buffer(0, 1):le_uint()

  local seq_num = nil
  -- Management of debug information
  if pinfo.visited == false then
    debug_print("Packet number: " .. pinfo.number, "Device address: " .. dev_adr, "Endpoint address: " .. ep_adr, "Command: " .. cmd)
    -- Initialization of communication information
    if convlist[dev_adr] == nil then
      convlist[dev_adr] = {
        seq = {}, -- Mapping from frame number to sequence number
        req = {}, -- Mapping from sequence number to request frame number
        res = {}, -- Mapping from sequence number to response frame number
        inf = {}, -- Command information (used for response buffer analysis)
      }
    end
    if is_request then
      if convlist[dev_adr].ep_out == nil then
        convlist[dev_adr].ep_out = ep_adr
      elseif convlist[dev_adr].ep_out ~= ep_adr then
        return false
      end
    else
      if convlist[dev_adr].ep_in == nil then
        convlist[dev_adr].ep_in = ep_adr
      elseif convlist[dev_adr].ep_in ~= ep_adr then
        if convlist[dev_adr].ep_swo == nil then
          -- maybe SWO packet
          convlist[dev_adr].ep_swo = ep_adr
        end
        if convlist[dev_adr].ep_swo == ep_adr then
          parse_trace(buffer, pinfo)
          return true
        else
          return false
        end
      end
    end
    -- Request processing
    if is_request then
      table.insert(convlist[dev_adr].req, pinfo.number)
      seq_num = #convlist[dev_adr].req
      convlist[dev_adr].seq[pinfo.number] = seq_num
      convlist[dev_adr].inf[seq_num] = {cmd = cmd}
    else
      -- Response processing
      local tentative_num = #convlist[dev_adr].res + 1
      -- Search for the same command
      local num_of_reqs = #convlist[dev_adr].req
      while tentative_num <= num_of_reqs do
        if cmd == convlist[dev_adr].inf[tentative_num].cmd then
          break
        end
        tentative_num = tentative_num + 1
      end
      
      if tentative_num <= num_of_reqs then
        table.insert(convlist[dev_adr].res, pinfo.number)
        seq_num = #convlist[dev_adr].res
        if cmd == convlist[dev_adr].inf[seq_num].cmd then
          convlist[dev_adr].seq[pinfo.number] = seq_num
        else
          -- Loss of response packet
          convlist[dev_adr].seq[pinfo.number] = -1
          convlist[dev_adr].seq[convlist[dev_adr].req[seq_num]] = -1
        end
      else
        -- Loss of request packet
        convlist[dev_adr].seq[pinfo.number] = -1
      end
    end
  else
    -- Already processed packet
    if convlist[dev_adr].ep_out ~= ep_adr and convlist[dev_adr].ep_in ~= ep_adr then
      if convlist[dev_adr].ep_swo == ep_adr then
        return dissect_trace(buffer, pinfo, tree)
      else
        return false
      end
    end
    seq_num = convlist[dev_adr].seq[pinfo.number]
    if seq_num and seq_num < 0 then
      seq_num = nil
    end
  end
  pinfo.cols.protocol = "USBDAP"
  local subtree = tree:add(dap, buffer(), "CMSIS-DAP")
  
  -- Warning for packet loss
  if nil == seq_num then
    subtree:add_proto_expert_info(dap.experts.lost)
  end

  -- Construction of display information
  local info_text = ""
  local command = "Unknown"
  if names.command[cmd] ~= nil then
    command = names.command[cmd]
  end
  
  if is_request then
    info_text = command .. " Request "
    if seq_num ~= nil and convlist[dev_adr].res[seq_num] ~= nil then
      subtree:add(dap.fields.res, convlist[dev_adr].res[seq_num])
    end
  else
    info_text = command .. " Response "
    if seq_num ~= nil then 
      subtree:add(dap.fields.req, convlist[dev_adr].req[seq_num])
    end
  end

  -- Command processing
  subtree:add_le(dap.fields.cmd, buffer(0, 1))
  
  -- Processing by command
  if cmd == vals.command.DAP_INFO then
    info_text = info_text .. dissect_info(is_request, buffer(1), subtree, convlist[dev_adr].inf[seq_num] or {})
  elseif cmd == vals.command.DAP_HOST_STATUS then
    info_text = info_text .. dissect_host_status(is_request, buffer(1), subtree)
  elseif cmd == vals.command.DAP_CONNECT then
    info_text = info_text .. dissect_dap_connect(is_request, buffer(1), subtree)
  elseif cmd == vals.command.DAP_DISCONNECT then
    info_text = info_text .. dissect_dap_disconnect(is_request, buffer(1), subtree)
  elseif cmd == vals.command.DAP_TRANSFER_CONFIGURE then
    info_text = info_text .. dissect_transfer_configure(is_request, buffer(1), subtree)
  elseif cmd == vals.command.DAP_TRANSFER then
    info_text = info_text .. dissect_transfer(is_request, buffer(1), subtree, convlist[dev_adr].inf[seq_num] or {})
  elseif cmd == vals.command.DAP_TRANSFER_BLOCK then
    info_text = info_text .. dissect_transfer_block(is_request, buffer(1), subtree, convlist[dev_adr].inf[seq_num] or {})
  elseif cmd == vals.command.DAP_TRANSFER_ABORT then
    -- TODO: Add processing
    info_text = info_text .. "Not implemented"
  elseif cmd == vals.command.DAP_WRITE_ABORT then
    info_text = info_text .. dissect_write_abort(is_request, buffer(1), subtree)
  elseif cmd == vals.command.DAP_DELAY then
    info_text = info_text .. dissect_dap_delay(is_request, buffer(1), subtree)
  elseif cmd == vals.command.DAP_RESET_TARGET then
    info_text = info_text .. dissect_dap_reset_target(is_request, buffer(1), subtree)
  elseif cmd == vals.command.DAP_SWJ_PINS then
    info_text = info_text .. dissect_swj_pins(is_request, buffer(1), subtree)
  elseif cmd == vals.command.DAP_SWJ_CLOCK then
    info_text = info_text .. dissect_swj_clk(is_request, buffer(1), subtree)
  elseif cmd == vals.command.DAP_SWJ_SEQUENCE then
    info_text = info_text .. dissect_swj_seq(is_request, buffer(1), subtree)
  elseif cmd == vals.command.DAP_SWD_CONFIGURE then
    info_text = info_text .. dissect_swd_configure(is_request, buffer(1), subtree)
  elseif cmd == vals.command.DAP_SWO_TRANSPORT then
    info_text = info_text .. dissect_swo_transport(is_request, buffer(1), subtree)
  elseif cmd == vals.command.DAP_SWO_MODE then
    info_text = info_text .. dissect_swo_mode(is_request, buffer(1), subtree)
  elseif cmd == vals.command.DAP_SWO_BAUDRATE then
    info_text = info_text .. dissect_swo_baudrate(is_request, buffer(1), subtree)
  elseif cmd == vals.command.DAP_SWO_CONTROL then
    info_text = info_text .. dissect_swo_control(is_request, buffer(1), subtree)
  elseif cmd == vals.command.DAP_SWO_STATUS then
    info_text = info_text .. dissect_swo_status(is_request, buffer(1), subtree)
  elseif cmd == vals.command.DAP_SWO_DATA then
    info_text = info_text .. dissect_swo_data(is_request, buffer(1), subtree)
  elseif cmd == vals.command.DAP_SWD_SEQUENCE then
    info_text = info_text .. dissect_swd_sequence(is_request, buffer(1), subtree)
  elseif cmd == vals.command.DAP_SWO_EXTENDED_STATUS then
    info_text = info_text .. dissect_swo_extended_status(is_request, buffer(1), subtree)
  elseif cmd == vals.command.DAP_JTAG_SEQUENCE or
         cmd == vals.command.DAP_JTAG_CONFIGURE or
         cmd == vals.command.DAP_JTAG_IDCODE or
         cmd == vals.command.DAP_UART_TRANSPORT or
         cmd == vals.command.DAP_UART_CONFIGURE or
         cmd == vals.command.DAP_UART_TRANSFER or
         cmd == vals.command.DAP_UART_CONTROL or
         cmd == vals.command.DAP_UART_STATUS or
         cmd == vals.command.DAP_QUEUE_COMMANDS or
         cmd == vals.command.DAP_EXECUTE_COMMANDS then
    -- TODO: Add processing for these commands
    info_text = info_text .. "Not implemented"
  end
  pinfo.cols.info = info_text
end

-- Dissector registration
DissectorTable.get("usb.bulk"):add(0xff, dap)
