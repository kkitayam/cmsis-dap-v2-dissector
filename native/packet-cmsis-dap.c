#include <epan/column-utils.h>
#include <epan/dissectors/packet-usb.h>
#include <epan/expert.h>
#include <epan/ftypes/ftypes.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/wmem_scopes.h>
#include <wsutil/wmem/wmem.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define CMSIS_DAP_USB_CLASS 0xff
#define CMSIS_DAP_USB_SUBCLASS 0x00
#define CMSIS_DAP_USB_PROTOCOL 0x00
#define USB_TRANSFER_TYPE_BULK 0x02
#define USB_UNKNOWN_INTERFACE_VALUE 0xffff
#define USB_DESCRIPTOR_STRING 0x03

enum {
    CMD_INFO = 0,
    CMD_HOST_STATUS = 1,
    CMD_CONNECT = 2,
    CMD_DISCONNECT = 3,
    CMD_TRANSFER_CONFIGURE = 4,
    CMD_TRANSFER = 5,
    CMD_TRANSFER_BLOCK = 6,
    CMD_TRANSFER_ABORT = 7,
    CMD_WRITE_ABORT = 8,
    CMD_DELAY = 9,
    CMD_RESET_TARGET = 10,
    CMD_SWJ_PINS = 16,
    CMD_SWJ_CLOCK = 17,
    CMD_SWJ_SEQUENCE = 18,
    CMD_SWD_CONFIGURE = 19,
    CMD_SWO_TRANSPORT = 23,
    CMD_SWO_MODE = 24,
    CMD_SWO_BAUDRATE = 25,
    CMD_SWO_CONTROL = 26,
    CMD_SWO_STATUS = 27,
    CMD_SWO_DATA = 28,
    CMD_SWD_SEQUENCE = 29,
    CMD_SWO_EXTENDED_STATUS = 30
};

static const value_string implementation_names[] = {
    { 0, "Not implemented" }, { 1, "Implemented" }, { 0, NULL }
};

static const value_string command_names[] = {
    { 0, "Info" }, { 1, "HostStatus" }, { 2, "Connect" },
    { 3, "Disconnect" }, { 4, "TransferConfigure" }, { 5, "Transfer" },
    { 6, "TransferBlock" }, { 7, "TransferAbort" }, { 8, "WriteABORT" },
    { 9, "Delay" }, { 10, "ResetTarget" }, { 16, "SWJ_Pins" },
    { 17, "SWJ_Clock" }, { 18, "SWJ_Sequence" }, { 19, "SWD_Configure" },
    { 20, "JTAG_Sequence" }, { 21, "JTAG_Configure" }, { 22, "JTAG_IDCOODE" },
    { 23, "SWO_Transport" }, { 24, "SWO_Mode" }, { 25, "SWO_Baudrate" },
    { 26, "SWO_Control" }, { 27, "SWO_Status" }, { 28, "SWO_Data" },
    { 29, "SWD_Sequence" }, { 30, "SWO_ExtendedStatus" },
    { 31, "UART_Transport" }, { 32, "UART_Configure" },
    { 33, "UART_Transfer" }, { 34, "UART_Control" }, { 35, "UART_Status" },
    { 126, "QueueCommands" }, { 127, "ExecuteCommands" }, { 0, NULL }
};

static const value_string info_names[] = {
    { 1, "Vendor Name" }, { 2, "Product Name" }, { 3, "Serial Number" },
    { 4, "CMSIS-DAP Protocol Version" }, { 5, "Target Device Vendor" },
    { 6, "Target Device Name" }, { 7, "Target Board Vendor" },
    { 8, "Target Board Name" }, { 9, "Product Firmware Version" },
    { 0xf0, "Capabilities" }, { 0xf1, "Test Domain Timer" },
    { 0xfb, "UART Receive Buffer Size" }, { 0xfc, "UART Transmit Buffer Size" },
    { 0xfd, "SWO Trace Buffer Size" }, { 0xfe, "Packet Count" },
    { 0xff, "Packet Size" }, { 0, NULL }
};

static const value_string response_names[] = {
    { 0, "DAP_OK" }, { 0xff, "DAP_ERROR" }, { 0, NULL }
};
static const value_string port_names[] = {
    { 0, "Default" }, { 1, "SWD" }, { 2, "JTAG" }, { 0, NULL }
};
static const value_string mode_names[] = {
    { 0, "Off" }, { 1, "UART" }, { 2, "Manchester" }, { 0, NULL }
};
static const value_string timestamp_format_names[] = {
    { 0, "single-byte" }, { 1, "2 to 5 bytes" }, { 0, NULL }
};
static const value_string exception_function_names[] = {
    { 1, "Entered" }, { 2, "Exited" }, { 3, "Returned" }, { 0, NULL }
};
static const value_string swo_packet_names[] = {
    { 0, "SYN" }, { 1, "OVF" }, { 2, "LTS" }, { 3, "GTS" },
    { 4, "EXT" }, { 5, "DWT" }, { 6, "ITM" }, { 0, NULL }
};
static const value_string ack_names[] = {
    { 1, "OK" }, { 2, "WAIT" }, { 3, "FAULT" }, { 4, "NO_ACKT" }, { 0, NULL }
};

static int proto_cmsis_dap;
static int hf_command;
static int hf_request;
static int hf_response;
static int hf_status;
static int hf_info_id;
static int hf_info_len;
static int hf_info_vendor;
static int hf_info_product;
static int hf_info_serial;
static int hf_info_protocol_version;
static int hf_info_target_device_vendor;
static int hf_info_target_device_name;
static int hf_info_target_board_vendor;
static int hf_info_target_board_name;
static int hf_info_firmware_version;
static int hf_info_capabilities;
static int hf_info_swd;
static int hf_info_jtag;
static int hf_info_swo_uart;
static int hf_info_swo_manchester;
static int hf_info_atomic;
static int hf_info_timer;
static int hf_info_swo_streaming;
static int hf_info_uart;
static int hf_info_usb_com;
static int hf_info_uart_rx_size;
static int hf_info_uart_tx_size;
static int hf_info_swo_size;
static int hf_info_packet_count;
static int hf_info_packet_size;
static int hf_host_status_type;
static int hf_host_status_status;
static int hf_dap_index;
static int hf_port;
static int hf_write_abort;
static int hf_delay;
static int hf_execute;
static int hf_transfer_config_idle;
static int hf_transfer_config_wait;
static int hf_transfer_config_match;
static int hf_swj_output;
static int hf_swj_select;
static int hf_swj_input;
static int hf_swj_tck;
static int hf_swj_tms;
static int hf_swj_tdi;
static int hf_swj_tdo;
static int hf_swj_ntrst;
static int hf_swj_nreset;
static int hf_swj_wait;
static int hf_swj_clock;
static int hf_swj_sequence_count;
static int hf_swj_sequence_data;
static int hf_swd_config;
static int hf_swd_turnaround;
static int hf_swd_data_phase;
static int hf_swo_transport;
static int hf_swo_mode;
static int hf_swo_baudrate;
static int hf_swo_control;
static int hf_swo_status;
static int hf_swo_active;
static int hf_swo_error;
static int hf_swo_overrun;
static int hf_swo_count;
static int hf_swo_data;
static int hf_swo_extended_status;
static int hf_swo_reassembled;
static int hf_transfer_count;
static int hf_transfer;
static int hf_transfer_request;
static int hf_transfer_apndp;
static int hf_transfer_rnw;
static int hf_transfer_a23;
static int hf_transfer_match;
static int hf_transfer_mask;
static int hf_transfer_timestamp;
static int hf_transfer_read_data;
static int hf_transfer_write_data;
static int hf_transfer_mask_data;
static int hf_transfer_match_data;
static int hf_transfer_block_count;
static int hf_transfer_response;
static int hf_transfer_ack;
static int hf_transfer_protocol_error;
static int hf_transfer_value_mismatch;
static int hf_swo_sync;
static int hf_swo_overflow_packet;
static int hf_swo_local_timestamp;
static int hf_swo_global_timestamp;
static int hf_swo_extension;
static int hf_swo_itm;
static int hf_swo_dwt;
static int hf_swo_packet_header;
static int hf_swo_packet_size;
static int hf_swo_packet_category;
static int hf_swo_packet_source;
static int hf_swo_packet_payload;
static int hf_swo_packet_timestamp;
static int hf_swo_lts_type;
static int hf_swo_lts_timestamp;
static int hf_swo_packet_source_type;
static int hf_swo_packet_page;
static int hf_swo_event;
static int hf_swo_event_cpi;
static int hf_swo_event_exc;
static int hf_swo_event_sleep;
static int hf_swo_event_lsu;
static int hf_swo_event_fold;
static int hf_swo_event_cyc;
static int hf_swo_exception_number;
static int hf_swo_exception_function;
static int ett_cmsis_dap;
static int ett_transfer;
static int ett_swo_packet;
static int ett_info_capabilities;
static expert_field ei_malformed = EI_INIT;
static expert_field ei_zero_length = EI_INIT;
static expert_field ei_packet_lost = EI_INIT;
static int proto_cmsis_dap_usb_identity;
static int hf_usb_descriptor_index;
static int hf_usb_descriptor_type;
static int hf_usb_request_in;
static int hf_usb_string;
static int hf_usb_product_string;
static int hf_usb_interface_number;
static int hf_usb_interface_class;
static int hf_usb_interface_subclass;
static int hf_usb_interface_protocol;
static int hf_usb_interface_string;
static int hf_usb_endpoint_address;
static int hf_usb_endpoint_transfer;

static dissector_handle_t usb_identity_handle;

static int dissect_cmsis_dap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void *data);

typedef struct {
    bool descriptor_seen;
    uint8_t interface_class;
    uint8_t interface_subclass;
    uint8_t interface_protocol;
    uint8_t string_index;
    bool string_seen;
    bool string_matches;
    bool have_bulk_out;
    bool have_bulk_in;
} interface_identity_t;

typedef struct {
    wmem_map_t *interfaces;
    wmem_map_t *string_requests;
    bool have_product_string_index;
    uint8_t product_string_index;
    bool product_string_seen;
    bool product_string_matches;
} usb_device_identity_t;

typedef struct {
    uint32_t request_frame;
    uint32_t response_frame;
    uint8_t command;
    uint8_t info_id;
} request_record_t;

typedef struct {
    uint32_t request_frame;
    uint32_t response_frame;
    uint32_t sequence;
    uint8_t command;
    uint8_t info_id;
    uint8_t trace_prefix[16];
    unsigned trace_prefix_length;
    uint32_t trace_prefix_frame;
    bool is_request;
    bool is_trace;
} frame_record_t;

typedef struct {
    wmem_map_t *requests;
    wmem_map_t *frames;
    usb_device_identity_t *identity;
    uint8_t interface_num;
    uint32_t request_count;
    uint32_t response_cursor[256];
    bool have_out_endpoint;
    bool have_in_endpoint;
    uint8_t out_endpoint;
    uint8_t in_endpoint;
    bool have_trace_endpoint;
    uint8_t trace_endpoint;
    bool is_cmsis_dap;
    const char *matched_by;
    uint8_t trace_tail[16];
    unsigned trace_tail_length;
    uint32_t trace_tail_frame;
} device_state_t;

static wmem_map_t *device_states;
static wmem_map_t *usb_device_identities;

#define HF_UINT8(hf, label, abbrev, display, vals, mask) \
    { &(hf), { label, abbrev, FT_UINT8, display, vals, mask, NULL, HFILL } }
#define HF_UINT16(hf, label, abbrev, display, vals, mask) \
    { &(hf), { label, abbrev, FT_UINT16, display, vals, mask, NULL, HFILL } }
#define HF_UINT32(hf, label, abbrev, display, vals, mask) \
    { &(hf), { label, abbrev, FT_UINT32, display, vals, mask, NULL, HFILL } }
#define HF_STRING(hf, label, abbrev) \
    { &(hf), { label, abbrev, FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } }
#define HF_BYTES(hf, label, abbrev) \
    { &(hf), { label, abbrev, FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } }

static hf_register_info hf[] = {
    HF_UINT8(hf_command, "Command", "cmsis_dap.command", BASE_HEX, VALS(command_names), 0),
    { &hf_request, { "Request", "cmsis_dap.request", FT_FRAMENUM, BASE_NONE,
        FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0, NULL, HFILL } },
    { &hf_response, { "Response", "cmsis_dap.response", FT_FRAMENUM, BASE_NONE,
        FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0, NULL, HFILL } },
    HF_UINT8(hf_status, "Status", "cmsis_dap.status", BASE_HEX, VALS(response_names), 0),
    HF_UINT8(hf_info_id, "Id", "cmsis_dap.info.id", BASE_HEX, VALS(info_names), 0),
    HF_UINT8(hf_info_len, "Len", "cmsis_dap.info.len", BASE_DEC_HEX, NULL, 0),
    HF_STRING(hf_info_vendor, "Vendor Name", "cmsis_dap.info.vendor"),
    HF_STRING(hf_info_product, "Product Name", "cmsis_dap.info.product"),
    HF_STRING(hf_info_serial, "Serial Number", "cmsis_dap.info.serial"),
    HF_STRING(hf_info_protocol_version, "CMSIS-DAP Protocol Version", "cmsis_dap.info.protocol_version"),
    HF_STRING(hf_info_target_device_vendor, "Target Device Vendor", "cmsis_dap.info.target.device.vendor"),
    HF_STRING(hf_info_target_device_name, "Target Device Name", "cmsis_dap.info.target.device.name"),
    HF_STRING(hf_info_target_board_vendor, "Target Board Vendor", "cmsis_dap.info.target.board.vendor"),
    HF_STRING(hf_info_target_board_name, "Target Board Name", "cmsis_dap.info.target.board.name"),
    HF_STRING(hf_info_firmware_version, "Product Firmware Version", "cmsis_dap.info.firmware.version"),
    HF_UINT16(hf_info_capabilities, "Capabilities", "cmsis_dap.info.caps", BASE_HEX, NULL, 0),
    HF_UINT8(hf_info_swd, "SWD", "cmsis_dap.info.swd", BASE_HEX, VALS(implementation_names), 0x01),
    HF_UINT8(hf_info_jtag, "JTAG", "cmsis_dap.info.jtag", BASE_HEX, VALS(implementation_names), 0x02),
    HF_UINT8(hf_info_swo_uart, "SWO UART", "cmsis_dap.info.swo_uart", BASE_HEX, VALS(implementation_names), 0x04),
    HF_UINT8(hf_info_swo_manchester, "SWO Manchester", "cmsis_dap.info.swo_manchester", BASE_HEX, VALS(implementation_names), 0x08),
    HF_UINT8(hf_info_atomic, "Atomic Commands", "cmsis_dap.info.atomic", BASE_HEX, VALS(implementation_names), 0x10),
    HF_UINT8(hf_info_timer, "Test Domain Timer", "cmsis_dap.info.timer", BASE_HEX, VALS(implementation_names), 0x20),
    HF_UINT8(hf_info_swo_streaming, "SWO Streaming Trace", "cmsis_dap.info.swo_streaming", BASE_HEX, VALS(implementation_names), 0x40),
    HF_UINT8(hf_info_uart, "UART Communication Port", "cmsis_dap.info.uart", BASE_HEX, VALS(implementation_names), 0x80),
    HF_UINT8(hf_info_usb_com, "USB COM Port", "cmsis_dap.info.usb_com", BASE_HEX, VALS(implementation_names), 0x01),
    HF_UINT32(hf_info_uart_rx_size, "UART Receive Buffer Size", "cmsis_dap.info.uart.rx_bufsz", BASE_DEC, NULL, 0),
    HF_UINT32(hf_info_uart_tx_size, "UART Transmit Buffer Size", "cmsis_dap.info.uart.tx_bufsz", BASE_DEC, NULL, 0),
    HF_UINT32(hf_info_swo_size, "SWO Trace Buffer Size", "cmsis_dap.info.swo_bufsz", BASE_DEC, NULL, 0),
    HF_UINT8(hf_info_packet_count, "Packet Count", "cmsis_dap.info.packet.count", BASE_DEC, NULL, 0),
    HF_UINT16(hf_info_packet_size, "Packet Size", "cmsis_dap.info.packet.size", BASE_DEC, NULL, 0),
    HF_UINT8(hf_host_status_type, "Type", "cmsis_dap.host_status.type", BASE_HEX, NULL, 0),
    HF_UINT8(hf_host_status_status, "Status", "cmsis_dap.host_status.status", BASE_HEX, NULL, 0),
    HF_UINT8(hf_dap_index, "DAP Index", "cmsis_dap.dap_index", BASE_DEC_HEX, NULL, 0),
    HF_UINT8(hf_port, "Port", "cmsis_dap.connect.port", BASE_HEX, VALS(port_names), 0),
    HF_UINT32(hf_write_abort, "Abort", "cmsis_dap.write_abort", BASE_DEC_HEX, NULL, 0),
    HF_UINT32(hf_delay, "Delay", "cmsis_dap.delay", BASE_DEC_HEX, NULL, 0),
    HF_UINT8(hf_execute, "Execute", "cmsis_dap.execute", BASE_DEC_HEX, NULL, 0),
    HF_UINT8(hf_transfer_config_idle, "Idle Cycles", "cmsis_dap.transfer_config.idle_cycles", BASE_DEC_HEX, NULL, 0),
    HF_UINT16(hf_transfer_config_wait, "WAIT Retry", "cmsis_dap.transfer_config.wait_retry", BASE_DEC_HEX, NULL, 0),
    HF_UINT16(hf_transfer_config_match, "Match Retry", "cmsis_dap.transfer_config.match_retry", BASE_DEC_HEX, NULL, 0),
    HF_UINT8(hf_swj_output, "Pin Output", "cmsis_dap.swj.pin.output", BASE_HEX, NULL, 0),
    HF_UINT8(hf_swj_select, "Pin Select", "cmsis_dap.swj.pin.select", BASE_HEX, NULL, 0),
    HF_UINT8(hf_swj_input, "Pin Input", "cmsis_dap.swj.pin.input", BASE_HEX, NULL, 0),
    HF_UINT8(hf_swj_tck, "SWCLK/TCK", "cmsis_dap.swj.pin.swclk_tck", BASE_HEX, NULL, 0x01),
    HF_UINT8(hf_swj_tms, "SWDIO/TMS", "cmsis_dap.swj.pin.swdio_tms", BASE_HEX, NULL, 0x02),
    HF_UINT8(hf_swj_tdi, "TDI", "cmsis_dap.swj.pin.tdi", BASE_HEX, NULL, 0x04),
    HF_UINT8(hf_swj_tdo, "TDO", "cmsis_dap.swj.pin.tdo", BASE_HEX, NULL, 0x08),
    HF_UINT8(hf_swj_ntrst, "nTRST", "cmsis_dap.swj.pin.ntrst", BASE_HEX, NULL, 0x20),
    HF_UINT8(hf_swj_nreset, "nRESET", "cmsis_dap.swj.pin.nreset", BASE_HEX, NULL, 0x80),
    HF_UINT32(hf_swj_wait, "Pin Wait", "cmsis_dap.swj.pin.wait", BASE_DEC_HEX, NULL, 0),
    HF_UINT32(hf_swj_clock, "Clock", "cmsis_dap.swj_clock", BASE_DEC_HEX, NULL, 0),
    HF_UINT8(hf_swj_sequence_count, "Bit Count", "cmsis_dap.swj_sequence.count", BASE_DEC_HEX, NULL, 0),
    HF_BYTES(hf_swj_sequence_data, "Bit Data", "cmsis_dap.swj_sequence.data"),
    HF_UINT8(hf_swd_config, "Configuration", "cmsis_dap.swd_config", BASE_HEX, NULL, 0),
    HF_UINT8(hf_swd_turnaround, "Turnaround clock period", "cmsis_dap.swd_config.turnaround_clock_period", BASE_HEX, NULL, 0x03),
    HF_UINT8(hf_swd_data_phase, "DataPhase", "cmsis_dap.swd_config.data_phase", BASE_HEX, NULL, 0x04),
    HF_UINT8(hf_swo_transport, "Transport", "cmsis_dap.swo_transport", BASE_HEX, NULL, 0),
    HF_UINT8(hf_swo_mode, "Mode", "cmsis_dap.swo_mode", BASE_HEX, VALS(mode_names), 0),
    HF_UINT32(hf_swo_baudrate, "Baudrate", "cmsis_dap.swo_baud", BASE_DEC_HEX, NULL, 0),
    HF_UINT8(hf_swo_control, "Control", "cmsis_dap.swo_ctrl", BASE_HEX, NULL, 0),
    HF_UINT8(hf_swo_status, "Trace Status", "cmsis_dap.swo_sts", BASE_HEX, NULL, 0),
    HF_UINT8(hf_swo_active, "Trace Capture", "cmsis_dap.swo_act", BASE_HEX, NULL, 0x01),
    HF_UINT8(hf_swo_error, "Trace Stream Error", "cmsis_dap.swo_err", BASE_HEX, NULL, 0x40),
    HF_UINT8(hf_swo_overrun, "Trace Buffer Overrun", "cmsis_dap.swo_ovr", BASE_HEX, NULL, 0x80),
    HF_UINT32(hf_swo_count, "Trace Count", "cmsis_dap.swo_cnt", BASE_DEC_HEX, NULL, 0),
    HF_BYTES(hf_swo_data, "Trace Data", "cmsis_dap.swo_data"),
    HF_UINT8(hf_swo_extended_status, "Control", "cmsis_dap.swo_ext_sts", BASE_HEX, NULL, 0),
    { &hf_swo_reassembled, { "Reassembled", "cmsis_dap.swo_reassemble", FT_FRAMENUM,
        BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_NONE), 0, NULL, HFILL } },
    HF_UINT8(hf_transfer_count, "Count", "cmsis_dap.transfer.count", BASE_DEC_HEX, NULL, 0),
    HF_BYTES(hf_transfer, "Transfer", "cmsis_dap.transfer"),
    HF_UINT8(hf_transfer_request, "Request", "cmsis_dap.transfer.request", BASE_HEX, NULL, 0),
    HF_UINT8(hf_transfer_apndp, "APnDP", "cmsis_dap.transfer.request.ap_n_dp", BASE_HEX, NULL, 0x01),
    HF_UINT8(hf_transfer_rnw, "RnW", "cmsis_dap.transfer.request.r_n_w", BASE_HEX, NULL, 0x02),
    HF_UINT8(hf_transfer_a23, "A[2:3]", "cmsis_dap.transfer.request.a23", BASE_HEX, NULL, 0x0c),
    HF_UINT8(hf_transfer_match, "Match", "cmsis_dap.transfer.request.match", BASE_HEX, NULL, 0x10),
    HF_UINT8(hf_transfer_mask, "Mask", "cmsis_dap.transfer.request.mask", BASE_HEX, NULL, 0x20),
    HF_UINT8(hf_transfer_timestamp, "Timestamp", "cmsis_dap.transfer.request.timestamp", BASE_HEX, NULL, 0x80),
    HF_UINT32(hf_transfer_read_data, "Read", "cmsis_dap.transfer.read.data", BASE_DEC_HEX, NULL, 0),
    HF_UINT32(hf_transfer_write_data, "Write", "cmsis_dap.transfer.write.data", BASE_DEC_HEX, NULL, 0),
    HF_UINT32(hf_transfer_mask_data, "Mask", "cmsis_dap.transfer.mask.data", BASE_DEC_HEX, NULL, 0),
    HF_UINT32(hf_transfer_match_data, "Match", "cmsis_dap.transfer.match.data", BASE_DEC_HEX, NULL, 0),
    HF_UINT16(hf_transfer_block_count, "Count", "cmsis_dap.transfer_block.count", BASE_DEC_HEX, NULL, 0),
    HF_UINT8(hf_transfer_response, "Response", "cmsis_dap.transfer.response", BASE_HEX, NULL, 0),
    HF_UINT8(hf_transfer_ack, "Acknowledge", "cmsis_dap.transfer.response.ack", BASE_HEX, VALS(ack_names), 0x07),
    HF_UINT8(hf_transfer_protocol_error, "Protocol Error", "cmsis_dap.transfer.response.protocol_error", BASE_HEX, NULL, 0x08),
    HF_UINT8(hf_transfer_value_mismatch, "Value Mismatch", "cmsis_dap.transfer.response.value_mismatch", BASE_HEX, NULL, 0x10),
    HF_BYTES(hf_swo_sync, "Synchronization packet", "cmsis_dap.swo_sync"),
    HF_BYTES(hf_swo_overflow_packet, "Overflow packet", "cmsis_dap.swo_ovf"),
    HF_BYTES(hf_swo_local_timestamp, "Local timestamp packet", "cmsis_dap.swo_lts"),
    HF_BYTES(hf_swo_global_timestamp, "Global timestamp packet", "cmsis_dap.swo_gts"),
    HF_BYTES(hf_swo_extension, "Extension", "cmsis_dap.swo_ext"),
    HF_BYTES(hf_swo_itm, "ITM packet", "cmsis_dap.swo_itm"),
    HF_BYTES(hf_swo_dwt, "DWT packet", "cmsis_dap.swo_dwt"),
    HF_UINT8(hf_swo_packet_header, "Header", "cmsis_dap.swo_pkt.header", BASE_HEX, NULL, 0),
    HF_UINT8(hf_swo_packet_size, "Packet size", "cmsis_dap.swo_pkt.size", BASE_DEC, NULL, 0x03),
    HF_UINT8(hf_swo_packet_category, "Category", "cmsis_dap.swo_pkt.itm_or_dwt", BASE_DEC, NULL, 0x04),
    HF_UINT8(hf_swo_packet_source, "Source ID / Port", "cmsis_dap.swo_pkt.source", BASE_DEC, NULL, 0xf8),
    HF_UINT32(hf_swo_packet_payload, "Payload", "cmsis_dap.swo_pkt.payload", BASE_DEC_HEX, NULL, 0),
    HF_UINT32(hf_swo_packet_timestamp, "Timestamp", "cmsis_dap.swo_pkt.timestamp", BASE_DEC, NULL, 0),
    HF_UINT8(hf_swo_lts_type, "Local timestamp format", "cmsis_dap.swo_pkt.lts.type", BASE_HEX, VALS(timestamp_format_names), 0x80),
    HF_UINT8(hf_swo_lts_timestamp, "Timestamp", "cmsis_dap.swo_pkt.lts.ts", BASE_DEC, NULL, 0x30),
    HF_UINT8(hf_swo_packet_source_type, "Source", "cmsis_dap.swo_pkt.source", BASE_DEC, NULL, 0x04),
    HF_UINT8(hf_swo_packet_page, "Stimulus port page", "cmsis_dap.swo_pkt.page", BASE_DEC, NULL, 0x70),
    HF_UINT8(hf_swo_event, "Event counter", "cmsis_dap.swo_pkt.dwt.event", BASE_HEX, NULL, 0),
    HF_UINT8(hf_swo_event_cpi, "CPICNT", "cmsis_dap.swo_pkt.dwt.event.cpi", BASE_HEX, NULL, 0x01),
    HF_UINT8(hf_swo_event_exc, "EXCCNT", "cmsis_dap.swo_pkt.dwt.event.exc", BASE_HEX, NULL, 0x02),
    HF_UINT8(hf_swo_event_sleep, "SLEEPCNT", "cmsis_dap.swo_pkt.dwt.event.sleep", BASE_HEX, NULL, 0x04),
    HF_UINT8(hf_swo_event_lsu, "LSUCNT", "cmsis_dap.swo_pkt.dwt.event.lsu", BASE_HEX, NULL, 0x08),
    HF_UINT8(hf_swo_event_fold, "FOLDCNT", "cmsis_dap.swo_pkt.dwt.event.fold", BASE_HEX, NULL, 0x10),
    HF_UINT8(hf_swo_event_cyc, "POSTCNT", "cmsis_dap.swo_pkt.dwt.event.cyc", BASE_HEX, NULL, 0x20),
    HF_UINT16(hf_swo_exception_number, "Exception number", "cmsis_dap.swo_pkt.dwt.except.num", BASE_HEX, NULL, 0x01ff),
    HF_UINT16(hf_swo_exception_function, "Function", "cmsis_dap.swo_pkt.dwt.except.fn", BASE_HEX, VALS(exception_function_names), 0x3000)
};

static void *
device_identity_key(uint16_t bus_id, uint32_t device_address)
{
    uint32_t key_value = ((uint32_t)bus_id << 8) | (device_address & 0xff);

    return GUINT_TO_POINTER(key_value + 1);
}

static usb_device_identity_t *
get_device_identity(uint16_t bus_id, uint32_t device_address)
{
    void *key = device_identity_key(bus_id, device_address);
    usb_device_identity_t *identity = (usb_device_identity_t *)
        wmem_map_lookup(usb_device_identities, key);

    if (identity == NULL) {
        identity = wmem_new0(wmem_file_scope(), usb_device_identity_t);
        identity->interfaces = wmem_map_new(wmem_file_scope(), g_direct_hash,
            g_direct_equal);
        identity->string_requests = wmem_map_new(wmem_file_scope(), g_direct_hash,
            g_direct_equal);
        wmem_map_insert(usb_device_identities, key, identity);
    }
    return identity;
}

static interface_identity_t *
get_interface_identity(usb_device_identity_t *identity, uint8_t interface_num)
{
    void *key = GUINT_TO_POINTER((unsigned)interface_num + 1);
    interface_identity_t *interface = (interface_identity_t *)
        wmem_map_lookup(identity->interfaces, key);

    if (interface == NULL) {
        interface = wmem_new0(wmem_file_scope(), interface_identity_t);
        wmem_map_insert(identity->interfaces, key, interface);
    }
    return interface;
}

static device_state_t *
lookup_device_state(uint16_t bus_id, uint32_t device_address, uint8_t interface_num)
{
    uint32_t key_value = ((uint32_t)bus_id << 15) |
        ((device_address & 0x7f) << 8) | interface_num;
    void *key = GUINT_TO_POINTER(key_value + 1);
    return (device_state_t *)wmem_map_lookup(device_states, key);
}

static device_state_t *
get_device_state(uint16_t bus_id, uint32_t device_address, uint8_t interface_num)
{
    /* USB endpoint conversations are separate; share command state by interface. */
    device_state_t *state = lookup_device_state(bus_id, device_address, interface_num);

    if (state == NULL) {
        uint32_t key_value = ((uint32_t)bus_id << 15) |
            ((device_address & 0x7f) << 8) | interface_num;
        void *key = GUINT_TO_POINTER(key_value + 1);

        state = wmem_new0(wmem_file_scope(), device_state_t);
        state->requests = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
        state->frames = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
        state->identity = get_device_identity(bus_id, device_address);
        state->interface_num = interface_num;
        wmem_map_insert(device_states, key, state);
    }
    return state;
}

static uint32_t
get_usb_device_address_for_identity(packet_info *pinfo, uint16_t *bus_id)
{
    /* The descriptor postdissector has no urb_info_t to read USB addresses from. */
    const address *addresses[] = { &pinfo->src, &pinfo->dst };

    for (unsigned i = 0; i < G_N_ELEMENTS(addresses); i++) {
        if (addresses[i]->len == USB_ADDR_LEN) {
            const usb_address_t *usb_address = (const usb_address_t *)addresses[i]->data;
            if (usb_address->device != NO_ENDPOINT) {
                *bus_id = usb_address->bus_id;
                return usb_address->device;
            }
        }
    }
    *bus_id = 0;
    return 0;
}

static GPtrArray *
usb_field_values(proto_tree *tree, int hfindex)
{
    if (tree == NULL || hfindex < 0) {
        return NULL;
    }
    GPtrArray *found = proto_find_finfo(tree, hfindex);
    if (found == NULL) {
        return NULL;
    }
    GPtrArray *fields = g_ptr_array_sized_new(found->len);
    for (unsigned i = 0; i < found->len; i++) {
        g_ptr_array_add(fields, g_ptr_array_index(found, i));
    }
    g_ptr_array_free(found, true);
    return fields;
}

static unsigned
usb_field_count(GPtrArray *fields)
{
    return fields != NULL ? fields->len : 0;
}

static field_info *
usb_field_at(GPtrArray *fields, unsigned index)
{
    return fields != NULL && index < fields->len ?
        (field_info *)g_ptr_array_index(fields, index) : NULL;
}

static void
usb_field_values_free(GPtrArray *fields)
{
    if (fields != NULL) {
        g_ptr_array_free(fields, true);
    }
}

static uint32_t
usb_field_uint(GPtrArray *fields, unsigned index)
{
    field_info *field = usb_field_at(fields, index);

    return field != NULL ? fvalue_get_uinteger(field->value) : 0;
}

static bool
string_contains_cmsis_dap(const char *value)
{
    if (value == NULL) {
        return false;
    }
    char *normalized = g_ascii_strdown(value, -1);
    for (char *cursor = normalized; *cursor != '\0'; cursor++) {
        if (*cursor == '_') {
            *cursor = '-';
        }
    }
    bool matched = strstr(normalized, "cmsis-dap") != NULL;
    g_free(normalized);
    return matched;
}

static int
dissect_usb_identity(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree,
    void *data _U_)
{
    if (PINFO_FD_VISITED(pinfo)) {
        return 0;
    }
    uint16_t bus_id;
    uint32_t device_address = get_usb_device_address_for_identity(pinfo, &bus_id);
    /* Identity requires the first-pass tree from the parent USB dissector. */
    if (device_address == 0 || tree == NULL) {
        return 0;
    }
    usb_device_identity_t *identity = get_device_identity(bus_id, device_address);

    GPtrArray *descriptor_indexes = usb_field_values(tree, hf_usb_descriptor_index);
    GPtrArray *descriptor_types = usb_field_values(tree, hf_usb_descriptor_type);
    for (unsigned i = 0; i < MIN(usb_field_count(descriptor_indexes),
            usb_field_count(descriptor_types)); i++) {
        if (usb_field_uint(descriptor_types, i) == USB_DESCRIPTOR_STRING &&
            usb_field_at(descriptor_indexes, i) != NULL) {
            wmem_map_insert(identity->string_requests,
                GUINT_TO_POINTER(pinfo->num + 1),
                GUINT_TO_POINTER(usb_field_uint(descriptor_indexes, i) + 1));
        }
    }

    GPtrArray *product_indexes = usb_field_values(tree, hf_usb_product_string);
    if (usb_field_count(product_indexes) > 0) {
        identity->have_product_string_index = true;
        identity->product_string_index = (uint8_t)usb_field_uint(product_indexes, 0);
    }

    GPtrArray *interface_numbers = usb_field_values(tree, hf_usb_interface_number);
    GPtrArray *interface_classes = usb_field_values(tree, hf_usb_interface_class);
    GPtrArray *interface_subclasses = usb_field_values(tree, hf_usb_interface_subclass);
    GPtrArray *interface_protocols = usb_field_values(tree, hf_usb_interface_protocol);
    GPtrArray *interface_strings = usb_field_values(tree, hf_usb_interface_string);
    unsigned interface_count = MIN(usb_field_count(interface_numbers),
        usb_field_count(interface_strings));
    for (unsigned i = 0; i < interface_count; i++) {
        uint8_t interface_num = (uint8_t)usb_field_uint(interface_numbers, i);
        interface_identity_t *interface = get_interface_identity(identity, interface_num);

        interface->descriptor_seen = true;
        if (i < usb_field_count(interface_classes)) {
            interface->interface_class = (uint8_t)usb_field_uint(interface_classes, i);
        }
        if (i < usb_field_count(interface_subclasses)) {
            interface->interface_subclass = (uint8_t)usb_field_uint(interface_subclasses, i);
        }
        if (i < usb_field_count(interface_protocols)) {
            interface->interface_protocol = (uint8_t)usb_field_uint(interface_protocols, i);
        }
        interface->string_index = (uint8_t)usb_field_uint(interface_strings, i);
    }

    GPtrArray *endpoint_addresses = usb_field_values(tree, hf_usb_endpoint_address);
    GPtrArray *endpoint_transfers = usb_field_values(tree, hf_usb_endpoint_transfer);
    interface_count = usb_field_count(interface_numbers);
    if (interface_count > 0) {
        unsigned current_interface = 0;
        for (unsigned i = 0; i < MIN(usb_field_count(endpoint_addresses),
                usb_field_count(endpoint_transfers)); i++) {
            field_info *endpoint_field = usb_field_at(endpoint_addresses, i);
            interface_identity_t *interface;
            uint32_t endpoint;

            while (current_interface + 1 < interface_count &&
                usb_field_at(interface_numbers, current_interface + 1)->start <
                    endpoint_field->start) {
                current_interface++;
            }
            if (usb_field_uint(endpoint_transfers, i) != USB_TRANSFER_TYPE_BULK) {
                continue;
            }
            interface = get_interface_identity(identity,
                (uint8_t)usb_field_uint(interface_numbers, current_interface));
            endpoint = usb_field_uint(endpoint_addresses, i);
            if ((endpoint & 0x80) != 0) {
                interface->have_bulk_in = true;
            } else {
                interface->have_bulk_out = true;
            }
        }
    }

    GPtrArray *request_frames = usb_field_values(tree, hf_usb_request_in);
    GPtrArray *strings = usb_field_values(tree, hf_usb_string);
    if (usb_field_count(request_frames) > 0 && usb_field_count(strings) > 0) {
        uint32_t request_frame = usb_field_uint(request_frames, 0);
        void *index_value = wmem_map_lookup(identity->string_requests,
            GUINT_TO_POINTER(request_frame + 1));
        field_info *string_field = usb_field_at(strings, 0);

        if (index_value != NULL && string_field != NULL) {
            uint8_t string_index = (uint8_t)(GPOINTER_TO_UINT(index_value) - 1);
            const char *value = fvalue_get_string(string_field->value);
            bool matches = string_contains_cmsis_dap(value);

            if (identity->have_product_string_index &&
                identity->product_string_index == string_index) {
                identity->product_string_seen = true;
                identity->product_string_matches = matches;
            }
            for (unsigned i = 0; i < 256; i++) {
                interface_identity_t *interface = (interface_identity_t *)
                    wmem_map_lookup(identity->interfaces, GUINT_TO_POINTER(i + 1));
                if (interface != NULL && interface->string_index == string_index) {
                    interface->string_seen = true;
                    interface->string_matches = matches;
                }
            }
        }
    }
    usb_field_values_free(descriptor_indexes);
    usb_field_values_free(descriptor_types);
    usb_field_values_free(request_frames);
    usb_field_values_free(strings);
    usb_field_values_free(product_indexes);
    usb_field_values_free(interface_numbers);
    usb_field_values_free(interface_classes);
    usb_field_values_free(interface_subclasses);
    usb_field_values_free(interface_protocols);
    usb_field_values_free(interface_strings);
    usb_field_values_free(endpoint_addresses);
    usb_field_values_free(endpoint_transfers);
    return 0;
}

static void
add_generated_frame(proto_tree *tree, int hfindex, tvbuff_t *tvb, uint32_t frame)
{
    if (tree == NULL || frame == 0) {
        return;
    }
    proto_item *item = proto_tree_add_uint(tree, hfindex, tvb, 0, 0, frame);
    proto_item_set_generated(item);
}

static void
add_info_string(proto_tree *tree, int hfindex, tvbuff_t *tvb, unsigned offset, unsigned length)
{
    if (tree == NULL || length == 0) {
        return;
    }
    char *value = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_UTF_8);
    proto_tree_add_string(tree, hfindex, tvb, offset, length, value);
}

static int
info_string_field(uint8_t id)
{
    switch (id) {
    case 1: return hf_info_vendor;
    case 2: return hf_info_product;
    case 3: return hf_info_serial;
    case 4: return hf_info_protocol_version;
    case 5: return hf_info_target_device_vendor;
    case 6: return hf_info_target_device_name;
    case 7: return hf_info_target_board_vendor;
    case 8: return hf_info_target_board_name;
    case 9: return hf_info_firmware_version;
    default: return -1;
    }
}

static void
add_malformed(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, const char *message)
{
    if (tree != NULL) {
        proto_tree_add_expert_format(tree, pinfo, &ei_malformed, tvb, 0,
            tvb_captured_length(tvb), "%s", message);
    }
}

static unsigned
parse_swo_stream(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    unsigned offset, unsigned *packet_count, GString *summary)
{
    *packet_count = 0;
    unsigned length = tvb_captured_length(tvb);
    while (offset < length) {
        unsigned start = offset;
        uint8_t header = tvb_get_uint8(tvb, offset);
        uint8_t first_header = header;
        uint32_t timestamp_value = 0;
        unsigned shift = 0;
        unsigned packet_length;
        unsigned payload_length;
        int packet_type;
        int packet_hf;
        if (header == 0) {
            while (offset < length && tvb_get_uint8(tvb, offset) == 0) {
                offset++;
            }
            if (offset >= length) {
                return start;
            }
            if (offset - start >= 5 && tvb_get_uint8(tvb, offset) == 0x80) {
                packet_length = offset - start + 1;
                offset++;
                packet_hf = hf_swo_sync;
                packet_type = 0;
            } else {
                packet_length = offset - start;
                packet_hf = hf_swo_sync;
                packet_type = -1;
            }
        } else if ((header & 0x03) != 0) {
            payload_length = (header & 0x03) == 3 ? 4 : (header & 0x03);
            packet_length = 1 + payload_length;
            if (length - start < packet_length) {
                return start;
            }
            packet_type = (header & 0x08) != 0 ? 5 : 6;
            packet_hf = packet_type == 5 ? hf_swo_dwt : hf_swo_itm;
            offset += packet_length;
        } else if (header == 0x70) {
            packet_length = 1;
            packet_type = 1;
            packet_hf = hf_swo_overflow_packet;
            offset++;
        } else if ((header & 0x0c) == 0) {
            packet_length = 1;
            packet_type = 2;
            packet_hf = hf_swo_local_timestamp;
            offset++;
            if ((header & 0x80) != 0) {
                unsigned bytes = 0;
                do {
                    if (offset >= length) {
                        return start;
                    }
                    header = tvb_get_uint8(tvb, offset++);
                    timestamp_value |= (uint32_t)(header & 0x7f) << shift;
                    shift += 7;
                    bytes++;
                } while ((header & 0x80) != 0 && bytes < 5);
                packet_length += bytes;
            }
        } else if ((header & 0x0b) == 0x08) {
            packet_length = 1;
            packet_type = 4;
            packet_hf = hf_swo_extension;
            offset++;
            if ((header & 0x80) != 0) {
                unsigned bytes = 0;
                do {
                    if (offset >= length) {
                        return start;
                    }
                    header = tvb_get_uint8(tvb, offset++);
                    bytes++;
                } while ((header & 0x80) != 0 && bytes < 4);
                packet_length += bytes;
            }
        } else if ((header & 0xdc) == 0x94) {
            unsigned max_bytes = header == 0x94 ? 4 : 6;
            unsigned bytes = 0;
            packet_length = 1;
            packet_type = 3;
            packet_hf = hf_swo_global_timestamp;
            offset++;
            do {
                if (offset >= length) {
                    return start;
                }
                header = tvb_get_uint8(tvb, offset++);
                bytes++;
            } while ((header & 0x80) != 0 && bytes < max_bytes);
            packet_length += bytes;
        } else {
            return start;
        }

        if (tree != NULL && packet_type >= 0 && packet_length > 0) {
            proto_item *item = proto_tree_add_item(tree, packet_hf, tvb, start,
                packet_length, ENC_NA);
            proto_tree *packet_tree = item != NULL ?
                proto_item_add_subtree(item, ett_swo_packet) : NULL;
            if (packet_tree != NULL && packet_type >= 5) {
                proto_tree_add_item(packet_tree, hf_swo_packet_header, tvb, start, 1, ENC_NA);
                proto_tree_add_item(packet_tree, hf_swo_packet_size, tvb, start, 1, ENC_NA);
                proto_tree_add_item(packet_tree, hf_swo_packet_category, tvb, start, 1, ENC_NA);
                proto_tree_add_item(packet_tree, hf_swo_packet_source, tvb, start, 1, ENC_NA);
                payload_length = packet_length - 1;
                if (payload_length <= 4) {
                    proto_tree_add_item(packet_tree, hf_swo_packet_payload, tvb, start + 1,
                        payload_length, ENC_LITTLE_ENDIAN);
                }
                if (first_header == 0x05) {
                    proto_tree_add_item(packet_tree, hf_swo_event, tvb, start + 1, 1,
                        ENC_NA);
                    proto_tree_add_item(packet_tree, hf_swo_event_cpi, tvb, start + 1, 1,
                        ENC_NA);
                    proto_tree_add_item(packet_tree, hf_swo_event_exc, tvb, start + 1, 1,
                        ENC_NA);
                    proto_tree_add_item(packet_tree, hf_swo_event_sleep, tvb, start + 1, 1,
                        ENC_NA);
                    proto_tree_add_item(packet_tree, hf_swo_event_lsu, tvb, start + 1, 1,
                        ENC_NA);
                    proto_tree_add_item(packet_tree, hf_swo_event_fold, tvb, start + 1, 1,
                        ENC_NA);
                    proto_tree_add_item(packet_tree, hf_swo_event_cyc, tvb, start + 1, 1,
                        ENC_NA);
                } else if (first_header == 0x0e && packet_length >= 3) {
                    proto_tree_add_item(packet_tree, hf_swo_exception_number, tvb, start + 1,
                        2, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(packet_tree, hf_swo_exception_function, tvb,
                        start + 1, 2, ENC_LITTLE_ENDIAN);
                }
            } else if (packet_tree != NULL && packet_type >= 0) {
                proto_tree_add_item(packet_tree, hf_swo_packet_header, tvb, start, 1, ENC_NA);
                if (packet_type == 2) {
                    if ((first_header & 0x80) == 0) {
                        proto_tree_add_item(packet_tree, hf_swo_lts_type, tvb, start, 1,
                            ENC_NA);
                        proto_tree_add_item(packet_tree, hf_swo_lts_timestamp, tvb, start, 1,
                            ENC_NA);
                    } else {
                        proto_tree_add_uint(packet_tree, hf_swo_packet_timestamp, tvb,
                            start + 1, packet_length - 1, timestamp_value);
                    }
                } else if (packet_type == 4 && (first_header & 0x80) == 0) {
                    proto_tree_add_item(packet_tree, hf_swo_packet_source_type, tvb, start, 1,
                        ENC_NA);
                    proto_tree_add_item(packet_tree, hf_swo_packet_page, tvb, start, 1, ENC_NA);
                }
            }
        }
        if (packet_type >= -1) {
            g_string_append(summary, val_to_str_const(packet_type, swo_packet_names, "UNK"));
            g_string_append_c(summary, ' ');
            (*packet_count)++;
        }
    }
    return offset;
}

static void
dissect_trace(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, device_state_t *state,
    frame_record_t *frame_record)
{
    const bool first_pass = !PINFO_FD_VISITED(pinfo);

    if (first_pass) {
        frame_record->trace_prefix_length = state->trace_tail_length;
        frame_record->trace_prefix_frame = state->trace_tail_frame;
        if (frame_record->trace_prefix_length > 0) {
            memcpy(frame_record->trace_prefix, state->trace_tail,
                frame_record->trace_prefix_length);
        }
    }
    unsigned current_length = tvb_captured_length(tvb);
    unsigned total_length = current_length + frame_record->trace_prefix_length;
    uint8_t *merged = (uint8_t *)wmem_alloc(wmem_packet_scope(), total_length);

    proto_item *root_item = tree != NULL ? proto_tree_add_item(tree, proto_cmsis_dap, tvb, 0,
        current_length, ENC_NA) : NULL;
    if (root_item != NULL) {
        proto_item_set_text(root_item, "CMSIS-DAP");
    }
    proto_tree *dap_tree = root_item != NULL ?
        proto_item_add_subtree(root_item, ett_cmsis_dap) : NULL;

    if (frame_record->trace_prefix_length > 0) {
        memcpy(merged, frame_record->trace_prefix, frame_record->trace_prefix_length);
        if (dap_tree != NULL && frame_record->trace_prefix_frame != 0) {
            add_generated_frame(dap_tree, hf_swo_reassembled, tvb,
                frame_record->trace_prefix_frame);
        }
    }
    if (current_length > 0) {
        memcpy(merged + frame_record->trace_prefix_length,
            tvb_get_ptr(tvb, 0, current_length), current_length);
    }
    tvbuff_t *stream = tvb_new_real_data(merged, total_length, total_length);
    add_new_data_source(pinfo, stream, "Reassembled SWO trace");
    unsigned packet_count;
    GString *summary = g_string_new("");
    unsigned parsed = parse_swo_stream(stream, pinfo, dap_tree, 0, &packet_count, summary);
    if (first_pass) {
        state->trace_tail_length = total_length - parsed;
        if (state->trace_tail_length > sizeof(state->trace_tail)) {
            state->trace_tail_length = 0;
        } else if (state->trace_tail_length > 0) {
            memcpy(state->trace_tail, merged + parsed, state->trace_tail_length);
            state->trace_tail_frame = pinfo->num;
        } else {
            state->trace_tail_frame = 0;
        }
    }
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USBDAP");
    col_add_fstr(pinfo->cinfo, COL_INFO, "SWO_Data %u packet(s) %s", packet_count,
        summary->str);
    g_string_free(summary, true);
}

static void
dissect_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned payload_offset,
    bool is_request, uint8_t info_id, char *summary, gsize summary_length)
{
    unsigned length = tvb_captured_length(tvb);
    if (payload_offset >= length) {
        add_malformed(tree, pinfo, tvb, "Info packet is missing its ID or length");
        return;
    }
    uint8_t id_or_length = tvb_get_uint8(tvb, payload_offset);
    if (is_request) {
        if (tree != NULL) {
            proto_tree_add_item(tree, hf_info_id, tvb, payload_offset, 1, ENC_NA);
        }
        g_snprintf(summary, summary_length, "%s",
            val_to_str_const(id_or_length, info_names, "Unknown ID"));
        return;
    }
    int string_hf = info_string_field(info_id);
    if (tree != NULL) {
        proto_tree_add_item(tree, hf_info_len, tvb, payload_offset, 1, ENC_NA);
    }
    if (length - payload_offset < (unsigned)id_or_length + 1) {
        add_malformed(tree, pinfo, tvb, "Info response is shorter than its declared length");
        return;
    }
    if (id_or_length > 0) {
        if (info_id >= 0xfb && info_id <= 0xfd && id_or_length >= 4 &&
            length - payload_offset >= 5) {
            int field = info_id == 0xfb ? hf_info_uart_rx_size :
                (info_id == 0xfc ? hf_info_uart_tx_size : hf_info_swo_size);
            uint32_t value = tvb_get_letohl(tvb, payload_offset + 1);
            if (tree != NULL) {
                proto_tree_add_item(tree, field, tvb, payload_offset + 1, 4,
                    ENC_LITTLE_ENDIAN);
            }
            g_snprintf(summary, summary_length, "%s %u bytes",
                val_to_str_const(info_id, info_names, "Info"), value);
        } else if (info_id == 0xfe && id_or_length >= 1) {
            if (tree != NULL) {
                proto_tree_add_item(tree, hf_info_packet_count, tvb,
                    payload_offset + 1, 1, ENC_NA);
            }
            g_snprintf(summary, summary_length, "%s %u packets",
                val_to_str_const(info_id, info_names, "Info"),
                tvb_get_uint8(tvb, payload_offset + 1));
        } else if (info_id == 0xff && id_or_length >= 2) {
            if (tree != NULL) {
                proto_tree_add_item(tree, hf_info_packet_size, tvb, payload_offset + 1, 2,
                    ENC_LITTLE_ENDIAN);
            }
            g_snprintf(summary, summary_length, "%s %u bytes",
                val_to_str_const(info_id, info_names, "Info"),
                tvb_get_letohs(tvb, payload_offset + 1));
        } else if (info_id == 0xf0) {
            unsigned i;
            proto_item *capabilities_item;
            proto_tree *capabilities_tree;
            int capability_fields[] = {
                hf_info_swd, hf_info_jtag, hf_info_swo_uart, hf_info_swo_manchester,
                hf_info_atomic, hf_info_timer, hf_info_swo_streaming, hf_info_uart
            };
            if (id_or_length < 2) {
                add_malformed(tree, pinfo, tvb,
                    "Capabilities Info response must contain 2 bytes");
            } else {
                capabilities_item = tree != NULL ?
                    proto_tree_add_item(tree, hf_info_capabilities, tvb, payload_offset + 1,
                        2, ENC_LITTLE_ENDIAN) : NULL;
                capabilities_tree = capabilities_item != NULL ?
                    proto_item_add_subtree(capabilities_item, ett_info_capabilities) : NULL;
                if (capabilities_tree != NULL) {
                    for (i = 0; i < G_N_ELEMENTS(capability_fields); i++) {
                        proto_tree_add_item(capabilities_tree, capability_fields[i], tvb,
                            payload_offset + 1, 1, ENC_NA);
                    }
                    proto_tree_add_item(capabilities_tree, hf_info_usb_com, tvb,
                        payload_offset + 2, 1, ENC_NA);
                }
            }
            g_snprintf(summary, summary_length, "%s",
                val_to_str_const(info_id, info_names, "Info"));
        } else if (string_hf >= 0) {
            add_info_string(tree, string_hf, tvb, payload_offset + 1, id_or_length);
            g_snprintf(summary, summary_length, "%s %.*s",
                val_to_str_const(info_id, info_names, "Info"), id_or_length,
                tvb_get_string_enc(wmem_packet_scope(), tvb, payload_offset + 1,
                    id_or_length, ENC_UTF_8));
        } else {
            g_snprintf(summary, summary_length, "%s",
                val_to_str_const(info_id, info_names, "Info"));
        }
    } else {
        g_snprintf(summary, summary_length, "%s",
            val_to_str_const(info_id, info_names, "Info"));
    }
}

static void
dissect_transfer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned payload_offset,
    bool is_request, char *summary, gsize summary_length)
{
    unsigned length = tvb_captured_length(tvb);
    unsigned count_offset = payload_offset + (is_request ? 1 : 0);

    if (length <= count_offset) {
        add_malformed(tree, pinfo, tvb, "Transfer packet is too short");
        return;
    }
    if (is_request) {
        unsigned count = tvb_get_uint8(tvb, payload_offset + 1);
        unsigned parsed_transfers = 0;
        unsigned offset = payload_offset + 2;
        bool have_previous = false;
        bool previous_is_write = false;
        GString *accesses = g_string_new("");
        if (tree != NULL) {
            proto_tree_add_item(tree, hf_dap_index, tvb, payload_offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_transfer_count, tvb, payload_offset + 1, 1, ENC_NA);
        }
        proto_item *item = tree != NULL ?
            proto_tree_add_item(tree, hf_transfer, tvb, payload_offset + 2,
                length - payload_offset - 2, ENC_NA) : NULL;
        proto_tree *subtree = item != NULL ?
            proto_item_add_subtree(item, ett_transfer) : NULL;
        for (unsigned i = 0; i < count && offset < length; i++) {
            uint8_t request = tvb_get_uint8(tvb, offset);
            bool is_write = (request & 0x02) == 0;
            if (!have_previous || is_write != previous_is_write) {
                g_string_append_c(accesses, is_write ? 'W' : 'R');
            }
            have_previous = true;
            previous_is_write = is_write;
            parsed_transfers++;
            if (subtree != NULL) {
                proto_tree_add_item(subtree, hf_transfer_request, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(subtree, hf_transfer_apndp, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(subtree, hf_transfer_rnw, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(subtree, hf_transfer_a23, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(subtree, hf_transfer_match, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(subtree, hf_transfer_mask, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(subtree, hf_transfer_timestamp, tvb, offset, 1, ENC_NA);
            }
            offset++;
            if (is_write || (request & 0x10) != 0) {
                if (length - offset < 4) {
                    add_malformed(subtree, pinfo, tvb, "Transfer request data is truncated");
                    break;
                }
                if (subtree != NULL) {
                    int data_hf = is_write ?
                        ((request & 0x20) != 0 ? hf_transfer_mask_data :
                            hf_transfer_write_data) : hf_transfer_match_data;
                    proto_tree_add_item(subtree, data_hf, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                }
                offset += 4;
            }
        }
        if (parsed_transfers > 1) {
            g_string_append_printf(accesses, "%u", parsed_transfers);
        }
        g_snprintf(summary, summary_length, "%u word(s) %s", count, accesses->str);
        g_string_free(accesses, true);
    } else {
        unsigned count = tvb_get_uint8(tvb, payload_offset);
        if (length - payload_offset < 2) {
            add_malformed(tree, pinfo, tvb, "Transfer response is missing its status");
            return;
        }
        uint8_t response = tvb_get_uint8(tvb, payload_offset + 1);
        if (tree != NULL) {
            proto_tree_add_item(tree, hf_transfer_count, tvb, payload_offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_transfer_response, tvb, payload_offset + 1, 1,
                ENC_NA);
            proto_tree_add_item(tree, hf_transfer_ack, tvb, payload_offset + 1, 1, ENC_NA);
            proto_tree_add_item(tree, hf_transfer_protocol_error, tvb, payload_offset + 1,
                1, ENC_NA);
            proto_tree_add_item(tree, hf_transfer_value_mismatch, tvb, payload_offset + 1,
                1, ENC_NA);
        }
        unsigned offset = payload_offset + 2;
        for (unsigned i = 0; i < count && length - offset >= 4; i++, offset += 4) {
            if (tree != NULL) {
                proto_tree_add_item(tree, hf_transfer_read_data, tvb, offset, 4,
                    ENC_LITTLE_ENDIAN);
            }
        }
        g_snprintf(summary, summary_length, "%s %u word(s)",
            val_to_str_const(response & 0x07, ack_names, "Unknown"), count);
    }
}

static void
add_response_status(tvbuff_t *tvb, proto_tree *tree, unsigned offset, unsigned payload_length,
    char *summary, gsize summary_length)
{
    if (payload_length == 0) {
        return;
    }
    uint8_t status = tvb_get_uint8(tvb, offset);
    if (tree != NULL) {
        proto_tree_add_item(tree, hf_status, tvb, offset, 1, ENC_NA);
    }
    g_snprintf(summary, summary_length, "%s",
        val_to_str_const(status, response_names, "Unknown"));
}

static void
add_swj_pin_bits(proto_tree *tree, tvbuff_t *tvb, unsigned offset)
{
    proto_tree_add_item(tree, hf_swj_tck, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_swj_tms, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_swj_tdi, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_swj_tdo, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_swj_ntrst, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_swj_nreset, tvb, offset, 1, ENC_NA);
}

static void
summarize_command_data(tvbuff_t *tvb, bool is_request, frame_record_t *frame,
    char *summary, gsize summary_length, packet_info *pinfo)
{
    unsigned length = tvb_captured_length(tvb);
    unsigned payload_offset = 1;
    unsigned payload_length = length > payload_offset ? length - payload_offset : 0;

    switch (frame->command) {
    case CMD_INFO:
        dissect_info(tvb, pinfo, NULL, payload_offset, is_request, frame->info_id, summary,
            summary_length);
        break;
    case CMD_HOST_STATUS:
        if (is_request && payload_length >= 2) {
            g_snprintf(summary, summary_length, "%s",
                tvb_get_uint8(tvb, payload_offset) == 0 ? "Connect" :
                (tvb_get_uint8(tvb, payload_offset) == 1 ? "Running" : ""));
        }
        break;
    case CMD_CONNECT:
        if (payload_length > 0) {
            g_snprintf(summary, summary_length, "%s",
                val_to_str_const(tvb_get_uint8(tvb, payload_offset), port_names, ""));
        }
        break;
    case CMD_TRANSFER:
        dissect_transfer(tvb, pinfo, NULL, payload_offset, is_request, summary, summary_length);
        break;
    case CMD_TRANSFER_CONFIGURE:
    case CMD_WRITE_ABORT:
    case CMD_DELAY:
    case CMD_SWO_TRANSPORT:
    case CMD_SWO_CONTROL:
    case CMD_SWJ_SEQUENCE:
    case CMD_SWD_SEQUENCE:
    case CMD_SWD_CONFIGURE:
    case CMD_DISCONNECT:
    case CMD_RESET_TARGET:
        if (!is_request) {
            add_response_status(tvb, NULL, payload_offset, payload_length, summary,
                summary_length);
        }
        break;
    case CMD_TRANSFER_BLOCK:
        if (is_request && payload_length >= 4) {
            uint16_t count = tvb_get_letohs(tvb, payload_offset + 1);
            bool is_read = (tvb_get_uint8(tvb, payload_offset + 3) & 2) != 0;
            g_snprintf(summary, summary_length, "%u word(s) %s", count,
                is_read ? "Read" : "Write");
        } else if (!is_request && payload_length >= 3) {
            uint16_t count = tvb_get_letohs(tvb, payload_offset);
            uint8_t ack = tvb_get_uint8(tvb, payload_offset + 2);
            bool is_read = payload_length > 3;
            g_snprintf(summary, summary_length, "%s %u word(s) %s",
                val_to_str_const(ack & 0x07, ack_names, "Unknown"), count,
                is_read ? "Read" : "Write");
        }
        break;
    case CMD_SWJ_CLOCK:
        if (payload_length >= 4 && is_request) {
            uint32_t value = tvb_get_letohl(tvb, payload_offset);
            g_snprintf(summary, summary_length, "%uHz", value);
        } else if (!is_request) {
            add_response_status(tvb, NULL, payload_offset, payload_length, summary,
                summary_length);
        }
        break;
    case CMD_SWO_MODE:
        if (payload_length > 0 && is_request) {
            g_snprintf(summary, summary_length, "%s",
                val_to_str_const(tvb_get_uint8(tvb, payload_offset), mode_names, ""));
        } else if (!is_request) {
            add_response_status(tvb, NULL, payload_offset, payload_length, summary,
                summary_length);
        }
        break;
    case CMD_SWO_BAUDRATE:
        if (payload_length >= 4) {
            uint32_t value = tvb_get_letohl(tvb, payload_offset);
            g_snprintf(summary, summary_length, "%ubps", value);
        }
        break;
    case CMD_SWO_STATUS:
        if (!is_request && payload_length >= 3) {
            unsigned value = tvb_get_letohs(tvb, payload_offset + 1);
            g_snprintf(summary, summary_length, "%u byte(s)", value);
        }
        break;
    case CMD_SWO_DATA:
        if (!is_request && payload_length >= 3) {
            unsigned count = tvb_get_letohs(tvb, payload_offset + 1);
            if (count > 0) {
                unsigned data_length = payload_length - 3;
                unsigned parsed_count;
                GString *types = g_string_new("");
                tvbuff_t *stream = tvb_new_subset_length(tvb, payload_offset + 3,
                    data_length);

                parse_swo_stream(stream, pinfo, NULL, 0, &parsed_count, types);
                g_snprintf(summary, summary_length, "%u packet(s) %s", parsed_count,
                    types->str);
                g_string_free(types, true);
            }
        }
        break;
    case CMD_TRANSFER_ABORT:
    default:
        g_strlcpy(summary, "Not implemented", summary_length);
        break;
    }
}

static void
dissect_command_data(tvbuff_t *tvb, proto_tree *tree, unsigned payload_offset,
    bool is_request, frame_record_t *frame, char *summary, gsize summary_length,
    packet_info *pinfo)
{
    unsigned length = tvb_captured_length(tvb);
    unsigned payload_length = length > payload_offset ? length - payload_offset : 0;

    if (tree == NULL) {
        summarize_command_data(tvb, is_request, frame, summary, summary_length, pinfo);
        return;
    }
    switch (frame->command) {
    case CMD_INFO:
        dissect_info(tvb, pinfo, tree, payload_offset, is_request, frame->info_id, summary,
            summary_length);
        break;
    case CMD_HOST_STATUS:
        if (is_request && payload_length >= 2) {
            g_snprintf(summary, summary_length, "%s",
                tvb_get_uint8(tvb, payload_offset) == 0 ? "Connect" :
                (tvb_get_uint8(tvb, payload_offset) == 1 ? "Running" : ""));
            proto_tree_add_item(tree, hf_host_status_type, tvb, payload_offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_host_status_status, tvb, payload_offset + 1, 1, ENC_NA);
        } else if (!is_request && payload_length > 0) {
            proto_tree_add_item(tree, hf_info_len, tvb, payload_offset, 1, ENC_NA);
            if (tvb_get_uint8(tvb, payload_offset) != 0) {
                proto_tree_add_expert(tree, pinfo, &ei_zero_length, tvb, payload_offset, 1);
            }
        }
        break;
    case CMD_CONNECT:
        if (payload_length > 0) {
            proto_tree_add_item(tree, hf_port, tvb, payload_offset, 1, ENC_NA);
            g_snprintf(summary, summary_length, "%s",
                val_to_str_const(tvb_get_uint8(tvb, payload_offset), port_names, ""));
        }
        break;
    case CMD_TRANSFER:
        dissect_transfer(tvb, pinfo, tree, payload_offset, is_request, summary, summary_length);
        break;
    case CMD_TRANSFER_CONFIGURE:
        if (is_request && payload_length >= 5) {
            proto_tree_add_item(tree, hf_transfer_config_idle, tvb, payload_offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_transfer_config_wait, tvb, payload_offset + 1, 2,
                ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_transfer_config_match, tvb, payload_offset + 3, 2,
                ENC_LITTLE_ENDIAN);
        } else if (!is_request) {
            add_response_status(tvb, tree, payload_offset, payload_length, summary,
                summary_length);
        }
        break;
    case CMD_TRANSFER_BLOCK:
        if (is_request && payload_length >= 4) {
            uint16_t count = tvb_get_letohs(tvb, payload_offset + 1);
            bool is_read = (tvb_get_uint8(tvb, payload_offset + 3) & 2) != 0;
            unsigned offset = payload_offset + 4;
            unsigned i;
            proto_item *request_item;
            proto_tree *request_tree;
            proto_tree_add_item(tree, hf_dap_index, tvb, payload_offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_transfer_block_count, tvb, payload_offset + 1, 2,
                ENC_LITTLE_ENDIAN);
            request_item = proto_tree_add_item(tree, hf_transfer_request, tvb,
                payload_offset + 3, 1, ENC_NA);
            request_tree = request_item != NULL ?
                proto_item_add_subtree(request_item, ett_transfer) : NULL;
            if (request_tree != NULL) {
                proto_tree_add_item(request_tree, hf_transfer_apndp, tvb,
                    payload_offset + 3, 1, ENC_NA);
                proto_tree_add_item(request_tree, hf_transfer_rnw, tvb,
                    payload_offset + 3, 1, ENC_NA);
                proto_tree_add_item(request_tree, hf_transfer_a23, tvb,
                    payload_offset + 3, 1, ENC_NA);
            }
            if (!is_read) {
                for (i = 0; i < count && length - offset >= 4; i++, offset += 4) {
                    proto_tree_add_item(tree, hf_transfer_write_data, tvb, offset, 4,
                        ENC_LITTLE_ENDIAN);
                }
            }
            g_snprintf(summary, summary_length, "%u word(s) %s", count,
                is_read ? "Read" : "Write");
        } else if (!is_request && payload_length >= 3) {
            uint16_t count = tvb_get_letohs(tvb, payload_offset);
            uint8_t ack = tvb_get_uint8(tvb, payload_offset + 2);
            bool is_read = payload_length > 3;
            unsigned offset = payload_offset + 3;
            unsigned i;
            proto_item *response_item;
            proto_tree *response_tree;
            proto_tree_add_item(tree, hf_transfer_block_count, tvb, payload_offset, 2,
                ENC_LITTLE_ENDIAN);
            response_item = proto_tree_add_item(tree, hf_transfer_response, tvb,
                payload_offset + 2, 1, ENC_NA);
            response_tree = response_item != NULL ?
                proto_item_add_subtree(response_item, ett_transfer) : NULL;
            if (response_tree != NULL) {
                proto_tree_add_item(response_tree, hf_transfer_ack, tvb,
                    payload_offset + 2, 1, ENC_NA);
                proto_tree_add_item(response_tree, hf_transfer_protocol_error, tvb,
                    payload_offset + 2, 1, ENC_NA);
            }
            if (is_read) {
                for (i = 0; i < count && length - offset >= 4; i++, offset += 4) {
                    proto_tree_add_item(tree, hf_transfer_read_data, tvb, offset, 4,
                        ENC_LITTLE_ENDIAN);
                }
            }
            g_snprintf(summary, summary_length, "%s %u word(s) %s",
                val_to_str_const(ack & 0x07, ack_names, "Unknown"), count,
                is_read ? "Read" : "Write");
        }
        break;
    case CMD_WRITE_ABORT:
        if (is_request && payload_length >= 5) {
            proto_tree_add_item(tree, hf_dap_index, tvb, payload_offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_write_abort, tvb, payload_offset + 1, 4,
                ENC_LITTLE_ENDIAN);
        } else if (!is_request) {
            add_response_status(tvb, tree, payload_offset, payload_length, summary,
                summary_length);
        }
        break;
    case CMD_DELAY:
        if (is_request && payload_length >= 2) {
            proto_tree_add_item(tree, hf_delay, tvb, payload_offset, 2,
                ENC_LITTLE_ENDIAN);
        } else if (!is_request) {
            add_response_status(tvb, tree, payload_offset, payload_length, summary,
                summary_length);
        }
        break;
    case CMD_SWJ_CLOCK:
        if (payload_length >= 4 && is_request) {
            uint32_t value = tvb_get_letohl(tvb, payload_offset);
            proto_tree_add_item(tree, hf_swj_clock, tvb, payload_offset, 4,
                ENC_LITTLE_ENDIAN);
            g_snprintf(summary, summary_length, "%uHz", value);
        } else if (!is_request) {
            add_response_status(tvb, tree, payload_offset, payload_length, summary,
                summary_length);
        }
        break;
    case CMD_SWO_TRANSPORT:
        if (payload_length > 0 && is_request) {
            proto_tree_add_item(tree, hf_swo_transport, tvb, payload_offset, 1, ENC_NA);
        } else if (!is_request) {
            add_response_status(tvb, tree, payload_offset, payload_length, summary,
                summary_length);
        }
        break;
    case CMD_SWO_MODE:
        if (payload_length > 0 && is_request) {
            proto_tree_add_item(tree, hf_swo_mode, tvb, payload_offset, 1, ENC_NA);
            g_snprintf(summary, summary_length, "%s",
                val_to_str_const(tvb_get_uint8(tvb, payload_offset), mode_names, ""));
        } else if (!is_request) {
            add_response_status(tvb, tree, payload_offset, payload_length, summary,
                summary_length);
        }
        break;
    case CMD_SWO_BAUDRATE:
        if (payload_length >= 4) {
            uint32_t value = tvb_get_letohl(tvb, payload_offset);
            proto_tree_add_item(tree, hf_swo_baudrate, tvb, payload_offset, 4,
                ENC_LITTLE_ENDIAN);
            g_snprintf(summary, summary_length, "%ubps", value);
        }
        break;
    case CMD_SWO_CONTROL:
        if (payload_length > 0 && is_request) {
            proto_tree_add_item(tree, hf_swo_control, tvb, payload_offset, 1, ENC_NA);
        } else if (!is_request) {
            add_response_status(tvb, tree, payload_offset, payload_length, summary,
                summary_length);
        }
        break;
    case CMD_SWO_EXTENDED_STATUS:
        if (is_request && payload_length > 0) {
            proto_tree_add_item(tree, hf_swo_extended_status, tvb, payload_offset, 1, ENC_NA);
        }
        break;
    case CMD_SWO_STATUS:
        if (!is_request && payload_length >= 3) {
            uint32_t count = tvb_get_letohs(tvb, payload_offset + 1);
            proto_tree_add_item(tree, hf_swo_status, tvb, payload_offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_swo_active, tvb, payload_offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_swo_error, tvb, payload_offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_swo_overrun, tvb, payload_offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_swo_count, tvb, payload_offset + 1, 2,
                ENC_LITTLE_ENDIAN);
            g_snprintf(summary, summary_length, "%u byte(s)", count);
        }
        break;
    case CMD_SWJ_PINS:
        if (is_request && payload_length >= 6) {
            proto_item *item = proto_tree_add_item(tree, hf_swj_output, tvb, payload_offset,
                1, ENC_NA);
            proto_tree *pins = item != NULL ? proto_item_add_subtree(item, ett_cmsis_dap) : NULL;
            if (pins != NULL) {
                add_swj_pin_bits(pins, tvb, payload_offset);
            }
            item = proto_tree_add_item(tree, hf_swj_select, tvb, payload_offset + 1, 1,
                ENC_NA);
            pins = item != NULL ? proto_item_add_subtree(item, ett_cmsis_dap) : NULL;
            if (pins != NULL) {
                add_swj_pin_bits(pins, tvb, payload_offset + 1);
            }
            proto_tree_add_item(tree, hf_swj_wait, tvb, payload_offset + 2, 4,
                ENC_LITTLE_ENDIAN);
        } else if (!is_request && payload_length > 0) {
            proto_item *item = proto_tree_add_item(tree, hf_swj_input, tvb, payload_offset, 1,
                ENC_NA);
            proto_tree *pins = item != NULL ? proto_item_add_subtree(item, ett_cmsis_dap) : NULL;
            if (pins != NULL) {
                add_swj_pin_bits(pins, tvb, payload_offset);
            }
        }
        break;
    case CMD_SWJ_SEQUENCE:
    case CMD_SWD_SEQUENCE:
        if (is_request && payload_length > 0) {
            proto_tree_add_item(tree, hf_swj_sequence_count, tvb, payload_offset, 1, ENC_NA);
            if (payload_length > 1) {
                proto_tree_add_item(tree, hf_swj_sequence_data, tvb, payload_offset + 1,
                    payload_length - 1, ENC_NA);
            }
        } else if (!is_request) {
            add_response_status(tvb, tree, payload_offset, payload_length, summary,
                summary_length);
        }
        break;
    case CMD_SWD_CONFIGURE:
        if (is_request && payload_length > 0) {
            proto_item *item = proto_tree_add_item(tree, hf_swd_config, tvb, payload_offset, 1,
                ENC_NA);
            proto_tree *config = item != NULL ?
                proto_item_add_subtree(item, ett_cmsis_dap) : NULL;
            if (config != NULL) {
                proto_tree_add_item(config, hf_swd_turnaround, tvb, payload_offset, 1, ENC_NA);
                proto_tree_add_item(config, hf_swd_data_phase, tvb, payload_offset, 1, ENC_NA);
            }
        } else if (!is_request) {
            add_response_status(tvb, tree, payload_offset, payload_length, summary,
                summary_length);
        }
        break;
    case CMD_SWO_DATA:
        if (is_request && payload_length >= 2) {
            proto_tree_add_item(tree, hf_swo_count, tvb, payload_offset, 2, ENC_LITTLE_ENDIAN);
        } else if (!is_request && payload_length >= 3) {
            unsigned count = tvb_get_letohs(tvb, payload_offset + 1);
            unsigned parsed_count;
            GString *types = g_string_new("");
            tvbuff_t *stream;
            unsigned data_length = payload_length - 3;
            proto_tree_add_item(tree, hf_swo_status, tvb, payload_offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_swo_active, tvb, payload_offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_swo_error, tvb, payload_offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_swo_overrun, tvb, payload_offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_swo_count, tvb, payload_offset + 1, 2,
                ENC_LITTLE_ENDIAN);
            if (count > 0) {
                proto_tree_add_item(tree, hf_swo_data, tvb, payload_offset + 3, data_length,
                    ENC_NA);
                stream = tvb_new_subset_length(tvb, payload_offset + 3, data_length);
                parse_swo_stream(stream, pinfo, tree, 0, &parsed_count, types);
                g_snprintf(summary, summary_length, "%u packet(s) %s", parsed_count, types->str);
            }
            g_string_free(types, true);
        }
        break;
    case CMD_DISCONNECT:
        if (!is_request) {
            add_response_status(tvb, tree, payload_offset, payload_length, summary,
                summary_length);
        }
        break;
    case CMD_RESET_TARGET:
        if (!is_request) {
            add_response_status(tvb, tree, payload_offset, payload_length, summary,
                summary_length);
            if (payload_length >= 2) {
                proto_tree_add_item(tree, hf_execute, tvb, payload_offset + 1, 1, ENC_NA);
            }
        }
        break;
    case CMD_TRANSFER_ABORT:
        g_strlcpy(summary, "Not implemented", summary_length);
        break;
    default:
        g_strlcpy(summary, "Not implemented", summary_length);
        break;
    }
}

static unsigned
minimum_command_length(uint8_t command, bool is_request)
{
    if (is_request) {
        switch (command) {
        case CMD_INFO:
        case CMD_CONNECT:
        case CMD_TRANSFER_CONFIGURE:
        case CMD_TRANSFER:
        case CMD_TRANSFER_BLOCK:
        case CMD_WRITE_ABORT:
        case CMD_DELAY:
        case CMD_SWJ_PINS:
        case CMD_SWJ_CLOCK:
        case CMD_SWJ_SEQUENCE:
        case CMD_SWD_CONFIGURE:
        case CMD_SWO_TRANSPORT:
        case CMD_SWO_MODE:
        case CMD_SWO_BAUDRATE:
        case CMD_SWO_CONTROL:
        case CMD_SWO_DATA:
        case CMD_SWD_SEQUENCE:
            return command == CMD_TRANSFER ? 3 :
                (command == CMD_TRANSFER_BLOCK ? 5 :
                (command == CMD_TRANSFER_CONFIGURE ? 6 :
                (command == CMD_WRITE_ABORT ? 6 :
                (command == CMD_DELAY ? 3 :
                (command == CMD_SWJ_PINS ? 6 :
                (command == CMD_SWJ_CLOCK ? 5 :
                (command == CMD_SWJ_SEQUENCE ? 2 :
                (command == CMD_SWD_CONFIGURE ? 2 :
                (command == CMD_SWO_BAUDRATE ? 5 :
                (command == CMD_SWO_DATA ? 3 : 2))))))))));
        case CMD_HOST_STATUS:
            return 3;
        case CMD_DISCONNECT:
        case CMD_TRANSFER_ABORT:
        case CMD_RESET_TARGET:
        case CMD_SWO_STATUS:
            return 1;
        default:
            return 0;
        }
    }

    switch (command) {
    case CMD_INFO:
    case CMD_HOST_STATUS:
    case CMD_CONNECT:
    case CMD_DISCONNECT:
    case CMD_TRANSFER_CONFIGURE:
    case CMD_TRANSFER_ABORT:
    case CMD_WRITE_ABORT:
    case CMD_DELAY:
    case CMD_SWJ_CLOCK:
    case CMD_SWJ_SEQUENCE:
    case CMD_SWD_CONFIGURE:
    case CMD_SWO_TRANSPORT:
    case CMD_SWO_MODE:
    case CMD_SWO_CONTROL:
        return 2;
    case CMD_TRANSFER:
        return 3;
    case CMD_TRANSFER_BLOCK:
        return 4;
    case CMD_RESET_TARGET:
        return 3;
    case CMD_SWO_BAUDRATE:
        return 5;
    case CMD_SWO_STATUS:
        return 6;
    case CMD_SWO_DATA:
        return 4;
    case CMD_SWD_SEQUENCE:
        return 2;
    case CMD_SWJ_PINS:
        return 3;
    default:
        return 0;
    }
}

static bool
is_cmsis_dap_command(tvbuff_t *tvb, bool is_request)
{
    unsigned length = tvb_captured_length(tvb);

    if (length == 0) {
        return false;
    }
    uint8_t command = tvb_get_uint8(tvb, 0);
    unsigned minimum = minimum_command_length(command, is_request);
    return minimum > 0 && length >= minimum;
}

static bool
urb_is_request(const urb_info_t *urb)
{
    if (urb->direction == P2P_DIR_SENT) {
        return true;
    }
    if (urb->direction == P2P_DIR_RECV) {
        return false;
    }
    return (urb->endpoint & 0x80) == 0;
}

static int
interface_string_match(const usb_device_identity_t *identity,
    const interface_identity_t *interface)
{
    bool has_mismatching_string = false;

    if (identity->have_product_string_index && identity->product_string_index != 0) {
        if (identity->product_string_seen && identity->product_string_matches) {
            return 1;
        }
        has_mismatching_string |= identity->product_string_seen;
    }
    if (interface != NULL && interface->descriptor_seen && interface->string_index != 0) {
        if (interface->string_seen && interface->string_matches) {
            return 1;
        }
        has_mismatching_string |= interface->string_seen;
    }
    if (has_mismatching_string) {
        return -1;
    }
    return 0;
}

static bool
dissect_cmsis_dap_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void *data)
{
    urb_info_t *urb = (urb_info_t *)data;

    if (urb == NULL || urb->conv == NULL) {
        return false;
    }
    const bool first_pass = !PINFO_FD_VISITED(pinfo);
    usb_conv_info_t *usb_info = urb->conv;
    if (tvb_captured_length(tvb) == 0) {
        return false;
    }
    if (usb_info->interfaceClass != USB_UNKNOWN_INTERFACE_VALUE &&
        (usb_info->interfaceClass != CMSIS_DAP_USB_CLASS ||
         (usb_info->interfaceSubclass != USB_UNKNOWN_INTERFACE_VALUE &&
          usb_info->interfaceSubclass != CMSIS_DAP_USB_SUBCLASS) ||
         (usb_info->interfaceProtocol != USB_UNKNOWN_INTERFACE_VALUE &&
          usb_info->interfaceProtocol != CMSIS_DAP_USB_PROTOCOL))) {
        return false;
    }
    uint8_t interface_num = usb_info->interfaceNum;
    device_state_t *state = first_pass ?
        get_device_state(urb->bus_id, urb->device_address, interface_num) :
        lookup_device_state(urb->bus_id, urb->device_address, interface_num);
    if (state == NULL) {
        return false;
    }
    interface_identity_t *interface = (interface_identity_t *)
        wmem_map_lookup(state->identity->interfaces,
        GUINT_TO_POINTER((unsigned)interface_num + 1));
    bool has_interface_descriptor = interface != NULL && interface->descriptor_seen;
    if (has_interface_descriptor &&
        (interface->interface_class != CMSIS_DAP_USB_CLASS ||
         interface->interface_subclass != CMSIS_DAP_USB_SUBCLASS ||
         interface->interface_protocol != CMSIS_DAP_USB_PROTOCOL)) {
        return false;
    }
    if (has_interface_descriptor &&
        (!interface->have_bulk_out || !interface->have_bulk_in)) {
        return false;
    }

    int string_match = interface_string_match(state->identity, interface);
    if (string_match < 0) {
        return false;
    }
    bool has_matching_string = string_match > 0;
    if (has_matching_string && first_pass) {
        state->is_cmsis_dap = true;
        state->matched_by = "string";
    }

    uint32_t endpoint = urb->endpoint;
    bool is_request = urb_is_request(urb);

    if (state->is_cmsis_dap) {
        if (is_request) {
            if (state->have_out_endpoint && endpoint != state->out_endpoint) {
                return false;
            }
            if (!is_cmsis_dap_command(tvb, true)) {
                return false;
            }
        } else if (state->have_in_endpoint && endpoint != state->in_endpoint &&
            endpoint != state->out_endpoint) {
            if (first_pass) {
                state->have_trace_endpoint = true;
                state->trace_endpoint = (uint8_t)endpoint;
            }
        } else if (!is_cmsis_dap_command(tvb, false)) {
            return false;
        }
    } else {
        if (!is_request || !is_cmsis_dap_command(tvb, true)) {
            return false;
        }
        if (!first_pass) {
            return false;
        }
        state->is_cmsis_dap = true;
        state->matched_by = has_matching_string ? "string" : "heuristic";
    }
    return dissect_cmsis_dap(tvb, pinfo, tree, urb) > 0;
}

static int
dissect_cmsis_dap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    /*
     * First pass: build frame, endpoint, and request/response state.
     * Every pass: populate columns; populate protocol trees only when requested.
     */
    urb_info_t *urb = (urb_info_t *)data;
    unsigned length = tvb_captured_length(tvb);

    if (urb == NULL || urb->conv == NULL || length == 0) {
        return 0;
    }
    const bool first_pass = !PINFO_FD_VISITED(pinfo);
    uint32_t device_address = urb->device_address;
    uint16_t bus_id = urb->bus_id;
    uint32_t endpoint = urb->endpoint;
    bool is_request = urb_is_request(urb);
    device_state_t *state = first_pass ?
        get_device_state(bus_id, device_address, urb->conv->interfaceNum) :
        lookup_device_state(bus_id, device_address, urb->conv->interfaceNum);
    if (state == NULL) {
        return 0;
    }
    frame_record_t *frame = (frame_record_t *)
        wmem_map_lookup(state->frames, GUINT_TO_POINTER(pinfo->num));

    if (frame == NULL) {
        if (!first_pass) {
            return 0;
    }
        frame = wmem_new0(wmem_file_scope(), frame_record_t);
        uint8_t command = frame->command = tvb_get_uint8(tvb, 0);
        if (is_request) {
            if (!state->have_out_endpoint) {
                state->have_out_endpoint = true;
                state->out_endpoint = (uint8_t)endpoint;
            } else if (state->out_endpoint != endpoint) {
                return 0;
            }
            frame->is_request = true;
            frame->sequence = ++state->request_count;
            frame->request_frame = pinfo->num;
            if (command == CMD_INFO && length >= 2) {
                frame->info_id = tvb_get_uint8(tvb, 1);
            }
            request_record_t *request = wmem_new0(wmem_file_scope(), request_record_t);
            request->request_frame = pinfo->num;
            request->command = command;
            request->info_id = frame->info_id;
            wmem_map_insert(state->requests, GUINT_TO_POINTER(frame->sequence), request);
        } else {
            if (!state->have_in_endpoint) {
                state->have_in_endpoint = true;
                state->in_endpoint = (uint8_t)endpoint;
            } else if (state->in_endpoint != endpoint) {
                if (!state->have_trace_endpoint) {
                    state->have_trace_endpoint = true;
                    state->trace_endpoint = (uint8_t)endpoint;
                }
                if (state->trace_endpoint == endpoint) {
                    frame->is_trace = true;
                } else {
                    return 0;
                }
            }
            if (!frame->is_trace) {
                uint32_t candidate = state->response_cursor[command] != 0 ?
                    state->response_cursor[command] : 1;
                while (candidate <= state->request_count) {
                    request_record_t *request = (request_record_t *)
                        wmem_map_lookup(state->requests,
                        GUINT_TO_POINTER(candidate));
                    if (request != NULL && request->response_frame == 0 &&
                        request->command == command) {
                        break;
                    }
                    candidate++;
                }
                frame->command = command;
                request_record_t *request;
                if (candidate <= state->request_count &&
                    (request = (request_record_t *)wmem_map_lookup(state->requests,
                        GUINT_TO_POINTER(candidate))) != NULL) {
                    state->response_cursor[command] = candidate + 1;
                    frame->sequence = candidate;
                    frame->request_frame = request->request_frame;
                    frame->info_id = request->info_id;
                    request->response_frame = pinfo->num;
                    frame_record_t *request_frame =
                        (frame_record_t *)wmem_map_lookup(state->frames,
                            GUINT_TO_POINTER(request->request_frame));
                    if (request_frame != NULL) {
                        request_frame->response_frame = pinfo->num;
                    }
                } else {
                    state->response_cursor[command] = state->request_count + 1;
                }
            }
        }
        wmem_map_insert(state->frames, GUINT_TO_POINTER(pinfo->num), frame);
    }

    if (frame->is_trace) {
        dissect_trace(tvb, pinfo, tree, state, frame);
        return length;
    }
    uint8_t command = frame->command;
    const char *command_name = val_to_str_const(command, command_names, "Unknown");
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USBDAP");
    char operation[160] = "";
    char info[256];
    g_snprintf(info, sizeof(info), "%s %s ", command_name,
        frame->is_request ? "Request" : "Response");
    if (tree != NULL) {
        proto_item *root_item = proto_tree_add_item(tree, proto_cmsis_dap, tvb, 0, length,
            ENC_NA);
        proto_item_set_text(root_item, "CMSIS-DAP");
        proto_tree *dap_tree = root_item != NULL ?
            proto_item_add_subtree(root_item, ett_cmsis_dap) : NULL;
        if (dap_tree != NULL) {
            if (frame->is_request && frame->response_frame != 0) {
                add_generated_frame(dap_tree, hf_response, tvb, frame->response_frame);
            } else if (!frame->is_request && frame->request_frame != 0) {
                add_generated_frame(dap_tree, hf_request, tvb, frame->request_frame);
            } else if (!frame->is_request) {
                proto_tree_add_expert(dap_tree, pinfo, &ei_packet_lost, tvb, 0, length);
            }
            proto_tree_add_item(dap_tree, hf_command, tvb, 0, 1, ENC_NA);
        }
        dissect_command_data(tvb, dap_tree, 1, frame->is_request, frame, operation,
            sizeof(operation), pinfo);
    } else {
        dissect_command_data(tvb, NULL, 1, frame->is_request, frame, operation,
            sizeof(operation), pinfo);
    }
    if (operation[0] != '\0') {
        g_strlcat(info, operation, sizeof(info));
    }
    col_set_str(pinfo->cinfo, COL_INFO, info);
    return length;
}

void
proto_register_cmsis_dap(void)
{
    static int *ett[] = {
        &ett_cmsis_dap,
        &ett_transfer,
        &ett_swo_packet,
        &ett_info_capabilities
    };
    static ei_register_info ei[] = {
        { &ei_malformed, { "cmsis_dap.malformed", PI_MALFORMED, PI_ERROR,
            "Malformed CMSIS-DAP packet", EXPFILL } },
        { &ei_zero_length, { "cmsis_dap.zero_length", PI_MALFORMED, PI_WARN,
            "Zero length", EXPFILL } },
        { &ei_packet_lost, { "cmsis_dap.packet_lost", PI_PROTOCOL, PI_WARN,
            "Relative packet lost", EXPFILL } }
    };
    proto_cmsis_dap = proto_register_protocol("USB CMSIS-DAP protocol", "USBDAP",
        "cmsis_dap");
    proto_cmsis_dap_usb_identity = proto_register_protocol("USB identity tracking",
        "DAP-ID", "usb_identity_tracking");
    proto_register_field_array(proto_cmsis_dap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module_t *expert_module = expert_register_protocol(proto_cmsis_dap);
    expert_register_field_array(expert_module, ei, array_length(ei));
    device_states = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(),
        g_direct_hash, g_direct_equal);
    usb_device_identities = wmem_map_new_autoreset(wmem_epan_scope(),
        wmem_file_scope(), g_direct_hash, g_direct_equal);
}

void
proto_reg_handoff_cmsis_dap(void)
{
    GArray *wanted_hfids;
    int usb_hfids[12];
    unsigned i;

    hf_usb_descriptor_index = proto_registrar_get_id_byname("usb.DescriptorIndex");
    hf_usb_descriptor_type = proto_registrar_get_id_byname("usb.bDescriptorType");
    hf_usb_request_in = proto_registrar_get_id_byname("usb.request_in");
    hf_usb_string = proto_registrar_get_id_byname("usb.bString");
    hf_usb_product_string = proto_registrar_get_id_byname("usb.iProduct");
    hf_usb_interface_number = proto_registrar_get_id_byname("usb.bInterfaceNumber");
    hf_usb_interface_class = proto_registrar_get_id_byname("usb.bInterfaceClass");
    hf_usb_interface_subclass = proto_registrar_get_id_byname("usb.bInterfaceSubClass");
    hf_usb_interface_protocol = proto_registrar_get_id_byname("usb.bInterfaceProtocol");
    hf_usb_interface_string = proto_registrar_get_id_byname("usb.iInterface");
    hf_usb_endpoint_address = proto_registrar_get_id_byname("usb.bEndpointAddress");
    hf_usb_endpoint_transfer = proto_registrar_get_id_byname("usb.bmAttributes.transfer");
    usb_hfids[0] = hf_usb_descriptor_index;
    usb_hfids[1] = hf_usb_descriptor_type;
    usb_hfids[2] = hf_usb_request_in;
    usb_hfids[3] = hf_usb_string;
    usb_hfids[4] = hf_usb_product_string;
    usb_hfids[5] = hf_usb_interface_number;
    usb_hfids[6] = hf_usb_interface_class;
    usb_hfids[7] = hf_usb_interface_subclass;
    usb_hfids[8] = hf_usb_interface_protocol;
    usb_hfids[9] = hf_usb_interface_string;
    usb_hfids[10] = hf_usb_endpoint_address;
    usb_hfids[11] = hf_usb_endpoint_transfer;

    heur_dissector_add("usb.bulk", dissect_cmsis_dap_heur, "CMSIS-DAP v2 USB bulk",
        "cmsis_dap_usb_bulk", proto_cmsis_dap, HEURISTIC_ENABLE);
    usb_identity_handle = create_dissector_handle(dissect_usb_identity,
        proto_cmsis_dap_usb_identity);
    wanted_hfids = g_array_new(false, false, sizeof(int));
    for (i = 0; i < G_N_ELEMENTS(usb_hfids); i++) {
        if (usb_hfids[i] >= 0) {
            g_array_append_val(wanted_hfids, usb_hfids[i]);
        } else {
            g_warning("USB field needed for CMSIS-DAP identification was not registered");
        }
    }
    register_postdissector(usb_identity_handle);
    set_postdissector_wanted_hfids(usb_identity_handle, wanted_hfids);
}
