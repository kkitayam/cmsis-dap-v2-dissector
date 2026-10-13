#include <epan/column-utils.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-usb.h>
#include <epan/expert.h>
#include <epan/ftypes/ftypes.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/proto_data.h>
#include <epan/wmem_scopes.h>
#include <wsutil/wmem/wmem.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define CMSIS_DAP_USB_CLASS 0xff
#define CMSIS_DAP_USB_SUBCLASS 0x00
#define CMSIS_DAP_USB_PROTOCOL 0x00
#define USB_UNKNOWN_INTERFACE_VALUE 0xffff
#define USB_DESCRIPTOR_DEVICE 0x01
#define USB_DESCRIPTOR_CONFIGURATION 0x02
#define USB_DESCRIPTOR_STRING 0x03
#define USB_DESCRIPTOR_INTERFACE 0x04
#define USB_DESCRIPTOR_ENDPOINT 0x05
#define USB_TRANSFER_TYPE_BULK 0x02

/* X(enum name, command id, display name, min request length, min response length) */
#define COMMAND_LIST(X) \
    X(CMD_INFO, 0, "Info", 2, 2) \
    X(CMD_HOST_STATUS, 1, "HostStatus", 3, 2) \
    X(CMD_CONNECT, 2, "Connect", 2, 2) \
    X(CMD_DISCONNECT, 3, "Disconnect", 1, 2) \
    X(CMD_TRANSFER_CONFIGURE, 4, "TransferConfigure", 6, 2) \
    X(CMD_TRANSFER, 5, "Transfer", 3, 3) \
    X(CMD_TRANSFER_BLOCK, 6, "TransferBlock", 5, 4) \
    X(CMD_TRANSFER_ABORT, 7, "TransferAbort", 1, 2) \
    X(CMD_WRITE_ABORT, 8, "WriteABORT", 6, 2) \
    X(CMD_DELAY, 9, "Delay", 3, 2) \
    X(CMD_RESET_TARGET, 10, "ResetTarget", 1, 3) \
    X(CMD_SWJ_PINS, 16, "SWJ_Pins", 7, 2) \
    X(CMD_SWJ_CLOCK, 17, "SWJ_Clock", 5, 2) \
    X(CMD_SWJ_SEQUENCE, 18, "SWJ_Sequence", 2, 2) \
    X(CMD_SWD_CONFIGURE, 19, "SWD_Configure", 2, 2) \
    X(CMD_JTAG_SEQUENCE, 20, "JTAG_Sequence", 3, 2) \
    X(CMD_JTAG_CONFIGURE, 21, "JTAG_Configure", 2, 2) \
    X(CMD_JTAG_IDCODE, 22, "JTAG_IDCODE", 2, 6) \
    X(CMD_SWO_TRANSPORT, 23, "SWO_Transport", 2, 2) \
    X(CMD_SWO_MODE, 24, "SWO_Mode", 2, 2) \
    X(CMD_SWO_BAUDRATE, 25, "SWO_Baudrate", 5, 5) \
    X(CMD_SWO_CONTROL, 26, "SWO_Control", 2, 2) \
    X(CMD_SWO_STATUS, 27, "SWO_Status", 1, 6) \
    X(CMD_SWO_DATA, 28, "SWO_Data", 3, 4) \
    X(CMD_SWD_SEQUENCE, 29, "SWD_Sequence", 2, 2) \
    X(CMD_SWO_EXTENDED_STATUS, 30, "SWO_ExtendedStatus", 2, 2) \
    X(CMD_UART_TRANSPORT, 31, "UART_Transport", 2, 2) \
    X(CMD_UART_CONFIGURE, 32, "UART_Configure", 6, 6) \
    X(CMD_UART_TRANSFER, 33, "UART_Transfer", 5, 6) \
    X(CMD_UART_CONTROL, 34, "UART_Control", 2, 2) \
    X(CMD_UART_STATUS, 35, "UART_Status", 1, 10) \
    X(CMD_QUEUE_COMMANDS, 126, "QueueCommands", 2, 2) \
    X(CMD_EXECUTE_COMMANDS, 127, "ExecuteCommands", 2, 2)

#define X(name, id, str, req, resp) name = id,
enum { COMMAND_LIST(X) };
#undef X

static const value_string command_names[] = {
#define X(name, id, str, req, resp) { id, str },
    COMMAND_LIST(X)
#undef X
    { 0, NULL }
};

/* Zero means the command is unknown. */
static const uint8_t command_lengths[128][2] = {
#define X(name, id, str, req, resp) [id] = { req, resp },
    COMMAND_LIST(X)
#undef X
};

static const value_string implementation_names[] = {
    { 0, "Not implemented" }, { 1, "Implemented" }, { 0, NULL }
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

static int proto_cmsis_dap, proto_cmsis_dap_usb_identity;
static int hf_command, hf_request, hf_response, hf_status;
static int hf_info_id, hf_info_len;
static int hf_info_vendor, hf_info_product, hf_info_serial, hf_info_protocol_version;
static int hf_info_target_device_vendor, hf_info_target_device_name;
static int hf_info_target_board_vendor, hf_info_target_board_name;
static int hf_info_firmware_version, hf_info_capabilities;
static int hf_info_swd, hf_info_jtag, hf_info_swo_uart, hf_info_swo_manchester;
static int hf_info_atomic, hf_info_timer, hf_info_swo_streaming, hf_info_uart;
static int hf_info_usb_com;
static int hf_info_uart_rx_size, hf_info_uart_tx_size, hf_info_swo_size;
static int hf_info_packet_count, hf_info_packet_size;
static int hf_host_status_type, hf_host_status_status;
static int hf_dap_index, hf_port, hf_write_abort, hf_delay, hf_execute;
static int hf_transfer_config_idle, hf_transfer_config_wait, hf_transfer_config_match;
static int hf_swj_output, hf_swj_select, hf_swj_input;
static int hf_swj_tck, hf_swj_tms, hf_swj_tdi, hf_swj_tdo, hf_swj_ntrst, hf_swj_nreset;
static int hf_swj_wait, hf_swj_clock, hf_swj_sequence_count, hf_swj_sequence_data;
static int hf_swd_sequence_count, hf_swd_sequence_info, hf_swd_sequence_data;
static int hf_swd_config, hf_swd_turnaround, hf_swd_data_phase;
static int hf_swo_transport, hf_swo_mode, hf_swo_baudrate, hf_swo_control;
static int hf_swo_status, hf_swo_active, hf_swo_error, hf_swo_overrun;
static int hf_swo_count, hf_swo_data, hf_swo_extended_status, hf_swo_reassembled;
static int hf_transfer_count, hf_transfer, hf_transfer_request;
static int hf_transfer_apndp, hf_transfer_rnw, hf_transfer_a23;
static int hf_transfer_match, hf_transfer_mask, hf_transfer_timestamp;
static int hf_transfer_read_data, hf_transfer_read_timestamp;
static int hf_transfer_write_data, hf_transfer_mask_data, hf_transfer_match_data;
static int hf_transfer_block_count, hf_transfer_response, hf_transfer_ack;
static int hf_transfer_protocol_error, hf_transfer_value_mismatch;
static int hf_swo_sync, hf_swo_overflow_packet, hf_swo_local_timestamp;
static int hf_swo_global_timestamp, hf_swo_extension, hf_swo_itm, hf_swo_dwt;
static int hf_swo_packet_header, hf_swo_packet_size, hf_swo_packet_category;
static int hf_swo_packet_source, hf_swo_lts_timestamp_control, hf_swo_packet_payload;
static int hf_swo_packet_timestamp, hf_swo_lts_type, hf_swo_lts_timestamp;
static int hf_swo_packet_source_type, hf_swo_packet_page;
static int hf_swo_event, hf_swo_event_cpi, hf_swo_event_exc, hf_swo_event_sleep;
static int hf_swo_event_lsu, hf_swo_event_fold, hf_swo_event_cyc;
static int hf_swo_exception_number, hf_swo_exception_function;
static int hf_usb_descriptor_index, hf_usb_descriptor_type;
static int hf_usb_request_in, hf_usb_string;
static int ett_cmsis_dap, ett_transfer, ett_swo_packet, ett_info_capabilities;
static expert_field ei_malformed = EI_INIT;
static expert_field ei_zero_length = EI_INIT;
static expert_field ei_packet_lost = EI_INIT;

/* Per-field lists added at one byte offset, NULL terminated. */
static int *const info_caps_fields[] = {
    &hf_info_swd, &hf_info_jtag, &hf_info_swo_uart, &hf_info_swo_manchester,
    &hf_info_atomic, &hf_info_timer, &hf_info_swo_streaming, &hf_info_uart, NULL
};
static int *const swj_pin_fields[] = {
    &hf_swj_tck, &hf_swj_tms, &hf_swj_tdi, &hf_swj_tdo, &hf_swj_ntrst, &hf_swj_nreset, NULL
};
static int *const swd_config_fields[] = {
    &hf_swd_turnaround, &hf_swd_data_phase, NULL
};
static int *const swo_status_fields[] = {
    &hf_swo_status, &hf_swo_active, &hf_swo_error, &hf_swo_overrun, NULL
};
static int *const transfer_request_fields[] = {
    &hf_transfer_request, &hf_transfer_apndp, &hf_transfer_rnw, &hf_transfer_a23,
    &hf_transfer_match, &hf_transfer_mask, &hf_transfer_timestamp, NULL
};
static int *const block_request_fields[] = {
    &hf_transfer_apndp, &hf_transfer_rnw, &hf_transfer_a23, NULL
};
static int *const transfer_response_fields[] = {
    &hf_transfer_response, &hf_transfer_ack, &hf_transfer_protocol_error,
    &hf_transfer_value_mismatch, NULL
};
static int *const block_response_fields[] = {
    &hf_transfer_ack, &hf_transfer_protocol_error, NULL
};
static int *const swo_dwt_header_fields[] = {
    &hf_swo_packet_header, &hf_swo_packet_size, &hf_swo_packet_category,
    &hf_swo_packet_source, NULL
};
static int *const swo_event_fields[] = {
    &hf_swo_event, &hf_swo_event_cpi, &hf_swo_event_exc, &hf_swo_event_sleep,
    &hf_swo_event_lsu, &hf_swo_event_fold, &hf_swo_event_cyc, NULL
};
static int *const swo_exception_fields[] = {
    &hf_swo_exception_number, &hf_swo_exception_function, NULL
};

/* Info ID 1..9 maps to a string field. */
static int *const info_string_fields[] = {
    NULL, &hf_info_vendor, &hf_info_product, &hf_info_serial, &hf_info_protocol_version,
    &hf_info_target_device_vendor, &hf_info_target_device_name,
    &hf_info_target_board_vendor, &hf_info_target_board_name, &hf_info_firmware_version
};

static dissector_handle_t usb_identity_handle;

enum {
    PROTO_DATA_FRAME = 0,
    PROTO_DATA_TRACE = 1
};

typedef struct {
    uint8_t out;
    uint8_t in;
    uint8_t trace;
} dap_endpoints_t;

typedef struct {
    uint8_t interface_num;
    uint8_t watch_index;
    dap_endpoints_t eps;
    bool confirmed;
} interface_candidate_t;

typedef struct {
    uint8_t i_product;
    wmem_map_t *candidates;
    wmem_map_t *string_requests;
} device_track_t;

typedef struct {
    uint32_t request_frame;
    uint32_t response_frame;
    uint8_t command;
    uint8_t info_id;
    wmem_array_t *transfers;      /* request byte of each transfer */
    wmem_array_t *swd_sequences;  /* sequence info byte of each sequence */
} request_record_t;

typedef struct {
    uint32_t frame;
    uint8_t len;
    uint8_t buf[16];
} trace_fragment_t;

typedef struct {
    request_record_t *request;
} frame_record_t;

typedef struct {
    wmem_array_t *requests;       /* request_record_t * in arrival order */
    uint32_t response_cursor[256];
    interface_candidate_t *applied_candidate;
    bool is_cmsis_dap;
    dap_endpoints_t eps;
    trace_fragment_t tail;
} dap_conv_state_t;

/* Control descriptors are bridged to bulk conversations by bus/device. */
static wmem_map_t *device_tracks;

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
    HF_UINT8(hf_swd_sequence_count, "Sequence Count", "cmsis_dap.swd_sequence.count", BASE_DEC, NULL, 0),
    HF_UINT8(hf_swd_sequence_info, "Sequence Info", "cmsis_dap.swd_sequence.info", BASE_HEX, NULL, 0),
    HF_BYTES(hf_swd_sequence_data, "SWDIO Data", "cmsis_dap.swd_sequence.data"),
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
    HF_UINT8(hf_transfer_read_timestamp, "Read timestamp", "cmsis_dap.transfer.read.timestamp", BASE_DEC_HEX, NULL, 0),
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
    HF_BYTES(hf_swo_extension, "Extension packet", "cmsis_dap.swo_ext"),
    HF_BYTES(hf_swo_itm, "ITM packet", "cmsis_dap.swo_itm"),
    HF_BYTES(hf_swo_dwt, "DWT packet", "cmsis_dap.swo_dwt"),
    HF_UINT8(hf_swo_packet_header, "Header", "cmsis_dap.swo_pkt.header", BASE_HEX, NULL, 0),
    HF_UINT8(hf_swo_packet_size, "Packet size", "cmsis_dap.swo_pkt.size", BASE_DEC, NULL, 0x03),
    HF_UINT8(hf_swo_packet_category, "Category", "cmsis_dap.swo_pkt.itm_or_dwt", BASE_DEC, NULL, 0x04),
    HF_UINT8(hf_swo_packet_source, "Source ID / Port", "cmsis_dap.swo_pkt.source", BASE_DEC, NULL, 0xf8),
    HF_UINT32(hf_swo_packet_payload, "Payload", "cmsis_dap.swo_pkt.payload", BASE_DEC_HEX, NULL, 0),
    HF_UINT32(hf_swo_packet_timestamp, "Timestamp", "cmsis_dap.swo_pkt.timestamp", BASE_DEC, NULL, 0),
    HF_UINT8(hf_swo_lts_type, "Local timestamp format", "cmsis_dap.swo_pkt.lts.type", BASE_HEX, VALS(timestamp_format_names), 0x80),
    HF_UINT8(hf_swo_lts_timestamp_control, "Timestamp control", "cmsis_dap.swo_pkt.lts.timestamp_control", BASE_HEX, NULL, 0x30),
    HF_UINT8(hf_swo_lts_timestamp, "Timestamp", "cmsis_dap.swo_pkt.lts.ts", BASE_DEC, NULL, 0x70),
    HF_UINT8(hf_swo_packet_source_type, "Source type", "cmsis_dap.swo_pkt.source_type", BASE_DEC, NULL, 0x04),
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

/* proto_tree_add_*() and proto_item_add_subtree() accept NULL, so callers need no tree checks. */
static proto_item *
add_le(proto_tree *tree, tvbuff_t *tvb, int hfindex, unsigned off, unsigned len)
{
    return proto_tree_add_item(tree, hfindex, tvb, off, len, ENC_LITTLE_ENDIAN);
}

static void
add_fields(proto_tree *tree, tvbuff_t *tvb, unsigned off, unsigned len,
    int *const *fields)
{
    for (; *fields; fields++)
        add_le(tree, tvb, **fields, off, len);
}

static proto_tree *
add_subtree(proto_tree *tree, tvbuff_t *tvb, int hfindex, int ett, unsigned off,
    unsigned len)
{
    return proto_item_add_subtree(add_le(tree, tvb, hfindex, off, len), ett);
}

static proto_tree *
add_root(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item *item = proto_tree_add_item(tree, proto_cmsis_dap, tvb, 0,
        tvb_captured_length(tvb), ENC_NA);

    proto_item_set_text(item, "CMSIS-DAP");
    return proto_item_add_subtree(item, ett_cmsis_dap);
}

static void
add_generated_frame(tvbuff_t *tvb, proto_tree *tree, int hfindex, uint32_t frame)
{
    proto_item_set_generated(proto_tree_add_uint(tree, hfindex, tvb, 0, 0, frame));
}

static void
add_malformed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const char *message)
{
    if (tree)
        proto_tree_add_expert_format(tree, pinfo, &ei_malformed, tvb, 0,
            tvb_captured_length(tvb), "%s", message);
}

static void
add_status(tvbuff_t *tvb, proto_tree *tree, unsigned payload_length,
    wmem_strbuf_t *summary)
{
    if (payload_length == 0)
        return;
    add_le(tree, tvb, hf_status, 1, 1);
    wmem_strbuf_append(summary, val_to_str_const(tvb_get_uint8(tvb, 1), response_names,
        "Unknown"));
}

/* ---- USB identity tracking ---- */

static void *
device_track_key(uint16_t bus_id, uint32_t device_address)
{
    return GUINT_TO_POINTER(((uint32_t)bus_id << 8) | (device_address & 0xff));
}

static device_track_t *
lookup_device_track(uint16_t bus_id, uint32_t device_address)
{
    return wmem_map_lookup(device_tracks, device_track_key(bus_id, device_address));
}

static device_track_t *
get_device_track(uint16_t bus_id, uint32_t device_address)
{
    device_track_t *track = lookup_device_track(bus_id, device_address);

    if (track == NULL) {
        track = wmem_new0(wmem_file_scope(), device_track_t);
        track->candidates = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
        track->string_requests = wmem_map_new(wmem_file_scope(), g_direct_hash,
            g_direct_equal);
        wmem_map_insert(device_tracks, device_track_key(bus_id, device_address), track);
    }
    return track;
}

static dap_conv_state_t *
get_dap_conv_state(packet_info *pinfo, const urb_info_t *urb)
{
    /* USB endpoint conversations differ by direction, but DAP state spans an interface. */
    conversation_element_t elements[] = {
        { .type = CE_STRING, .str_val = "CMSIS-DAP" },
        { .type = CE_UINT, .uint_val = urb->bus_id },
        { .type = CE_UINT, .uint_val = urb->device_address },
        { .type = CE_UINT, .uint_val = urb->conv->interfaceNum },
        { .type = CE_CONVERSATION_TYPE, .conversation_type_val = CONVERSATION_USB }
    };
    conversation_t *conv = find_conversation_full(pinfo->num, elements);
    if (conv == NULL) {
        conv = conversation_new_full(pinfo->num, elements);
    }
    dap_conv_state_t *state = (dap_conv_state_t *)conversation_get_proto_data(
        conv, proto_cmsis_dap);

    if (state == NULL) {
        /* Kept across SET_CONFIGURATION; later passes need the first-pass records. */
        state = wmem_new0(wmem_file_scope(), dap_conv_state_t);
        state->requests = wmem_array_new(wmem_file_scope(), sizeof(request_record_t *));
        conversation_add_proto_data(conv, proto_cmsis_dap, state);
    }
    return state;
}

/* The descriptor postdissector has no urb_info_t to read USB addresses from. */
static uint32_t
usb_device_address(packet_info *pinfo, uint16_t *bus_id)
{
    const address *addresses[] = { &pinfo->src, &pinfo->dst };

    for (unsigned i = 0; i < G_N_ELEMENTS(addresses); i++) {
        const usb_address_t *usb = (const usb_address_t *)addresses[i]->data;

        if (addresses[i]->len == USB_ADDR_LEN && usb->device != NO_ENDPOINT) {
            *bus_id = usb->bus_id;
            return usb->device;
        }
    }
    *bus_id = 0;
    return 0;
}

static gint
compare_field_info_start(gconstpointer left, gconstpointer right)
{
    const field_info *l = *(field_info * const *)left;
    const field_info *r = *(field_info * const *)right;

    return (l->start > r->start) - (l->start < r->start);
}

/* The result lives as long as the packet's proto tree. */
static field_info *
usb_first_field(proto_tree *tree, int hfindex)
{
    GPtrArray *fields = proto_find_finfo(tree, hfindex);
    field_info *first = NULL;

    if (fields->len > 0) {
        g_ptr_array_sort(fields, compare_field_info_start);
        first = g_ptr_array_index(fields, 0);
    }
    g_ptr_array_free(fields, true);
    return first;
}

static bool
string_contains_cmsis_dap(const char *value)
{
    char *normalized = g_strdelimit(g_ascii_strdown(value, -1), "_", '-');
    bool matched = strstr(normalized, "cmsis-dap") != NULL;

    g_free(normalized);
    return matched;
}

/* Returns the descriptor start when the field holds exactly one whole descriptor, else -1. */
static int
single_descriptor_start(const field_info *type_field, uint8_t type, unsigned min_length)
{
    tvbuff_t *tvb = type_field->ds_tvb;
    int start = type_field->start - 1;
    int remaining;

    if (tvb == NULL || start < 0)
        return -1;
    remaining = tvb_captured_length_remaining(tvb, start);
    if (remaining < 2 || tvb_get_uint8(tvb, start) < min_length ||
        remaining != tvb_get_uint8(tvb, start) ||
        tvb_get_uint8(tvb, type_field->start) != type)
        return -1;
    return start;
}

static bool
update_configuration_candidates(device_track_t *track, const field_info *type_field)
{
    tvbuff_t *tvb = type_field->ds_tvb;
    interface_candidate_t *cur = NULL;
    wmem_array_t *found;
    unsigned start, total, end, offset, length, type;
    int remaining;

    if (tvb == NULL || type_field->start < 1)
        return false;
    start = type_field->start - 1;
    remaining = tvb_captured_length_remaining(tvb, start);
    if (remaining < 9 || tvb_get_uint8(tvb, type_field->start) != USB_DESCRIPTOR_CONFIGURATION)
        return false;
    total = tvb_get_uint16(tvb, start + 2, ENC_LITTLE_ENDIAN);
    length = tvb_get_uint8(tvb, start);
    if (length < 9 || length > total || (unsigned)remaining != total)
        return false;

    end = start + total;
    found = wmem_array_new(wmem_packet_scope(), sizeof(interface_candidate_t));
    for (offset = start; offset < end; offset += length) {
        if (end - offset < 2)
            return false;
        length = tvb_get_uint8(tvb, offset);
        type = tvb_get_uint8(tvb, offset + 1);
        if (length < 2 || length > end - offset)
            return false;

        if (type == USB_DESCRIPTOR_INTERFACE) {
            if (length < 9)
                return false;
            cur = NULL;
            /* Interface number is at +2, class/subclass/protocol at +5..+7, iInterface at +8. */
            if (tvb_get_uint8(tvb, offset + 5) == CMSIS_DAP_USB_CLASS &&
                tvb_get_uint8(tvb, offset + 6) == CMSIS_DAP_USB_SUBCLASS &&
                tvb_get_uint8(tvb, offset + 7) == CMSIS_DAP_USB_PROTOCOL) {
                interface_candidate_t c = {
                    .interface_num = tvb_get_uint8(tvb, offset + 2),
                    .watch_index = tvb_get_uint8(tvb, offset + 8)
                };
                wmem_array_append_one(found, c);
                cur = wmem_array_index(found, wmem_array_get_count(found) - 1);
            }
        } else if (type == USB_DESCRIPTOR_ENDPOINT && cur != NULL) {
            if (length < 7)
                return false;
            /* Endpoint address is at +2; bmAttributes is at +3. */
            uint8_t ep = tvb_get_uint8(tvb, offset + 2);

            if ((tvb_get_uint8(tvb, offset + 3) & 0x03) != USB_TRANSFER_TYPE_BULK)
                continue;
            /* The first bulk IN is the response endpoint; the second carries SWO. */
            if (!(ep & 0x80)) {
                if (!cur->eps.out)
                    cur->eps.out = ep;
            } else if (!cur->eps.in) {
                cur->eps.in = ep;
            } else if (!cur->eps.trace) {
                cur->eps.trace = ep;
            }
        }
    }

    track->candidates = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    for (unsigned i = 0; i < wmem_array_get_count(found); i++) {
        interface_candidate_t *c = wmem_array_index(found, i);

        if (!c->eps.in || !c->eps.out)
            continue;
        if (!c->watch_index)
            c->watch_index = track->i_product;
        if (c->watch_index)
            wmem_map_insert(track->candidates, GUINT_TO_POINTER(c->interface_num),
                wmem_memdup(wmem_file_scope(), c, sizeof(*c)));
    }
    return true;
}

typedef struct {
    uint8_t index;
    bool matches;
} string_match_t;

/* Confirm candidates watching this string if it matches; drop them otherwise. */
static gboolean
apply_string_match(gpointer key _U_, gpointer value, gpointer user_data)
{
    interface_candidate_t *candidate = value;
    const string_match_t *match = user_data;

    if (candidate->watch_index != match->index)
        return false;
    candidate->confirmed = match->matches;
    return !match->matches;
}

static void
process_string_response(device_track_t *track, proto_tree *tree,
    uint16_t bus_id, uint32_t device_address)
{
    field_info *request_in = usb_first_field(tree, hf_usb_request_in);
    field_info *string = usb_first_field(tree, hf_usb_string);
    void *key, *index_value;
    string_match_t match;

    if (request_in == NULL || string == NULL)
        return;
    key = GUINT_TO_POINTER(fvalue_get_uinteger(request_in->value));
    index_value = wmem_map_lookup(track->string_requests, key);
    if (index_value == NULL)
        return;
    wmem_map_remove(track->string_requests, key);

    match.index = GPOINTER_TO_UINT(index_value) - 1;
    match.matches = string_contains_cmsis_dap(fvalue_get_string(string->value));
    if (wmem_map_foreach_remove(track->candidates, apply_string_match, &match) > 0 &&
            wmem_map_size(track->candidates) == 0)
        wmem_map_remove(device_tracks, device_track_key(bus_id, device_address));
}

static int
dissect_usb_identity(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree,
    void *data _U_)
{
    uint16_t bus_id;
    uint32_t address;
    field_info *type_field, *index_field;
    device_track_t *track;
    int start;

    if (PINFO_FD_VISITED(pinfo) || tree == NULL)
        return 0;
    address = usb_device_address(pinfo, &bus_id);
    type_field = address ? usb_first_field(tree, hf_usb_descriptor_type) : NULL;
    if (type_field == NULL)
        return 0;

    track = lookup_device_track(bus_id, address);
    index_field = usb_first_field(tree, hf_usb_descriptor_index);

    switch (fvalue_get_uinteger(type_field->value)) {
    case USB_DESCRIPTOR_DEVICE:
        start = single_descriptor_start(type_field, USB_DESCRIPTOR_DEVICE, 18);
        if (start >= 0)
            /* iProduct is at byte offset 15 of a complete device descriptor. */
            get_device_track(bus_id, address)->i_product =
                tvb_get_uint8(type_field->ds_tvb, start + 15);
        break;
    case USB_DESCRIPTOR_STRING:
        if (index_field != NULL) {
            if (track == NULL)
                track = get_device_track(bus_id, address);
            wmem_map_insert(track->string_requests, GUINT_TO_POINTER(pinfo->num),
                GUINT_TO_POINTER(fvalue_get_uinteger(index_field->value) + 1));
        } else if (track != NULL &&
                single_descriptor_start(type_field, USB_DESCRIPTOR_STRING, 2) >= 0) {
            process_string_response(track, tree, bus_id, address);
        }
        break;
    case USB_DESCRIPTOR_CONFIGURATION:
        if (index_field == NULL) {
            if (track == NULL)
                track = get_device_track(bus_id, address);
            if (update_configuration_candidates(track, type_field) &&
                    wmem_map_size(track->candidates) == 0)
                wmem_map_remove(device_tracks, device_track_key(bus_id, address));
        }
        break;
    }
    return 0;
}

/* ---- SWO ---- */

/* Indexed by the packet types named in swo_packet_names. */
static int *const swo_packet_hf[] = {
    &hf_swo_sync, &hf_swo_overflow_packet, &hf_swo_local_timestamp,
    &hf_swo_global_timestamp, &hf_swo_extension, &hf_swo_dwt, &hf_swo_itm
};

/* Reads up to max continuation bytes; returns the byte count or -1 when truncated. */
static int
swo_continuation(tvbuff_t *tvb, unsigned offset, unsigned max, uint32_t *value)
{
    unsigned length = tvb_captured_length(tvb), n = 0;
    uint8_t byte;

    do {
        if (offset + n >= length)
            return -1;
        byte = tvb_get_uint8(tvb, offset + n);
        if (n < 5)
            *value |= (uint32_t)(byte & 0x7f) << (7 * n);
        n++;
    } while ((byte & 0x80) && n < max);
    return n;
}

static void
add_swo_source_packet(tvbuff_t *tvb, proto_tree *tree, unsigned start, unsigned plen)
{
    uint8_t header = tvb_get_uint8(tvb, start);

    add_fields(tree, tvb, start, 1, swo_dwt_header_fields);
    if (plen - 1 <= 4)
        add_le(tree, tvb, hf_swo_packet_payload, start + 1, plen - 1);
    if (header == 0x05)
        add_fields(tree, tvb, start + 1, 1, swo_event_fields);
    else if (header == 0x0e && plen >= 3)
        add_fields(tree, tvb, start + 1, 2, swo_exception_fields);
}

/* Returns the offset of the first byte of an incomplete trailing packet. */
static unsigned
parse_swo_stream(tvbuff_t *tvb, proto_tree *tree, wmem_strbuf_t *summary,
    unsigned *packet_count)
{
    unsigned length = tvb_captured_length(tvb), offset = 0;

    *packet_count = 0;
    while (offset < length) {
        unsigned start = offset, plen = 1, max_ext = 0;
        uint8_t header = tvb_get_uint8(tvb, offset);
        uint32_t timestamp = 0;
        int type, n;

        if (header == 0) {
            while (offset < length && tvb_get_uint8(tvb, offset) == 0)
                offset++;
            if (offset >= length)
                return start;
            plen = offset - start;
            type = -1;
            if (plen >= 5 && tvb_get_uint8(tvb, offset) == 0x80) {
                plen++;
                offset++;
                type = 0;
            }
        } else if (header & 0x03) {
            plen = 1 + ((header & 0x03) == 3 ? 4 : (header & 0x03));
            if (length - start < plen)
                return start;
            type = (header & 0x04) ? 5 : 6;
            offset += plen;
        } else if (header == 0x70) {
            type = 1;
            offset++;
        } else if ((header & 0x0c) == 0) {
            type = 2;
            offset++;
            if (header & 0x80) {
                if (!(header & 0x40))
                    return start;
                max_ext = 4;
            }
        } else if ((header & 0x0b) == 0x08) {
            type = 4;
            offset++;
            max_ext = (header & 0x80) ? 4 : 0;
        } else if ((header & 0xdc) == 0x94) {
            type = 3;
            offset++;
            max_ext = header == 0x94 ? 4 : 6;
        } else {
            return start;
        }
        if (max_ext) {
            n = swo_continuation(tvb, offset, max_ext, &timestamp);
            if (n < 0)
                return start;
            offset += n;
            plen += n;
        }
        if (type >= 0) {
            proto_tree *sub = proto_item_add_subtree(proto_tree_add_item(tree,
                *swo_packet_hf[type], tvb, start, plen, ENC_NA), ett_swo_packet);

            if (type >= 5) {
                add_swo_source_packet(tvb, sub, start, plen);
            } else {
                add_le(sub, tvb, hf_swo_packet_header, start, 1);
                if (type == 2 && !(header & 0x80)) {
                    add_le(sub, tvb, hf_swo_lts_type, start, 1);
                    add_le(sub, tvb, hf_swo_lts_timestamp, start, 1);
                } else if (type == 2) {
                    add_le(sub, tvb, hf_swo_lts_timestamp_control, start, 1);
                    proto_tree_add_uint(sub, hf_swo_packet_timestamp, tvb, start + 1,
                        plen - 1, timestamp);
                } else if (type == 4 && !(header & 0x80)) {
                    add_le(sub, tvb, hf_swo_packet_source_type, start, 1);
                    add_le(sub, tvb, hf_swo_packet_page, start, 1);
                }
            }
        }
        wmem_strbuf_append_printf(summary, "%s ", val_to_str_const(type, swo_packet_names,
            "UNK"));
        (*packet_count)++;
    }
    return offset;
}

static void
dissect_trace(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    trace_fragment_t *prefix, trace_fragment_t *tail)
{
    const bool first_pass = !PINFO_FD_VISITED(pinfo);
    unsigned current_length = tvb_captured_length(tvb), parsed, packet_count;
    proto_tree *dap_tree = add_root(tvb, pinfo, tree);
    wmem_strbuf_t *summary = wmem_strbuf_new(wmem_packet_scope(), "");
    uint8_t *merged;
    tvbuff_t *stream;

    unsigned total = current_length + prefix->len;
    merged = wmem_alloc(wmem_packet_scope(), total);
    memcpy(merged, prefix->buf, prefix->len);
    if (prefix->len > 0 && prefix->frame != 0)
        add_generated_frame(tvb, dap_tree, hf_swo_reassembled, prefix->frame);
    tvb_memcpy(tvb, merged + prefix->len, 0, current_length);

    stream = tvb_new_child_real_data(tvb, merged, total, total);
    add_new_data_source(pinfo, stream, "Reassembled SWO trace");
    parsed = parse_swo_stream(stream, dap_tree, summary, &packet_count);
    if (first_pass) {
        unsigned remain = total - parsed;
        if (remain > sizeof(tail->buf)) {
            tail->len = 0;
            tail->frame = 0;
        } else {
            tail->len = (uint8_t)remain;
            tail->frame = remain ? pinfo->num : 0;
            if (remain)
                memcpy(tail->buf, merged + parsed, remain);
        }
    }
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USBDAP");
    col_add_fstr(pinfo->cinfo, COL_INFO, "SWO_Data %u packet(s) %s", packet_count,
        wmem_strbuf_get_str(summary));
}

/* ---- Command dissection ---- */

static void
dissect_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned off,
    bool is_request, uint8_t info_id, wmem_strbuf_t *summary)
{
    unsigned length = tvb_captured_length(tvb), len, field;
    const char *name = val_to_str_const(info_id, info_names, "Info");

    if (off >= length) {
        add_malformed(tvb, pinfo, tree, "Info packet is missing its ID or length");
        return;
    }
    len = tvb_get_uint8(tvb, off);
    if (is_request) {
        add_le(tree, tvb, hf_info_id, off, 1);
        wmem_strbuf_append(summary, val_to_str_const(len, info_names, "Unknown ID"));
        return;
    }
    add_le(tree, tvb, hf_info_len, off, 1);
    if (length - off < len + 1) {
        add_malformed(tvb, pinfo, tree, "Info response is shorter than its declared length");
        return;
    }
    wmem_strbuf_append(summary, name);
    if (len == 0)
        return;

    switch (info_id) {
    case 0xfb:
    case 0xfc:
    case 0xfd:
        if (len < 4)
            break;
        field = info_id == 0xfb ? hf_info_uart_rx_size :
            (info_id == 0xfc ? hf_info_uart_tx_size : hf_info_swo_size);
        add_le(tree, tvb, field, off + 1, 4);
        wmem_strbuf_append_printf(summary, " %u bytes", tvb_get_letohl(tvb, off + 1));
        break;
    case 0xfe:
        add_le(tree, tvb, hf_info_packet_count, off + 1, 1);
        wmem_strbuf_append_printf(summary, " %u packets", tvb_get_uint8(tvb, off + 1));
        break;
    case 0xff:
        if (len < 2)
            break;
        add_le(tree, tvb, hf_info_packet_size, off + 1, 2);
        wmem_strbuf_append_printf(summary, " %u bytes", tvb_get_letohs(tvb, off + 1));
        break;
    case 0xf0: {
        proto_tree *caps;

        if (len < 2) {
            add_malformed(tvb, pinfo, tree, "Capabilities Info response must contain 2 bytes");
            break;
        }
        caps = add_subtree(tree, tvb, hf_info_capabilities, ett_info_capabilities, off + 1, 2);
        add_fields(caps, tvb, off + 1, 1, info_caps_fields);
        add_le(caps, tvb, hf_info_usb_com, off + 2, 1);
        break;
    }
    default:
        if (info_id >= 1 && info_id <= 9) {
            const char *text = tvb_get_string_enc(wmem_packet_scope(), tvb, off + 1, len,
                ENC_UTF_8);

            proto_tree_add_string(tree, *info_string_fields[info_id], tvb, off + 1, len, text);
            wmem_strbuf_append_printf(summary, " %.*s", len, text);
        }
        break;
    }
}

static void
dissect_transfer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned off,
    bool is_request, request_record_t *request, wmem_strbuf_t *summary)
{
    unsigned length = tvb_captured_length(tvb), pos, count, i;
    const bool record = request != NULL && !PINFO_FD_VISITED(pinfo);

    if (length <= off + (is_request ? 1 : 0)) {
        add_malformed(tvb, pinfo, tree, "Transfer packet is too short");
        return;
    }
    count = tvb_get_uint8(tvb, is_request ? off + 1 : off);

    if (!is_request) {
        unsigned n = request != NULL && request->transfers != NULL ?
            wmem_array_get_count(request->transfers) : 0;

        if (length - off < 2) {
            add_malformed(tvb, pinfo, tree, "Transfer response is missing its status");
            return;
        }
        add_le(tree, tvb, hf_transfer_count, off, 1);
        add_fields(tree, tvb, off + 1, 1, transfer_response_fields);
        pos = off + 2;
        for (i = 0; i < count && i < n; i++) {
            uint8_t rq = *(uint8_t *)wmem_array_index(request->transfers, i);

            if (!(rq & 0x02))
                continue;
            if ((rq & 0x80) && !(rq & 0x30)) {
                if (length - pos < 1) {
                    add_malformed(tvb, pinfo, tree, "Transfer response timestamp is missing");
                    break;
                }
                add_le(tree, tvb, hf_transfer_read_timestamp, pos++, 1);
            }
            if (length - pos < 4) {
                add_malformed(tvb, pinfo, tree, "Transfer response data is truncated");
                break;
            }
            add_le(tree, tvb, hf_transfer_read_data, pos, 4);
            pos += 4;
        }
        wmem_strbuf_append_printf(summary, "%s %u word(s)",
            val_to_str_const(tvb_get_uint8(tvb, off + 1) & 0x07, ack_names, "Unknown"), count);
        return;
    }

    unsigned parsed = 0;
    char previous = 0;
    wmem_strbuf_t *accesses = wmem_strbuf_new(wmem_packet_scope(), "");
    proto_tree *sub;

    if (record)
        request->transfers = count ? wmem_array_new(wmem_file_scope(), 1) : NULL;
    add_le(tree, tvb, hf_dap_index, off, 1);
    add_le(tree, tvb, hf_transfer_count, off + 1, 1);
    sub = proto_item_add_subtree(proto_tree_add_item(tree, hf_transfer, tvb, off + 2,
        length - off - 2, ENC_NA), ett_transfer);
    pos = off + 2;
    for (i = 0; i < count && pos < length; i++) {
        uint8_t rq = tvb_get_uint8(tvb, pos);
        bool is_write = !(rq & 0x02), has_match = rq & 0x30;
        char access = is_write ? 'W' : 'R';

        if (has_match && (rq & 0x80))
            add_malformed(tvb, pinfo, sub,
                "Transfer timestamp cannot be combined with a match operation");
        if (parsed == 0 || access != previous)
            wmem_strbuf_append_c(accesses, access);
        previous = access;
        parsed++;
        add_fields(sub, tvb, pos++, 1, transfer_request_fields);
        if (is_write || has_match) {
            if (length - pos < 4) {
                add_malformed(tvb, pinfo, sub, "Transfer request data is truncated");
                break;
            }
            add_le(sub, tvb, is_write ? ((rq & 0x20) ? hf_transfer_mask_data :
                hf_transfer_write_data) : hf_transfer_match_data, pos, 4);
            pos += 4;
        }
        if (record)
            wmem_array_append_one(request->transfers, rq);
    }
    if (parsed > 1)
        wmem_strbuf_append_printf(accesses, "%u", parsed);
    wmem_strbuf_append_printf(summary, "%u word(s) %s", count, wmem_strbuf_get_str(accesses));
}

static unsigned
swd_sequence_data_length(uint8_t info)
{
    unsigned bits = info & 0x3f;

    return ((bits ? bits : 64) + 7) / 8;
}

static void
dissect_swd_sequence(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned off,
    bool is_request, request_record_t *request, wmem_strbuf_t *summary)
{
    unsigned length = tvb_captured_length(tvb), pos = off + 1, count, i;
    const bool record = request != NULL && !PINFO_FD_VISITED(pinfo);

    if (length <= off) {
        add_malformed(tvb, pinfo, tree, is_request ?
            "SWD sequence request is missing its count" :
            "SWD sequence response is missing its status");
        return;
    }
    if (!is_request) {
        add_status(tvb, tree, length - off, summary);
        if (request == NULL || request->swd_sequences == NULL) {
            if (pos < length)
                proto_tree_add_item(tree, hf_swd_sequence_data, tvb, pos, length - pos, ENC_NA);
            return;
        }
        for (i = 0; i < wmem_array_get_count(request->swd_sequences); i++) {
            uint8_t info = *(uint8_t *)wmem_array_index(request->swd_sequences, i);
            unsigned data_length = swd_sequence_data_length(info);

            if (!(info & 0x80))
                continue;
            if (length - pos < data_length) {
                add_malformed(tvb, pinfo, tree, "SWD sequence input data is truncated");
                break;
            }
            proto_tree_add_item(tree, hf_swd_sequence_data, tvb, pos, data_length, ENC_NA);
            pos += data_length;
        }
        return;
    }

    count = tvb_get_uint8(tvb, off);
    add_le(tree, tvb, hf_swd_sequence_count, off, 1);
    if (record)
        request->swd_sequences = count ? wmem_array_new(wmem_file_scope(), 1) : NULL;
    for (i = 0; i < count; i++) {
        uint8_t info;
        unsigned data_length;

        if (pos >= length) {
            add_malformed(tvb, pinfo, tree, "SWD sequence info is truncated");
            break;
        }
        info = tvb_get_uint8(tvb, pos);
        data_length = swd_sequence_data_length(info);
        add_le(tree, tvb, hf_swd_sequence_info, pos++, 1);
        if (!(info & 0x80)) {
            if (length - pos < data_length) {
                add_malformed(tvb, pinfo, tree, "SWD sequence output data is truncated");
                break;
            }
            proto_tree_add_item(tree, hf_swd_sequence_data, tvb, pos, data_length, ENC_NA);
            pos += data_length;
        }
        if (record)
            wmem_array_append_one(request->swd_sequences, info);
    }
    wmem_strbuf_append_printf(summary, "%u sequence(s)", count);
}

static void
add_block_words(tvbuff_t *tvb, proto_tree *tree, int hfindex, unsigned pos, unsigned count)
{
    unsigned length = tvb_captured_length(tvb);

    for (unsigned i = 0; i < count && length - pos >= 4; i++, pos += 4)
        add_le(tree, tvb, hfindex, pos, 4);
}

/* The payload starts at byte 1; plen is the payload length. */
static void
dissect_block_request(tvbuff_t *tvb, proto_tree *tree, unsigned plen,
    wmem_strbuf_t *summary)
{
    unsigned count;
    bool is_read;

    if (plen < 4)
        return;
    count = tvb_get_letohs(tvb, 2);
    is_read = tvb_get_uint8(tvb, 4) & 0x02;
    add_le(tree, tvb, hf_dap_index, 1, 1);
    add_le(tree, tvb, hf_transfer_block_count, 2, 2);
    add_fields(add_subtree(tree, tvb, hf_transfer_request, ett_transfer, 4, 1), tvb, 4, 1,
        block_request_fields);
    wmem_strbuf_append_printf(summary, "%u word(s) %s", count, is_read ? "Read" : "Write");
    if (!is_read)
        add_block_words(tvb, tree, hf_transfer_write_data, 5, count);
}

static void
dissect_block_response(tvbuff_t *tvb, proto_tree *tree, unsigned plen,
    wmem_strbuf_t *summary)
{
    unsigned count;
    bool is_read;

    if (plen < 3)
        return;
    count = tvb_get_letohs(tvb, 1);
    is_read = plen > 3;
    add_le(tree, tvb, hf_transfer_block_count, 1, 2);
    add_fields(add_subtree(tree, tvb, hf_transfer_response, ett_transfer, 3, 1), tvb, 3, 1,
        block_response_fields);
    wmem_strbuf_append_printf(summary, "%s %u word(s) %s",
        val_to_str_const(tvb_get_uint8(tvb, 3) & 0x07, ack_names, "Unknown"), count,
        is_read ? "Read" : "Write");
    if (is_read)
        add_block_words(tvb, tree, hf_transfer_read_data, 4, count);
}

static void
dissect_command_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, bool is_request,
    uint8_t command, frame_record_t *frame, wmem_strbuf_t *summary)
{
    const unsigned off = 1;
    unsigned plen = tvb_captured_length(tvb) - off;
    request_record_t *request = frame->request;
    proto_tree *sub;

    if (!is_request) {
        switch (command) {
        case CMD_TRANSFER_CONFIGURE:
        case CMD_WRITE_ABORT:
        case CMD_DELAY:
        case CMD_SWJ_CLOCK:
        case CMD_SWJ_SEQUENCE:
        case CMD_SWD_CONFIGURE:
        case CMD_SWO_TRANSPORT:
        case CMD_SWO_MODE:
        case CMD_SWO_CONTROL:
        case CMD_DISCONNECT:
            add_status(tvb, tree, plen, summary);
            return;
        }
    }

    switch (command) {
    case CMD_INFO:
        dissect_info(tvb, pinfo, tree, off, is_request, request ? request->info_id : 0,
            summary);
        break;
    case CMD_HOST_STATUS:
        if (is_request && plen >= 2) {
            uint8_t type = tvb_get_uint8(tvb, off);

            wmem_strbuf_append(summary, type == 0 ? "Connect" : (type == 1 ? "Running" : ""));
            add_le(tree, tvb, hf_host_status_type, off, 1);
            add_le(tree, tvb, hf_host_status_status, off + 1, 1);
        } else if (!is_request && plen > 0) {
            add_le(tree, tvb, hf_info_len, off, 1);
            if (tree && tvb_get_uint8(tvb, off) != 0)
                proto_tree_add_expert(tree, pinfo, &ei_zero_length, tvb, off, 1);
        }
        break;
    case CMD_CONNECT:
        if (plen > 0) {
            add_le(tree, tvb, hf_port, off, 1);
            wmem_strbuf_append(summary, val_to_str_const(tvb_get_uint8(tvb, off), port_names,
                ""));
        }
        break;
    case CMD_TRANSFER:
        dissect_transfer(tvb, pinfo, tree, off, is_request, request, summary);
        break;
    case CMD_TRANSFER_CONFIGURE:
        if (plen >= 5) {
            add_le(tree, tvb, hf_transfer_config_idle, off, 1);
            add_le(tree, tvb, hf_transfer_config_wait, off + 1, 2);
            add_le(tree, tvb, hf_transfer_config_match, off + 3, 2);
        }
        break;
    case CMD_TRANSFER_BLOCK:
        if (is_request)
            dissect_block_request(tvb, tree, plen, summary);
        else
            dissect_block_response(tvb, tree, plen, summary);
        break;
    case CMD_WRITE_ABORT:
        if (plen >= 5) {
            add_le(tree, tvb, hf_dap_index, off, 1);
            add_le(tree, tvb, hf_write_abort, off + 1, 4);
        }
        break;
    case CMD_DELAY:
        if (plen >= 2)
            add_le(tree, tvb, hf_delay, off, 2);
        break;
    case CMD_SWJ_CLOCK:
        if (plen >= 4) {
            add_le(tree, tvb, hf_swj_clock, off, 4);
            wmem_strbuf_append_printf(summary, "%uHz", tvb_get_letohl(tvb, off));
        }
        break;
    case CMD_SWO_TRANSPORT:
        if (plen > 0)
            add_le(tree, tvb, hf_swo_transport, off, 1);
        break;
    case CMD_SWO_MODE:
        if (plen > 0) {
            add_le(tree, tvb, hf_swo_mode, off, 1);
            wmem_strbuf_append(summary, val_to_str_const(tvb_get_uint8(tvb, off), mode_names,
                ""));
        }
        break;
    case CMD_SWO_BAUDRATE:
        if (plen >= 4) {
            add_le(tree, tvb, hf_swo_baudrate, off, 4);
            wmem_strbuf_append_printf(summary, "%ubps", tvb_get_letohl(tvb, off));
        }
        break;
    case CMD_SWO_CONTROL:
        if (plen > 0)
            add_le(tree, tvb, hf_swo_control, off, 1);
        break;
    case CMD_SWO_EXTENDED_STATUS:
        if (is_request && plen > 0)
            add_le(tree, tvb, hf_swo_extended_status, off, 1);
        break;
    case CMD_SWO_STATUS:
        if (!is_request && plen >= 5) {
            add_fields(tree, tvb, off, 1, swo_status_fields);
            add_le(tree, tvb, hf_swo_count, off + 1, 4);
            wmem_strbuf_append_printf(summary, "%u byte(s)", tvb_get_letohl(tvb, off + 1));
        }
        break;
    case CMD_SWJ_PINS:
        if (is_request && plen >= 6) {
            add_fields(add_subtree(tree, tvb, hf_swj_output, ett_cmsis_dap, off, 1),
                tvb, off, 1, swj_pin_fields);
            add_fields(add_subtree(tree, tvb, hf_swj_select, ett_cmsis_dap, off + 1, 1),
                tvb, off + 1, 1, swj_pin_fields);
            add_le(tree, tvb, hf_swj_wait, off + 2, 4);
        } else if (!is_request && plen > 0) {
            add_fields(add_subtree(tree, tvb, hf_swj_input, ett_cmsis_dap, off, 1),
                tvb, off, 1, swj_pin_fields);
        }
        break;
    case CMD_SWJ_SEQUENCE:
        if (plen > 0) {
            add_le(tree, tvb, hf_swj_sequence_count, off, 1);
            if (plen > 1)
                proto_tree_add_item(tree, hf_swj_sequence_data, tvb, off + 1, plen - 1, ENC_NA);
        }
        break;
    case CMD_SWD_SEQUENCE:
        dissect_swd_sequence(tvb, pinfo, tree, off, is_request, request, summary);
        break;
    case CMD_SWD_CONFIGURE:
        if (plen > 0) {
            sub = add_subtree(tree, tvb, hf_swd_config, ett_cmsis_dap, off, 1);
            add_fields(sub, tvb, off, 1, swd_config_fields);
        }
        break;
    case CMD_SWO_DATA:
        if (is_request && plen >= 2) {
            add_le(tree, tvb, hf_swo_count, off, 2);
        } else if (!is_request && plen >= 3) {
            unsigned count = tvb_get_letohs(tvb, off + 1), parsed;
            wmem_strbuf_t *types = wmem_strbuf_new(wmem_packet_scope(), "");

            add_fields(tree, tvb, off, 1, swo_status_fields);
            add_le(tree, tvb, hf_swo_count, off + 1, 2);
            if (count > 0) {
                proto_tree_add_item(tree, hf_swo_data, tvb, off + 3, plen - 3, ENC_NA);
                parse_swo_stream(tvb_new_subset_length(tvb, off + 3, plen - 3), tree, types,
                    &parsed);
                wmem_strbuf_append_printf(summary, "%u packet(s) %s", parsed,
                    wmem_strbuf_get_str(types));
            }
        }
        break;
    case CMD_DISCONNECT:
        break;
    case CMD_RESET_TARGET:
        if (!is_request) {
            add_status(tvb, tree, plen, summary);
            if (plen >= 2)
                add_le(tree, tvb, hf_execute, off + 1, 1);
        }
        break;
    default:
        wmem_strbuf_append(summary, "Not implemented");
        break;
    }
}

/* ---- Frame tracking and entry points ---- */

static bool
urb_is_request(const urb_info_t *urb)
{
    if (urb->direction == P2P_DIR_SENT)
        return true;
    if (urb->direction == P2P_DIR_RECV)
        return false;
    return !(urb->endpoint & 0x80);
}

static frame_record_t *
new_frame_record(tvbuff_t *tvb, packet_info *pinfo, const urb_info_t *urb,
    dap_conv_state_t *state, uint8_t command)
{
    frame_record_t *frame = wmem_new0(wmem_file_scope(), frame_record_t);
    request_record_t *request = NULL;
    unsigned i, n;

    if (urb_is_request(urb)) {
        request = wmem_new0(wmem_file_scope(), request_record_t);
        request->request_frame = pinfo->num;
        request->command = command;
        if (command == CMD_INFO && tvb_captured_length(tvb) >= 2)
            request->info_id = tvb_get_uint8(tvb, 1);
        wmem_array_append_one(state->requests, request);
    } else {
        /* Pair with the oldest unanswered request of the same command. */
        n = wmem_array_get_count(state->requests);
        for (i = state->response_cursor[command]; i < n; i++) {
            request = *(request_record_t **)wmem_array_index(state->requests, i);
            if (request->response_frame == 0 && request->command == command)
                break;
        }
        if (i < n) {
            request->response_frame = pinfo->num;
            state->response_cursor[command] = i + 1;
        } else {
            request = NULL;
            state->response_cursor[command] = n;
        }
    }
    frame->request = request;
    return frame;
}

static int
dissect_cmsis_dap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    /*
     * First pass: build frame, endpoint, and request/response state.
     * Every pass: populate columns; populate protocol trees only when requested.
     */
    urb_info_t *urb = data;
    unsigned length = tvb_captured_length(tvb);
    dap_conv_state_t *state;
    frame_record_t *frame;
    proto_tree *dap_tree;
    wmem_strbuf_t *info;

    if (urb == NULL || urb->conv == NULL || length == 0)
        return 0;
    state = get_dap_conv_state(pinfo, urb);
    const bool is_trace = state->eps.trace && urb->endpoint == state->eps.trace;
    if (is_trace) {
        trace_fragment_t *prefix = p_get_proto_data(wmem_file_scope(), pinfo,
            proto_cmsis_dap, PROTO_DATA_TRACE);
        if (prefix == NULL) {
            if (PINFO_FD_VISITED(pinfo))
                return 0;
            prefix = wmem_new(wmem_file_scope(), trace_fragment_t);
            *prefix = state->tail;
            p_add_proto_data(wmem_file_scope(), pinfo, proto_cmsis_dap,
                PROTO_DATA_TRACE, prefix);
        }
        dissect_trace(tvb, pinfo, tree, prefix, &state->tail);
        return length;
    }

    const bool is_request = urb_is_request(urb);
    const uint8_t command = tvb_get_uint8(tvb, 0);
    frame = p_get_proto_data(wmem_file_scope(), pinfo, proto_cmsis_dap,
        PROTO_DATA_FRAME);
    if (frame == NULL) {
        if (PINFO_FD_VISITED(pinfo))
            return 0;
        frame = new_frame_record(tvb, pinfo, urb, state, command);
        p_add_proto_data(wmem_file_scope(), pinfo, proto_cmsis_dap,
            PROTO_DATA_FRAME, frame);
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USBDAP");
    info = wmem_strbuf_new(wmem_packet_scope(), "");
    wmem_strbuf_append_printf(info, "%s %s ",
        val_to_str_const(command, command_names, "Unknown"),
        is_request ? "Request" : "Response");

    dap_tree = add_root(tvb, pinfo, tree);
    if (is_request && frame->request->response_frame != 0)
        add_generated_frame(tvb, dap_tree, hf_response, frame->request->response_frame);
    else if (!is_request && frame->request != NULL)
        add_generated_frame(tvb, dap_tree, hf_request, frame->request->request_frame);
    else if (!is_request && dap_tree)
        proto_tree_add_expert(dap_tree, pinfo, &ei_packet_lost, tvb, 0, length);
    add_le(dap_tree, tvb, hf_command, 0, 1);
    dissect_command_data(tvb, pinfo, dap_tree, is_request, command, frame, info);
    col_add_str(pinfo->cinfo, COL_INFO, wmem_strbuf_get_str(info));
    return length;
}

static bool
usb_class_compatible_with_cmsis_dap(const usb_conv_info_t *usb_info)
{
    return usb_info->interfaceClass == USB_UNKNOWN_INTERFACE_VALUE ||
        (usb_info->interfaceClass == CMSIS_DAP_USB_CLASS &&
         (usb_info->interfaceSubclass == USB_UNKNOWN_INTERFACE_VALUE ||
          usb_info->interfaceSubclass == CMSIS_DAP_USB_SUBCLASS) &&
         (usb_info->interfaceProtocol == USB_UNKNOWN_INTERFACE_VALUE ||
          usb_info->interfaceProtocol == CMSIS_DAP_USB_PROTOCOL));
}

static bool
looks_like_cmsis_dap_command(tvbuff_t *tvb, bool is_request)
{
    unsigned length = tvb_captured_length(tvb);
    uint8_t command = tvb_get_uint8(tvb, 0);
    unsigned minimum = command < 128 ? command_lengths[command][!is_request] : 0;

    return minimum > 0 && length >= minimum;
}

static bool
dissect_cmsis_dap_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    urb_info_t *urb = data;
    usb_conv_info_t *usb_info;
    dap_conv_state_t *state;
    device_track_t *track;
    interface_candidate_t *candidate;
    bool is_request, is_trace = false;

    if (urb == NULL || urb->conv == NULL)
        return false;
    /* A frame accepted earlier is marked with protocol data. */
    if (p_get_proto_data(wmem_file_scope(), pinfo, proto_cmsis_dap,
            PROTO_DATA_FRAME) != NULL ||
        p_get_proto_data(wmem_file_scope(), pinfo, proto_cmsis_dap,
            PROTO_DATA_TRACE) != NULL) {
        if (PINFO_FD_VISITED(pinfo))
            dissect_cmsis_dap(tvb, pinfo, tree, urb);
        return true;
    }
    usb_info = urb->conv;
    if (PINFO_FD_VISITED(pinfo) || tvb_captured_length(tvb) == 0 ||
            !usb_class_compatible_with_cmsis_dap(usb_info))
        return false;

    state = get_dap_conv_state(pinfo, urb);
    is_request = urb_is_request(urb);
    track = lookup_device_track(urb->bus_id, urb->device_address);
    candidate = track ? wmem_map_lookup(track->candidates,
        GUINT_TO_POINTER(usb_info->interfaceNum)) : NULL;

    /* A successful payload probe is per-packet only; enumeration grants trust. */
    if (candidate && candidate->confirmed && state->applied_candidate != candidate) {
        state->is_cmsis_dap = true;
        state->eps = candidate->eps;
        state->applied_candidate = candidate;
    }
    if (!state->is_cmsis_dap) {
        if (!is_request)
            return false;
    } else if (is_request) {
        if (urb->endpoint != state->eps.out)
            return false;
    } else {
        is_trace = state->eps.trace && urb->endpoint == state->eps.trace;
        if (!is_trace && urb->endpoint != state->eps.in)
            return false;
    }

    if (!is_trace && !looks_like_cmsis_dap_command(tvb, is_request))
        return false;
    return dissect_cmsis_dap(tvb, pinfo, tree, urb) > 0;
}

void
proto_register_cmsis_dap(void)
{
    static int *ett[] = {
        &ett_cmsis_dap, &ett_transfer, &ett_swo_packet, &ett_info_capabilities
    };
    static ei_register_info ei[] = {
        { &ei_malformed, { "cmsis_dap.malformed", PI_MALFORMED, PI_ERROR,
            "Malformed CMSIS-DAP packet", EXPFILL } },
        { &ei_zero_length, { "cmsis_dap.zero_length", PI_MALFORMED, PI_WARN,
            "Zero length", EXPFILL } },
        { &ei_packet_lost, { "cmsis_dap.packet_lost", PI_PROTOCOL, PI_WARN,
            "Relative packet lost", EXPFILL } }
    };
    expert_module_t *expert_module;

    proto_cmsis_dap = proto_register_protocol("USB CMSIS-DAP protocol", "USBDAP",
        "cmsis_dap");
    proto_cmsis_dap_usb_identity = proto_register_protocol("USB identity tracking",
        "DAP-ID", "usb_identity_tracking");
    proto_register_field_array(proto_cmsis_dap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module = expert_register_protocol(proto_cmsis_dap);
    expert_register_field_array(expert_module, ei, array_length(ei));
    device_tracks = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(),
        g_direct_hash, g_direct_equal);
}

void
proto_reg_handoff_cmsis_dap(void)
{
    GArray *wanted_hfids = g_array_new(false, false, sizeof(int));

    hf_usb_descriptor_index = proto_registrar_get_id_byname("usb.DescriptorIndex");
    hf_usb_descriptor_type = proto_registrar_get_id_byname("usb.bDescriptorType");
    hf_usb_request_in = proto_registrar_get_id_byname("usb.request_in");
    hf_usb_string = proto_registrar_get_id_byname("usb.bString");
    g_array_append_val(wanted_hfids, hf_usb_descriptor_index);
    g_array_append_val(wanted_hfids, hf_usb_descriptor_type);
    g_array_append_val(wanted_hfids, hf_usb_request_in);
    g_array_append_val(wanted_hfids, hf_usb_string);

    heur_dissector_add("usb.bulk", dissect_cmsis_dap_heur, "CMSIS-DAP v2 USB bulk",
        "cmsis_dap_usb_bulk", proto_cmsis_dap, HEURISTIC_ENABLE);
    usb_identity_handle = create_dissector_handle(dissect_usb_identity,
        proto_cmsis_dap_usb_identity);
    register_postdissector(usb_identity_handle);
    set_postdissector_wanted_hfids(usb_identity_handle, wanted_hfids);
}
