#include <epan/proto.h>
#include <ws_version.h>
#include <ws_symbol_export.h>

void proto_register_cmsis_dap(void);
void proto_reg_handoff_cmsis_dap(void);

WS_DLL_PUBLIC_DEF const gchar plugin_version[] = "1.0.0";
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

WS_DLL_PUBLIC_DEF void
plugin_register(void)
{
    static proto_plugin plugin = {
        proto_register_cmsis_dap,
        proto_reg_handoff_cmsis_dap
    };

    proto_register_plugin(&plugin);
}
