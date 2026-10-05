# CMSIS-DAP v2 dissector

A [Wireshark](https://www.wireshark.org/) dissector for [CMSIS-DAP v2](https://arm-software.github.io/CMSIS-DAP/latest/index.html). This repository provides both a Lua dissector and a native C plugin. Both register the protocol as `USBDAP` and use the `cmsis_dap` display-filter prefix.

## Lua plugin

Copy `lua/cmsis-dap-v2.lua` to your personal Wireshark Lua plugins directory. On Windows, use `%APPDATA%\Wireshark\plugins`. On Linux, use `~/.local/lib/wireshark/plugins`.

## Native plugin

The native plugin requires Wireshark development files that match the Wireshark major and minor versions used at runtime, plus CMake and a C compiler. On Debian, install the `wireshark-dev` package.

Build and install the plugin into your personal plugin directory:

```sh
cmake -S native -B build -DCMAKE_PREFIX_PATH=/usr
cmake --build build
cmake --install build --prefix "$HOME/.local"
```

Confirm that Wireshark loads the plugin:

```sh
tshark -G plugins | grep -i cmsis_dap
```

Both plugins use a `usb.bulk` heuristic instead of binding every vendor-specific interface. The native plugin tracks USB enumeration and confirms interfaces with class/subclass/protocol `0xff/0x00/0x00`, bulk IN and OUT endpoints, and a complete Product or Interface string descriptor containing `CMSIS-DAP` or `CMSIS_DAP`, ignoring case. A complete nonmatching descriptor rejects the corresponding interface. If the capture does not include enough enumeration data, the native plugin falls back to validating command-like bulk OUT packets by command ID and minimum length; bulk IN responses and raw SWO traffic are not inferred in that fallback mode.

The Lua plugin uses only the payload heuristic: it requires a recognized command ID and the minimum packet length, then learns the command endpoints. It does not inspect interface descriptors or strings, so it can classify unrelated bulk traffic with a matching payload layout. Captures without enumeration are supported by both plugins. The native plugin decodes raw SWO traffic only when enumeration identifies the interface and its second bulk IN endpoint; the Lua plugin decodes it after learning command endpoints.

The Lua and native plugins can coexist, but do not enable both for the same capture because both dissect the same USB bulk traffic. Wireshark does not offer `usb.bulk` for Decode As, so the plugins do not register a manual Decode As option.

## Filter and inspect packets

Use `cmsis_dap` to filter packets. For example:

```sh
tshark -r capture.pcapng -Y cmsis_dap \
  -T fields -e frame.number -e cmsis_dap.command -e cmsis_dap.swo_data
```

Use `-V` to inspect the decoded packet tree.
