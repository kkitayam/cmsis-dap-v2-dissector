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

The Lua and native plugins can coexist, but do not enable both for the same capture because both dissect the same USB bulk interface class.

## Filter and inspect packets

Use `cmsis_dap` to filter packets. For example:

```sh
tshark -r capture.pcapng -Y cmsis_dap \
  -T fields -e frame.number -e cmsis_dap.command -e cmsis_dap.swo_data
```

Use `-V` to inspect the decoded packet tree.
