# Wireshark MCP Dissector

A Wireshark protocol dissector for the Model Context Protocol (MCP), implemented in Lua.

## Overview

This dissector enables Wireshark to interpret and display Model Context Protocol (MCP) traffic. It provides a structured view of MCP packets, making it easier to analyze, debug, and understand MCP communications.

## Features

- Full dissection of MCP headers and payload data
- Support for all message types (Control, Data, and Error messages)
- Detailed flag bit analysis
- TCP stream reassembly support
- Heuristic protocol detection
- Compatible with both TCP and UDP transports

## Installation

### Automatic Installation

1. Download the `mcp_dissector.lua` file from this repository
2. Place it in your Wireshark plugins directory:
   - Windows: `%APPDATA%\Wireshark\plugins\`
   - Linux: `~/.local/lib/wireshark/plugins/` or `~/.wireshark/plugins/`
   - macOS: `~/.wireshark/plugins/`
3. Restart Wireshark

### Manual Installation from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/wireshark-mcp-dissector.git

# Copy the Lua script to your Wireshark plugins directory
# Windows (run in PowerShell)
cp wireshark-mcp-dissector/mcp_dissector.lua "$env:APPDATA\Wireshark\plugins\"

# Linux/macOS
cp wireshark-mcp-dissector/mcp_dissector.lua ~/.wireshark/plugins/
```

## Usage

Once installed, the dissector will automatically detect MCP traffic on TCP/UDP port 8765.

If your MCP implementation uses different ports:

1. Open Wireshark and capture some MCP traffic
2. Right-click on one of the packets and select "Decode As..."
3. Choose "MCP" from the list of available protocols
4. Click "Apply"

## Customization

You can customize the dissector by editing the `mcp_dissector.lua` file:

- Change the default ports by modifying the port registration lines
- Add additional message types or flags as needed
- Extend the payload parsing for specific message types

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

This project is licensed under the [MIT License](LICENSE).

## References

- Official MCP Documentation: [mcp.so](https://mcp.so)
- [Wireshark Lua API Reference](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html)
