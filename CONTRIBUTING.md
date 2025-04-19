# Contributing to the MCP Wireshark Dissector

Thank you for your interest in contributing to this project! Here are some guidelines to help you get started.

## How to Contribute

1. **Fork the Repository**: Start by forking this repository to your GitHub account.

2. **Clone the Fork**: Clone your fork to your local machine.
   ```
   git clone https://github.com/jaitndangi1206/wireshark-mcp-dissector.git
   ```

3. **Create a Branch**: Create a new branch for your changes.
   ```
   git checkout -b feature/your-feature-name
   ```

4. **Make Your Changes**: Implement your changes, additions, or fixes.

5. **Test Your Changes**: Ensure your changes work as expected with Wireshark.

6. **Commit Your Changes**: Use clear and descriptive commit messages.
   ```
   git commit -m "Add support for new MCP message type"
   ```

7. **Push to GitHub**: Push your changes to your fork.
   ```
   git push origin feature/your-feature-name
   ```

8. **Create a Pull Request**: Submit a pull request from your fork to the main repository.

## Coding Standards

- Use consistent indentation (2 spaces)
- Add comments to explain complex logic
- Follow Lua best practices
- Maintain backward compatibility when possible

## Testing

- Test your changes with multiple versions of Wireshark
- Include sample capture files when adding support for new protocol features
- Verify that your changes don't break existing functionality

## Reporting Issues

If you find a bug or have a suggestion, please create an issue with:

- A clear description of the problem
- Steps to reproduce it
- Expected behavior
- Actual behavior
- Wireshark version and operating system

## Code of Conduct

- Be respectful and inclusive
- Accept constructive criticism gracefully
- Focus on solving problems, not blaming
