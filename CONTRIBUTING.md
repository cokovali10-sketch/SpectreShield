# Contributing to SpectreShield

Thank you for your interest in contributing to SpectreShield! 

## How to Contribute

### Reporting Bugs
- Open an issue with the bug label
- Include: OS, kernel version, Go version, steps to reproduce
- Include relevant logs

### Suggesting Features
- Open an issue with the enhancement label
- Describe the use case and expected behavior

### Code Contributions
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`make test`)
5. Run linter (`make lint`)
6. Commit with clear message
7. Push and open a Pull Request

### Development Setup
```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/SpectreShield.git
cd SpectreShield

# Install dependencies
go mod download

# Build
make build

# Run tests
make test
```

### Code Style
- Follow standard Go conventions
- Use `gofmt` and `goimports`
- Write tests for new functionality
- Update documentation

### eBPF Development
- Use clang/llvm for compilation
- Test on kernel 5.4+
- Use cilium/ebpf library

## Code of Conduct
- Be respectful and inclusive
- Focus on constructive feedback
- Help newcomers

## Questions?
Open an issue or start a discussion.
