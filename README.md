# sysauth-nss

`sysauth-nss` is a Rust-based project designed to create an NSS (Name Service Switch) module for system authentication. 
This module integrates with the NSS framework, providing custom authentication mechanisms and seamless compatibility with system-level NSS services.

## Features

- **Custom NSS Module**: Implements a pluggable NSS library for system authentication.
- **Cross-platform Compatibility**: Utilizes Rust's system-level libraries for portability.
- **Logging**: Integrated with `log` and `env_logger` for detailed logging.
- **Configuration Support**: Includes support for JSON and YAML configuration loading.
- **Networking**: Makes HTTP requests via the lightweight `ureq` library.

## Dependencies

This project makes use of the following Rust packages:

- `env_logger`: Logging framework for managing structured logs.
- `gethostname`: Retrieves the system's hostname.
- `libc`: Bindings to native C libraries.
- `libnss`: Provides the base implementation for `libnss` modules.
- `log`: Logging facade for conditional output.
- `serde`: Framework for serializing/deserializing data into Rust objects and vice versa.
- `serde_json`: JSON support for `serde`.
- `serde_yaml`: YAML support for `serde`.
- `ureq`: Simple and efficient HTTP client.

## Getting Started

### Prerequisites

To build and use this project, you'll need:

- Rust (minimum supported version: `1.65.0`)
- Build tools like `cargo` to compile Rust code.
- Basic knowledge of how NSS modules work on Linux or Unix-like systems.

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/evsinev/sysauth-nss.git
   cd sysauth-nss
   ```

2. Build the project:

   ```bash
   cargo build --release
   ```

3. Install the resulting libnss_sysauth.so.2 shared library as an NSS module (requires system access). Typically placed in `/lib` or `/lib64`.

4. Update your `/etc/nsswitch.conf` to use the new module (e.g., add `sysauth` to the desired service).

   ```bash
   passwd: sss files systemd sysauth
   ```

### Usage

1. Configure the module as needed by providing it with a JSON or YAML configuration file.
2. Restart any services that rely on the modified `/etc/nsswitch.conf`.
3. Test using system utilities like `getent` to verify correct behavior:

   ```bash
   getent passwd
   ```

### Example Configuration

Here is an example YAML configuration /opt/sysauth-client/etc/sysauth-client.yaml:

```yaml
baseUrls:
  - http://10.0.0.1:8090/sysauth

nssSocketAddresses:
  - from : "10.0.0.1:8090"
    to   : "10.0.0.1:8090"
```

### Logging

To enable detailed logs for debugging, set the `RUST_LOG` environment variable before running your application. For instance:

```bash
RUST_LOG=debug cargo run
```

## License

This project is licensed under the MIT License.

