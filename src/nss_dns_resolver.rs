use crate::sysauth_client::NssSocketAddress;
use std::net::{AddrParseError, SocketAddr};
use ureq::Resolver;

pub struct NssDnsResolver {
    pub(crate) nss_socket_addresses: Vec<NssSocketAddress>,
}

impl Resolver for NssDnsResolver {
    fn resolve(&self, netloc: &str) -> std::io::Result<Vec<SocketAddr>> {
        let mut addresses : Vec<SocketAddr> = Vec::new();
        for item in self.nss_socket_addresses.iter() {
            if !String::from(netloc).eq(&item.from) {
                continue;
            }

            let socket_address : &Result<SocketAddr, AddrParseError> = &item.to.parse();
            match socket_address {
                Ok(addr) => addresses.push(*addr),
                Err(err) => log::error!("Cannot parse '{:?}' : {:?}", &item.to, err.to_string()),
            }
        }
        Ok(addresses)
    }
}

#[cfg(test)]
mod tests {
    use crate::nss_dns_resolver::NssDnsResolver;
    use crate::sysauth_client::PamClientConfig;
    use std::fs::File;
    use ureq::Resolver;

    #[test]
    fn test_client() {
        let config: PamClientConfig = serde_yaml::from_reader(File::open("sysauth-client.yaml").unwrap()).unwrap();

        let resolver = NssDnsResolver {
            nss_socket_addresses: config.nss_socket_addresses,
        };

        let result = resolver.resolve("github.com:443");
        println!("{:?}", result);
        assert!(result.is_ok());
    }
}
