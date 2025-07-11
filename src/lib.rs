mod sysauth_client;
mod nss_dns_resolver;

use libnss::interop::Response;
use libnss::passwd::{Passwd, PasswdHooks};
use libnss::{
    libnss_passwd_hooks,
};
use crate::sysauth_client::NssPasswordClient;

struct HardcodedPasswd;
libnss_passwd_hooks!(sysauth, HardcodedPasswd);

impl PasswdHooks for HardcodedPasswd {
    fn get_all_entries() -> Response<Vec<Passwd>> {
        println!("get_all_entries");
        Response::NotFound
    }

    fn get_entry_by_uid(uid: libc::uid_t) -> Response<Passwd> {
        let _ = env_logger::try_init();
        let client = NssPasswordClient {};
        client.client_get_nss_by_id(String::from("/opt/sysauth-client/etc/sysauth-client.yaml"), uid)
    }

    fn get_entry_by_name(name: String) -> Response<Passwd> {
        let _ = env_logger::try_init();
        let client = NssPasswordClient {};
        client.client_get_nss_by_name(String::from("/opt/sysauth-client/etc/sysauth-client.yaml"), name)
    }
}
