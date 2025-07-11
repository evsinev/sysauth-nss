use crate::nss_dns_resolver::NssDnsResolver;
use gethostname::gethostname;
use libnss::interop::Response;
use libnss::passwd::Passwd;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::time::Duration;
use ureq::{Agent};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NssSocketAddress {
    pub from : String,
    pub to   : String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PamClientConfig {
    pub base_urls: Vec<String>,
    pub nss_socket_addresses: Vec<NssSocketAddress>,

}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NssPasswordByUidRequest {
    pub hostname : String,
    pub user_id  : u32,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NssPasswordByNameRequest {
    pub hostname : String,
    pub name     : String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NssPasswordEntryResponse {
    pub result_code    : i32,
    pub error_message  : Option<String>,
    pub password_entry : Option<NssPasswordEntry>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NssPasswordEntry {
    pub name    : String,
    pub passwd  : String,
    pub uid     : u32,
    pub gid     : u32,
    pub gecos   : String,
    pub dir     : String,
    pub shell   : String,
}

fn create_nss_error(message: &str, error: String, response: Response<Passwd>) -> Response<Passwd> {
    println!("error: {message}: {error}");
    log::error!("{message}: {error}");
    response
}

pub struct NssPasswordClient {
    // fn get_nss_by_name(config_file: String, name: String) -> Response<Passwd>;
}

impl NssPasswordClient {
    fn fetch_nss_result<F>(&self, config_file: String, supplier : F) -> Response<Passwd>
    where F: FnOnce(String, String, &Agent) -> Result<ureq::Response, ureq::Error>,
    {
        let hostname = match gethostname().to_str() {
            Some(hostname) => hostname.to_string(),
            None => return create_nss_error("Cannot get hostname", "none".to_string(), Response::Unavail),
        };

        let file: File = match File::open(&config_file) {
            Ok(file) => file,
            Err(err) => return create_nss_error(&format!("Cannot open file {config_file}"), err.to_string(), Response::Unavail),
        };

        let config: PamClientConfig = match serde_yaml::from_reader(file) {
            Ok(config) => config,
            Err(err) => return create_nss_error("Cannot open file", err.to_string(), Response::Unavail),
        };

        let first_url: String = config.base_urls.first().unwrap().to_string();

        let resolver = NssDnsResolver {
            nss_socket_addresses: config.nss_socket_addresses,
        };

        let agent: Agent = ureq::AgentBuilder::new()
            .timeout_read    ( Duration::from_secs(5) )
            .timeout_write   ( Duration::from_secs(5) )
            .timeout_connect ( Duration::from_secs(5) )
            .resolver(resolver)
            .build();

        let http_response_result = supplier(hostname, first_url, &agent);

        let http_response = match http_response_result {
            Ok(response) => response,
            Err(err) => return create_nss_error("Cannot get response", err.to_string(), Response::Unavail),
        };

        if http_response.status() != 200 {
            println!("Response status is not 200 {:?}", http_response);
            return Response::TryAgain;
        }

        let body = match http_response.into_string() {
            Ok(body) => body,
            Err(err) => return create_nss_error("Cannot extract body", err.to_string(), Response::TryAgain),
        };

        let password_entry_response : NssPasswordEntryResponse = match serde_json::from_str(&body) {
            Ok(password_entry) => password_entry,
            Err(err) => return create_nss_error("Cannot deserialize response", err.to_string(), Response::Unavail),
        };

        if password_entry_response.result_code != 0 {
            log::error!("User not found");
            return Response::NotFound;
        };

        let entry = match password_entry_response.password_entry {
            Some(entry) => entry,
            None => return create_nss_error("No password entry in response", "none".to_string(), Response::Unavail),
        };

        Response::Success(Passwd {
            name    : entry.name,
            passwd  : entry.passwd,
            uid     : entry.uid,
            gid     : entry.gid,
            gecos   : entry.gecos,
            dir     : entry.dir,
            shell   : entry.shell,
        })
    }

    pub fn client_get_nss_by_id(&self, config_file: String, uid: u32) -> Response<Passwd> {

        self.fetch_nss_result(config_file,    |hostname : String, base_url : String, agent : &Agent| -> Result<ureq::Response, ureq::Error>  {

            let url_nss_by_uid = format!("{base_url}/nss/password/uid/{hostname}/{uid}");

            let nss_uid_request: NssPasswordByUidRequest = NssPasswordByUidRequest {
                hostname,
                user_id: uid,
            };

            let nss_uid_request_json = match serde_json::to_string(&nss_uid_request) {
                Ok(json) => json,
                Err(_err) => panic!("Cannot serialize to json"),
            };

            agent.post(url_nss_by_uid.as_str())
                .timeout(Duration::new(5, 0))
                .set("Content-Type", "application/json")
                .send_string(nss_uid_request_json.as_str())

        })
    }

    pub fn client_get_nss_by_name(&self, config_file: String, name: String) -> Response<Passwd> {
        let hostname = match gethostname().to_str() {
            Some(hostname) => hostname.to_string(),
            None => return create_nss_error("Cannot get hostname", "none".to_string(), Response::Unavail),
        };

        let file: File = match File::open(&config_file) {
            Ok(file) => file,
            Err(err) => return create_nss_error(&format!("Cannot open file {config_file}"), err.to_string(), Response::Unavail),
        };

        let config: PamClientConfig = match serde_yaml::from_reader(file) {
            Ok(config) => config,
            Err(err) => return create_nss_error("Cannot open file", err.to_string(), Response::Unavail),
        };

        let first_url: String = config.base_urls.first().unwrap().to_string();

        let url_nss_by_uid = format!("{first_url}/nss/password/name/{hostname}/{name}");

        let nss_uid_request: NssPasswordByNameRequest = NssPasswordByNameRequest {
            hostname,
            name: name.clone(),
        };

        let nss_uid_request_json = match serde_json::to_string(&nss_uid_request) {
            Ok(json) => json,
            Err(err) => return create_nss_error("Cannot serialize request", err.to_string(), Response::Unavail),
        };


        let resolver = NssDnsResolver {
            nss_socket_addresses: config.nss_socket_addresses,
        };

        let agent: Agent = ureq::AgentBuilder::new()
            .timeout_read    ( Duration::from_secs(5) )
            .timeout_write   ( Duration::from_secs(5) )
            .timeout_connect ( Duration::from_secs(5) )
            .resolver(resolver)
            .build();

        let http_response_result = agent.post(url_nss_by_uid.as_str())
            .timeout(Duration::new(5, 0))
            .set("Content-Type", "application/json")
            .send_string(nss_uid_request_json.as_str());

        let http_response = match http_response_result {
            Ok(response) => response,
            Err(err) => return create_nss_error("Cannot get response", err.to_string(), Response::Unavail),
        };

        if http_response.status() != 200 {
            println!("Response status is not 200 {:?}", http_response);
            return Response::TryAgain;
        }

        let body = match http_response.into_string() {
            Ok(body) => body,
            Err(err) => return create_nss_error("Cannot extract body", err.to_string(), Response::TryAgain),
        };

        let password_entry_response : NssPasswordEntryResponse = match serde_json::from_str(&body) {
            Ok(password_entry) => password_entry,
            Err(err) => return create_nss_error("Cannot deserialize response", err.to_string(), Response::Unavail),
        };

        if password_entry_response.result_code != 0 {
            log::error!("User {name} not found");
            return Response::NotFound;
        };

        let entry = match password_entry_response.password_entry {
            Some(entry) => entry,
            None => return create_nss_error("No password entry in response", "none".to_string(), Response::Unavail),
        };

        Response::Success(Passwd {
            name    : entry.name,
            passwd  : entry.passwd,
            uid     : entry.uid,
            gid     : entry.gid,
            gecos   : entry.gecos,
            dir     : entry.dir,
            shell   : entry.shell,
        })
    }

}

#[cfg(test)]
mod tests {
    use crate::sysauth_client::NssPasswordClient;
    use libnss::interop::Response;
    use libnss::passwd::Passwd;
    use std::time::Duration;
    use ureq::Agent;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_client_name() {
        init();
        let client = NssPasswordClient {};
        let response = client.client_get_nss_by_name(String::from("sysauth-client.yaml"), String::from("test-3"));
        print_response(response);
    }

    #[test]
    fn test_client_id() {
        init();
        let client = NssPasswordClient {};
        let response = client.client_get_nss_by_id(String::from("sysauth-client.yaml"), 4001);
        print_response(response);
    }

    fn print_response(response: Response<Passwd>) {
        match response {
            Response::NotFound => println!("not found"),
            Response::Unavail => println!("Unavail"),
            Response::Success(passwd) => println!("Success {:?}", passwd.name),
            Response::TryAgain => println!("TryAgain"),
            Response::Return => println!("Return"),
        };
    }

    #[test]
    fn test_ureq() {
        // env_logger::init();
        let agent: Agent = ureq::AgentBuilder::new()
            .timeout_read(Duration::from_secs(5))
            .timeout_write(Duration::from_secs(5))
            .timeout_connect(Duration::from_secs(5))
            .build();
        let body: String = agent.get("https://ip-api.com")
            .call()
            .unwrap()
            .into_string()
            .unwrap();
        println!("{}", body);
    }
}
