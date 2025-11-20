use crate::auth_capnp::auth;
use crate::system::ZKPSystem;
use crate::utils::ZKPUtils;
use crate::actors::{Prover, Verifier};
use capnp::capability::Promise;
use capnp_rpc::{rpc_twoparty_capnp, twoparty, RpcSystem, pry};
use num_bigint::BigUint;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use crate::protocol::ZKPProtocol;

pub mod auth_capnp;
pub mod actors;
pub mod protocol;
pub mod system;
pub mod utils;

struct AuthImpl {
    system: Arc<ZKPSystem>,
    // user -> (y1, y2)
    users: Arc<Mutex<HashMap<String, (BigUint, BigUint)>>>,
    // auth_id -> (user, challenge, r1, r2)
    sessions: Arc<Mutex<HashMap<String, (String, BigUint, BigUint, BigUint)>>>,
}

impl AuthImpl {
    fn new(system: Arc<ZKPSystem>) -> Self {
        Self {
            system,
            users: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl auth::Server for AuthImpl {
    fn register(
        &mut self,
        params: auth::RegisterParams,
        mut _results: auth::RegisterResults,
    ) -> Promise<(), ::capnp::Error> {
        let request = pry!(params.get());
        let request_reader = pry!(request.get_request());
        let user = pry!(request_reader.get_user()).to_string();
        let user = match user {
            Ok(u) => u,
            Err(_) => return Promise::err(capnp::Error::failed("Invalid user string".to_string())),
        };
        let y1 = BigUint::from_bytes_be(pry!(request_reader.get_y1()));
        let y2 = BigUint::from_bytes_be(pry!(request_reader.get_y2()));

        println!("Registering user: {}", user);
        self.users.lock().unwrap().insert(user, (y1, y2));

        Promise::ok(())
    }

    fn create_authentication_challenge(
        &mut self,
        params: auth::CreateAuthenticationChallengeParams,
        mut results: auth::CreateAuthenticationChallengeResults,
    ) -> Promise<(), ::capnp::Error> {
        let request = pry!(params.get());
        let request_reader = pry!(request.get_request());
        let user = pry!(request_reader.get_user()).to_string();
        let user = match user {
            Ok(u) => u,
            Err(_) => return Promise::err(capnp::Error::failed("Invalid user string".to_string())),
        };
        let r1 = BigUint::from_bytes_be(pry!(request_reader.get_r1()));
        let r2 = BigUint::from_bytes_be(pry!(request_reader.get_r2()));

        println!("Creating challenge for user: {}", user);

        // Verify user exists
        if !self.users.lock().unwrap().contains_key(&user) {
            return Promise::err(capnp::Error::failed("User not found".to_string()));
        }

        let verifier = Verifier::new(&*self.system);
        let challenge = verifier.generate_challenge();
        let auth_id = ZKPUtils::generate_random_string(16);

        {
            let mut sessions = self.sessions.lock().unwrap();
            sessions.insert(
                auth_id.clone(),
                (user, challenge.clone(), r1, r2),
            );
        }

        let mut response = results.get().init_response();
        response.set_auth_id(&auth_id);
        response.set_c(&challenge.to_bytes_be());

        Promise::ok(())
    }

    fn verify_authentication(
        &mut self,
        params: auth::VerifyAuthenticationParams,
        mut results: auth::VerifyAuthenticationResults,
    ) -> Promise<(), ::capnp::Error> {
        let request = pry!(params.get());
        let request_reader = pry!(request.get_request());
        let auth_id = pry!(request_reader.get_auth_id()).to_string();
        let auth_id = match auth_id {
            Ok(id) => id,
            Err(_) => return Promise::err(capnp::Error::failed("Invalid auth_id string".to_string())),
        };
        let s = BigUint::from_bytes_be(pry!(request_reader.get_s()));

        println!("Verifying authentication for auth_id: {}", auth_id);

        let session = {
            let mut sessions = self.sessions.lock().unwrap();
            sessions.remove(&auth_id)
        };

        let (user, challenge, r1, r2) = match session {
            Some(s) => s,
            None => return Promise::err(capnp::Error::failed("Session not found".to_string())),
        };

        let users = self.users.lock().unwrap();
        let (y1, y2) = match users.get(&user) {
            Some(u) => u,
            None => return Promise::err(capnp::Error::failed("User not found".to_string())),
        };

        let verifier = Verifier::new(&*self.system);
        let is_valid = verifier.verify(
            (&r1, &r2),
            &challenge,
            &s,
            (y1, y2),
        );

        if is_valid {
            println!("Authentication successful for user: {}", user);
            let session_id = ZKPUtils::generate_random_string(32);
            results.get().init_response().set_session_id(&session_id);
            Promise::ok(())
        } else {
            println!("Authentication failed for user: {}", user);
            Promise::err(capnp::Error::failed("Authentication failed".to_string()))
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage:");
        println!("  Server: {} server", args[0]);
        println!("  Client: {} client <username> [register|login]", args[0]);
        println!("          If action is omitted, both register and login will be performed.");
        return Ok(());
    }

    let (alpha, beta, p, q) = ZKPUtils::get_1024_bit_constants();
    let system = Arc::new(ZKPSystem::new(p, q, alpha, beta));

    let local = tokio::task::LocalSet::new();
    
    match args[1].as_str() {
        "server" => {
            local.run_until(async move {
                let addr = "127.0.0.1:8080";
                let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
                let auth_impl = AuthImpl::new(system);
                let auth_client: auth::Client = capnp_rpc::new_client(auth_impl);

                println!("Server listening on {}", addr);

                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    let auth_client = auth_client.clone();
                    tokio::task::spawn_local(async move {
                        let stream: tokio_util::compat::Compat<tokio::net::TcpStream> = tokio_util::compat::TokioAsyncReadCompatExt::compat(stream);
                        let (reader, writer) = futures::io::AsyncReadExt::split(stream);
                        let network =
                            twoparty::VatNetwork::new(reader, writer, rpc_twoparty_capnp::Side::Server, Default::default());
                        let rpc_system = RpcSystem::new(Box::new(network), Some(auth_client.client));
                        if let Err(e) = rpc_system.await {
                            eprintln!("rpc error: {:?}", e);
                        }
                    });
                }
            }).await;
        }
        "client" => {
            // Parse client arguments
            if args.len() < 3 {
                println!("Error: Username required for client mode");
                println!("Usage: {} client <username> [register|login]", args[0]);
                return Ok(());
            }

            let username = args[2].clone();
            let action = if args.len() >= 4 {
                args[3].as_str()
            } else {
                "both" // Default: perform both register and login
            };

            // Validate action
            if !["register", "login", "both"].contains(&action) {
                println!("Error: Invalid action '{}'. Must be 'register', 'login', or omitted for both.", action);
                return Ok(());
            }

            local.run_until(async move {
                let addr = "127.0.0.1:8080";
                let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
                let stream: tokio_util::compat::Compat<tokio::net::TcpStream> = tokio_util::compat::TokioAsyncReadCompatExt::compat(stream);
                let (reader, writer) = futures::io::AsyncReadExt::split(stream);
                let network = twoparty::VatNetwork::new(reader, writer, rpc_twoparty_capnp::Side::Client, Default::default());
                let mut rpc_system = RpcSystem::new(Box::new(network), None);
                let auth_client: auth::Client = rpc_system.bootstrap(rpc_twoparty_capnp::Side::Server);

                tokio::task::spawn_local(async move {
                    if let Err(e) = rpc_system.await {
                        eprintln!("rpc error: {:?}", e);
                    }
                });

                // Generate or load secret
                let secret_file = format!(".secret_{}", username);
                let secret = if action == "login" {
                    // Load existing secret for login
                    match std::fs::read_to_string(&secret_file) {
                        Ok(secret_str) => {
                            println!("Loading existing secret for user '{}'", username);
                            BigUint::parse_bytes(secret_str.trim().as_bytes(), 10).unwrap()
                        }
                        Err(_) => {
                            println!("Error: No secret found for user '{}'. Please register first.", username);
                            return;
                        }
                    }
                } else {
                    // Generate new secret for register or both
                    let new_secret = ZKPUtils::generate_random_below(system.get_order());
                    if action == "register" || action == "both" {
                        // Save secret to file
                        std::fs::write(&secret_file, new_secret.to_str_radix(10)).unwrap();
                        println!("Generated and saved secret for user '{}'", username);
                    }
                    new_secret
                };

                let prover = Prover::new(&*system, secret.clone());

                // Perform registration if requested
                if action == "register" || action == "both" {
                    println!("\n=== Registration ===");
                    println!("Registering user '{}'...", username);
                    let (y1, y2) = prover.public_values();
                    let mut request = auth_client.register_request();
                    let mut request_builder = request.get().init_request();
                    request_builder.set_user(&username);
                    request_builder.set_y1(&y1.to_bytes_be());
                    request_builder.set_y2(&y2.to_bytes_be());
                    request.send().promise.await.unwrap();
                    println!("✓ Registration successful for user '{}'", username);
                }

                // Perform login if requested
                if action == "login" || action == "both" {
                    println!("\n=== Authentication ===");
                    
                    // 1. Create Challenge
                    println!("Requesting authentication challenge for '{}'...", username);
                    let (commitments, randomness) = prover.generate_commitments();
                    let (r1, r2) = commitments;
                    let mut request = auth_client.create_authentication_challenge_request();
                    let mut request_builder = request.get().init_request();
                    request_builder.set_user(&username);
                    request_builder.set_r1(&r1.to_bytes_be());
                    request_builder.set_r2(&r2.to_bytes_be());
                    let response = request.send().promise.await.unwrap();
                    let response_reader = response.get().unwrap().get_response().unwrap();
                    let auth_id = response_reader.get_auth_id().unwrap().to_string().unwrap();
                    let c_bytes = response_reader.get_c().unwrap();
                    let c = BigUint::from_bytes_be(c_bytes);
                    println!("✓ Received challenge (auth_id: {})", auth_id);

                    // 2. Verify Authentication
                    println!("Sending authentication response...");
                    let s = prover.generate_response(&c, &randomness);
                    let mut request = auth_client.verify_authentication_request();
                    let mut request_builder = request.get().init_request();
                    request_builder.set_auth_id(&auth_id);
                    request_builder.set_s(&s.to_bytes_be());
                    let response = request.send().promise.await.unwrap();
                    let session_id = response.get().unwrap().get_response().unwrap().get_session_id().unwrap().to_string().unwrap();

                    println!("✓ Authentication successful!");
                    println!("Session ID: {}", session_id);
                }
            }).await;
        }
        _ => {
            println!("Unknown mode: {}", args[1]);
        }
    }

    Ok(())
}
