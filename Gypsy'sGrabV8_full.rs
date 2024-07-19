extern crate log;
extern crate notify;
extern crate simple_logging;

use std::process::Command;
use std::thread;
use std::time::Duration;
use std::net::{IpAddr, Ipv4Addr};
use log::{info, error};
use notify::{Watcher, RecursiveMode, watcher};

const LOG_FILE: &str = "/tmp/migration.log"; // Using /tmp for stealth
const UPLOAD_DIR: &str = "/path/to/upload_directory";  // Directory to monitor
const CONTAINER_REGISTRY: &str = "my_docker_registry"; // Docker registry

fn main() {
    simple_logging::log_to_file(LOG_FILE, log::LevelFilter::Info).expect("Failed to initialize logger");

    let source_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)); // Localhost as source IP
    let destination_ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)); // Placeholder destination IP

    trigger_migration(source_ip, destination_ip);
}

fn trigger_migration(source_ip: IpAddr, destination_ip: IpAddr) {
    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher = watcher(tx, Duration::from_secs(1)).expect("Failed to initialize watcher");
    watcher.watch(UPLOAD_DIR, RecursiveMode::Recursive).expect("Failed to watch directory");

    loop {
        match rx.recv() {
            Ok(event) => {
                match event {
                    notify::DebouncedEvent::Create(path) |
                    notify::DebouncedEvent::Write(path) |
                    notify::DebouncedEvent::Rename(_, path) => {
                        info!("File created, modified, or renamed: {:?}", path);
                        if let Some(file_name) = path.file_name() {
                            if let Some(file_name_str) = file_name.to_str() {
                                if file_name_str.ends_with(".rs") {
                                    info!("Triggering migration...");
                                    if let Err(err) = migrate_server(source_ip, destination_ip) {
                                        error!("Migration failed: {}", err);
                                    }
                                }
                            }
                        }
                    }
                    notify::DebouncedEvent::Remove(path) => {
                        info!("File deleted: {:?}", path);
                        if let Some(file_name) = path.file_name() {
                            if let Some(file_name_str) = file_name.to_str() {
                                if file_name_str.ends_with(".rs") {
                                    info!("Triggering migration...");
                                    if let Err(err) = migrate_server(source_ip, destination_ip) {
                                        error!("Migration failed: {}", err);
                                    }
                                }
                            }
                        }
                    }
                    notify::DebouncedEvent::Error(err, _) => {
                        error!("Watcher error: {:?}", err);
                    }
                    _ => {}
                }
            }
            Err(err) => {
                error!("Watcher channel receive error: {:?}", err);
            }
        }
    }
}

fn migrate_server(source_ip: IpAddr, destination_ip: IpAddr) -> Result<(), String> {
    let server_components = identify_server_components()?;
    info!("Identified server components: {:?}", server_components);

    let container_images = containerize_server_components(&server_components)?;
    info!("Container images created: {:?}", container_images);

    synchronize_data(source_ip, destination_ip)?;
    info!("Data synchronized successfully.");

    configure_network(destination_ip)?;
    info!("Network configured successfully.");

    deploy_containers(&container_images, destination_ip)?;
    info!("Containers deployed successfully.");

    validate_migration(destination_ip)?;
    info!("Migration validated successfully.");

    cleanup_source_server()?;
    info!("Source server cleanup completed successfully.");

    info!("Server migration completed successfully!");
    Ok(())
}

fn identify_server_components() -> Result<Vec<String>, String> {
    let components = vec!["web_server".into(), "database".into(), "backend_service".into()];
    Ok(components)
}

fn containerize_server_components(components: &[String]) -> Result<Vec<String>, String> {
    let container_images: Vec<String> = components.iter()
        .map(|component| {
            let image_name = format!("{}/{}", CONTAINER_REGISTRY, component);
            let status = Command::new("docker")
                .args(&["build", "-t", &image_name, "."])
                .status()
                .expect("Failed to build Docker image");
            if !status.success() {
                return Err(format!("Failed to build image for component: {}", component));
            }
            Ok(image_name)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(container_images)
}

fn synchronize_data(source_ip: IpAddr, destination_ip: IpAddr) -> Result<(), String> {
    let status = Command::new("rsync")
        .args(&["-avz", UPLOAD_DIR, &format!("{}:{}", destination_ip, UPLOAD_DIR)])
        .status()
        .expect("Failed to synchronize data");
    if !status.success() {
        return Err("Data synchronization failed".into());
    }
    Ok(())
}

fn configure_network(destination_ip: IpAddr) -> Result<(), String> {
    info!("Configuring network for destination IP address: {}", destination_ip);

    let commands = vec![
        format!("ssh {} 'sudo ufw enable'", destination_ip),           // Enable UFW firewall
        format!("ssh {} 'sudo ufw allow 22/tcp'", destination_ip),    // Allow SSH
        format!("ssh {} 'sudo ufw allow 80/tcp'", destination_ip),    // Allow HTTP
        format!("ssh {} 'sudo ufw allow 443/tcp'", destination_ip),   // Allow HTTPS
        format!("ssh {} 'sudo ufw allow 2375/tcp'", destination_ip),  // Allow Docker API over TCP
        format!("ssh {} 'sudo ufw allow 2376/tcp'", destination_ip),  // Allow Docker Swarm communication
        format!("ssh {} 'sudo ufw reload'", destination_ip)           // Reload UFW to apply changes
    ];

    for command in commands {
        let status = Command::new("sh")
            .arg("-c")
            .arg(&command)
            .status()
            .expect("Failed to configure UFW firewall");
        if !status.success() {
            return Err(format!("UFW firewall configuration failed: {}", command));
        }
    }

    let network_config_commands = vec![
        format!("ssh {} 'echo \"auto eth0\niface eth0 inet static\naddress 192.168.1.100\nnetmask 255.255.255.0\ngateway 192.168.1.1\" | sudo tee /etc/network/interfaces.d/eth0'", destination_ip),
        format!("ssh {} 'sudo systemctl restart networking'", destination_ip)  // Restart networking service
    ];

    for command in network_config_commands {
        let status = Command::new("sh")
            .arg("-c")
            .arg(&command)
            .status()
            .expect("Failed to configure network interfaces");
        if !status.success() {
            return Err(format!("Network interface configuration failed: {}", command));
        }
    }

    Ok(())
}

fn deploy_containers(container_images: &[String], destination_ip: IpAddr) -> Result<(), String> {
    for image in container_images {
        let status = Command::new("ssh")
            .arg(destination_ip.to_string())
            .arg(format!("docker run -d {}", image))
            .status()
            .expect("Failed to deploy Docker container");
        if !status.success() {
            return Err(format!("Failed to deploy container: {}", image));
        }
    }
    Ok(())
}

fn validate_migration(destination_ip: IpAddr) -> Result<(), String> {
    info!("Validating migration to destination IP address: {}", destination_ip);

    let services = vec!["web_server", "database", "backend_service"];
    for service in services {
        let status = Command::new("ssh")
            .arg(destination_ip.to_string())
            .arg(format!("docker ps | grep {}", service))
            .status()
            .expect("Failed to validate service");
        if !status.success() {
            return Err(format!("Validation failed for service: {}", service));
        }
    }

    Ok(())
}

fn cleanup_source_server() -> Result<(), String> {
    info!("Performing cleanup tasks on the source server...");

    let commands = vec![
        "sudo systemctl stop web_server",          // Stop the web server service
        "sudo systemctl stop database",            // Stop the database service
        "sudo systemctl stop backend_service",    // Stop the backend service
        "rm -rf /tmp/*"                             // Example: Remove temporary files
    ];

    for command in commands {
        let status = Command::new("sh")
            .arg("-c")
            .arg(command)
            .status()
            .expect("Failed to complete cleanup command");
        if !status.success() {
            return Err(format!("Cleanup failed for command: {}", command));
        }
    }

    // Continue cleanup tasks
    info!("Performing final cleanup tasks on the source server...");
    let final_cleanup_commands = vec![
        "sudo rm -rf /path/to/temp/directory",  // Example: Remove temporary directories
        "sudo rm -f /var/log/migration.log"    // Example: Remove the migration log file
    ];

    for command in final_cleanup_commands {
        let status = Command::new("sh")
            .arg("-c")
            .arg(command)
            .status()
            .expect("Failed to complete final cleanup tasks");
        if !status.success() {
            return Err(format!("Final cleanup failed for command: {}", command));
        }
    }

    Ok(())
}