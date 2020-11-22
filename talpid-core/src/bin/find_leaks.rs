use std::{
    collections::HashSet,
    env,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
};
use talpid_core::{dns, firewall, routing, tunnel::TunnelMetadata};
use talpid_types::net::{Endpoint, TransportProtocol};
use tokio::runtime::Runtime;

const GATEWAY_V4: Ipv4Addr = Ipv4Addr::new(192, 168, 30, 1);
const GATEWAY: IpAddr = IpAddr::V4(GATEWAY_V4);
const TUNNEL_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 30, 2));
const DNS_SERVERS: &[IpAddr] = &[GATEWAY];


fn main() {
    let mut args = env::args();
    let path_to_self: PathBuf = args.next().expect("failed to get path to self").into();
    let interface = args.next().expect("no interface name given");
    let runtime = Runtime::new().expect("failed to initialize tokio runtime");
    let handle = runtime.handle();
    let cache_dir = tempdir::TempDir::new("find-leaks").expect("failed to create temp dir");

    let mut route_manager = routing::RouteManager::new(handle.clone(), Default::default())
        .expect("Failed to initialize route manager");
    let mut firewall = firewall::Firewall::new(firewall::FirewallArguments {
        allow_lan: true,
        initialize_blocked: false,
    })
    .expect("failed to initialzie firewall");
    let mut dns_monitor =
        dns::DnsMonitor::new(cache_dir).expect("failed to initialize DNS monitor");

    loop {
        firewall.apply_policy(connecting_policy(path_to_self.clone())).expect("failed to apply connecting policy");
        route_manager
            .add_routes(routes(&interface))
            .expect("failed to set routes");
        dns_monitor
            .set(&interface, DNS_SERVERS)
            .expect("Failed to set DNS");

        firewall.apply_policy(connected_policy(path_to_self.clone(), &interface)).expect("failed to apply connected policy");

        dns_monitor.reset().expect("failed to reset DNS policy");
        route_manager.clear_routes().expect("failed to clear routes");
        firewall.reset_policy().expect("failed to reset firewall");
    }
}

fn routes(interface_name: &str) -> HashSet<routing::RequiredRoute> {
    let mut routes = HashSet::new();

    routes.insert(routing::RequiredRoute::new(
        "192.168.30.0/24".parse().unwrap(),
        routing::Node::device(interface_name.to_string()),
    ));
    routes
}

#[allow(unused_variables)]
fn connecting_policy(path: PathBuf) -> firewall::FirewallPolicy {
    firewall::FirewallPolicy::Connecting {
        peer_endpoint: Endpoint::new(GATEWAY, 80, TransportProtocol::Tcp),
        pingable_hosts: vec![GATEWAY],
        allow_lan: true,
        #[cfg(windows)]
        relay_client: path,
        #[cfg(target_os = "linux")]
        use_fwmark: false,
    }
}

#[allow(unused_variables)]
fn connected_policy(path: PathBuf, interface: &str) -> firewall::FirewallPolicy {
    let tunnel_metadata = TunnelMetadata {
        interface: interface.to_string(),
        ips: vec![TUNNEL_IP],
        ipv4_gateway: GATEWAY_V4,
        ipv6_gateway: None,
    };

    firewall::FirewallPolicy::Connected {
        peer_endpoint: Endpoint::new(GATEWAY, 80, TransportProtocol::Tcp),
        tunnel: tunnel_metadata,
        allow_lan: true,
        dns_servers: DNS_SERVERS.to_vec(),
        #[cfg(windows)]
        relay_client: path,
        #[cfg(target_os = "linux")]
        use_fwmark: false,
    }
}
