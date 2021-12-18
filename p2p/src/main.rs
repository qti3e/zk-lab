use std::error::Error;
use libp2p::{identity, Multiaddr, PeerId};
use futures::executor::block_on;
use libp2p::swarm::{Swarm, SwarmEvent};
use futures::{StreamExt};
use libp2p::mdns::{Mdns, MdnsConfig, MdnsEvent};

#[async_std::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());

    println!("Local peer id: {:?}", local_peer_id);
    let transport = block_on(libp2p::development_transport(local_key))?;

    // A network behaviour cares about "what" data we want to send, while
    // transport cares about "how" to send the data.
    let behaviour = Mdns::new(MdnsConfig::default()).await?;

    // Now to connect the two we need to use a swarm. It basically pipes
    // the behaviour and transport together.

    let mut swarm = Swarm::new(transport, behaviour, local_peer_id);

    // Tell the swarm to listen on all interfaces and a random, OS-assigned port.
    // It's like TCP bind method.
    // This string is called a Multiaddr, which is a self describing network
    // address.
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, ..} => {
                println!("Listening on {:?}", address)
            },
            SwarmEvent::IncomingConnection { send_back_addr,.. } => {
                println!("Incoming connecting {:?}", send_back_addr)
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                println!("Connection established {:?}", peer_id);
            }
            SwarmEvent::ConnectionClosed { peer_id , ..} => {
                println!("Connection closed {:?}", peer_id);
            }
            SwarmEvent::Behaviour(MdnsEvent::Discovered(peers)) => {
                for (peer, addr) in peers {
                    println!("discovered {} {}", peer, addr);
                }
            }
            SwarmEvent::Behaviour(MdnsEvent::Expired(expired)) => {
                for (peer, addr) in expired {
                    println!("expired {} {}", peer, addr);
                }
            },
            SwarmEvent::Dialing(peer_id) => {
                println!("Dialing {:?}", peer_id);
            }
            _ => {}
        }
    }
}
