use async_std::{io, task};
use futures::{
    prelude::{stream::StreamExt, *},
    select,
};
use libp2p::{
    floodsub::{self, Floodsub, FloodsubEvent},
    identity,
    mdns::{Mdns, MdnsConfig, MdnsEvent},
    swarm::SwarmEvent,
    Multiaddr, NetworkBehaviour, PeerId, Swarm,
};
use std::error::Error;

#[async_std::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());

    println!("Local peer id: {:?}", local_peer_id);
    let transport = libp2p::development_transport(local_key).await?;

    // Create a floodsub topic
    let floodsub_topic = floodsub::Topic::new("chat");

    // We create a custom network behaviour, it combines floodsub and mDNS.
    #[derive(NetworkBehaviour)]
    #[behaviour(out_event = "OutEvent")]
    struct ChatBehaviour {
        floodsub: Floodsub,
        mdns: Mdns,

        // Struct fields which do not implement NetworkBehaviour need to be ignore
        #[behaviour(ignore)]
        #[allow(dead_code)]
        ignored_member: bool,
    }

    #[derive(Debug)]
    enum OutEvent {
        Floodsub(FloodsubEvent),
        Mdns(MdnsEvent),
    }

    impl From<MdnsEvent> for OutEvent {
        fn from(v: MdnsEvent) -> Self {
            Self::Mdns(v)
        }
    }

    impl From<FloodsubEvent> for OutEvent {
        fn from(v: FloodsubEvent) -> Self {
            Self::Floodsub(v)
        }
    }

    let mut swarm = {
        let mdns = Mdns::new(MdnsConfig::default()).await?;
        let mut behaviour = ChatBehaviour {
            floodsub: Floodsub::new(local_peer_id),
            mdns,
            ignored_member: false,
        };

        behaviour.floodsub.subscribe(floodsub_topic.clone());
        Swarm::new(transport, behaviour, local_peer_id)
    };

    if let Some(to_dial) = std::env::args().nth(1) {
        let addr: Multiaddr = to_dial.parse()?;
        swarm.dial(addr)?;
        println!("Dialed {:?}", to_dial)
    }

    let mut stdin = io::BufReader::new(io::stdin()).lines().fuse();

    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    loop {
        select! {
            line = stdin.select_next_some() => swarm
                .behaviour_mut()
                .floodsub
                .publish(floodsub_topic.clone(), line.expect("Stdin not to close").as_bytes()),
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Listening on {:?}", address)
                }
                SwarmEvent::IncomingConnection { send_back_addr, .. } => {
                    println!("Incoming connecting {:?}", send_back_addr)
                }
                SwarmEvent::ConnectionEstablished { peer_id, num_established, .. } => {
                    println!("Connection established ({}) {:?}", num_established, peer_id);
                }
                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    println!("Connection closed {:?}", peer_id);
                }
                SwarmEvent::Dialing(peer_id) => {
                    println!("Dialing {:?}", peer_id);
                }

                SwarmEvent::Behaviour(OutEvent::Floodsub(FloodsubEvent::Message(message))) => {
                    println!(
                        "Received: '{:?}' from {:?}",
                        String::from_utf8_lossy(&message.data),
                        message.source
                    );
                }
                SwarmEvent::Behaviour(OutEvent::Mdns(MdnsEvent::Discovered(list))) => {
                    for (peer, addr) in list {
                        println!("discovered {} {}", peer, addr);
                        swarm
                            .behaviour_mut()
                            .floodsub
                            .add_node_to_partial_view(peer);
                    }
                }
                SwarmEvent::Behaviour(OutEvent::Mdns(MdnsEvent::Expired(list))) => {
                    for (peer, addr) in list {
                        println!("expired {} {}", peer, addr);
                        if !swarm.behaviour_mut().mdns.has_node(&peer) {
                            swarm
                                .behaviour_mut()
                                .floodsub
                                .remove_node_from_partial_view(&peer);
                        }
                    }
                }
                _ => {}
                }
        }
    }
}
