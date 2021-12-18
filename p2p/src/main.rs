use std::error::Error;
use libp2p::{identity, Multiaddr, PeerId};
use futures::executor::block_on;
use libp2p::ping::{Ping, PingConfig};
use libp2p::swarm::{Swarm, SwarmEvent};
use futures::{future, StreamExt};
use std::task::Poll;

fn main() -> Result<(), Box<dyn Error>> {
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());

    println!("Local peer id: {:?}", local_peer_id);
    let transport = block_on(libp2p::development_transport(local_key))?;

    // Create a ping network behaviour.
    // A network behaviour cares about "what" data we want to send, while
    // transport cares about "how" to send the data.
    let behaviour = Ping::new(PingConfig::new().with_keep_alive(true));

    // Now to connect the two we need to use a swarm. It basically pipes
    // the behaviour and transport together.

    let mut swarm = Swarm::new(transport, behaviour, local_peer_id);

    // Tell the swarm to listen on all interfaces and a random, OS-assigned port.
    // It's like TCP bind method.
    // This string is called a Multiaddr, which is a self describing network
    // address.
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    // Dial the peer identified by the multi-address given as the second
    // command-line argument, if any.
    if let Some(addr) = std::env::args().nth(1) {
        let remote: Multiaddr = addr.parse()?;
        swarm.dial(remote)?;
        println!("Dialed {}", addr);
    }

    // Now we need start running an event loop.
    block_on(future::poll_fn(move |cx| loop {
        match swarm.poll_next_unpin(cx) {
            Poll::Ready(Some(event)) => match event {
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
                SwarmEvent::Behaviour(event) => {
                    // println!("{:?}", event);
                },
                SwarmEvent::Dialing(peer_id) => {
                    println!("Dialing {:?}", peer_id);
                }
                _ => {}
            },
            Poll::Ready(None) => return Poll::Ready(()),
            Poll::Pending => return Poll::Pending
        }
    }));

    Ok(())
}
