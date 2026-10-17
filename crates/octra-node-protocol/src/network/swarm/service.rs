// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    diagnostics, guard, now, policy, Arc, BTreeSet, Connection, Direction, Duration, Endpoint,
    Error, Future, Handler, JoinSet, Outcome, PeerClass, Phase, Pin, Swarm, TcpListener, TcpStream,
};
use rand::rngs::OsRng;
use tokio::{
    sync::{mpsc, Semaphore},
    time::{Instant, MissedTickBehavior},
};
#[cfg(test)]
mod tests;
type Task = Pin<Box<dyn Future<Output = ()> + Send>>;
#[derive(Clone)]
struct Spawner(mpsc::Sender<Task>);
impl Spawner {
    async fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) -> bool {
        self.0.send(Box::pin(task)).await.is_ok()
    }
}
struct RunGuard {
    swarm: Swarm,
    generation: u64,
}
impl Drop for RunGuard {
    fn drop(&mut self) {
        let mut s = self.swarm.state();
        if s.generation == self.generation {
            s.running = false;
            s.started = false;
            for p in s.peers.values() {
                p.peer.close();
            }
            s.peers.clear();
            s.dialing.clear();
            s.record_dialing.clear();
        }
    }
}
struct DialGuard {
    swarm: Swarm,
    generation: u64,
    endpoint: Vec<u8>,
}
struct SessionCompletion {
    swarm: Swarm,
    generation: u64,
    direction: Direction,
    completed: bool,
}
impl SessionCompletion {
    fn finish(mut self, result: Result<(), Error>) {
        let outcome = match result {
            Ok(()) => Outcome::LocalClose,
            Err(error) => diagnostics::failure(Phase::Session, &error),
        };
        self.completed = true;
        self.swarm
            .note(self.generation, self.direction, Phase::Session, outcome);
    }
}
impl Drop for SessionCompletion {
    fn drop(&mut self) {
        if !self.completed {
            self.swarm.note(
                self.generation,
                self.direction,
                Phase::Session,
                Outcome::Cancelled,
            );
        }
    }
}
impl Drop for DialGuard {
    fn drop(&mut self) {
        let mut s = self.swarm.state();
        if s.generation == self.generation {
            s.dialing.remove(&self.endpoint);
            s.record_dialing.remove(&self.endpoint);
            self.swarm.0.wake.notify_one();
        }
    }
}
fn active(swarm: &Swarm, generation: u64) -> bool {
    let s = swarm.state();
    s.running && s.generation == generation
}

async fn launch(
    swarm: Swarm,
    generation: u64,
    direction: Direction,
    connection: Connection<TcpStream>,
    remote_host: Vec<u8>,
    handler: Arc<dyn Handler>,
    spawn: Spawner,
) -> bool {
    let peer_id = connection.peer().node_id.clone();
    let installed = swarm.install(generation, direction, connection, remote_host);
    let (peer, driver) = match installed {
        Ok(Some(installed)) => installed,
        result => {
            if result.is_err() {
                swarm.note(generation, direction, Phase::Admission, Outcome::Other);
            }
            return swarm
                .state()
                .peers
                .get(&peer_id)
                .is_some_and(|p| p.peer.is_connected());
        }
    };
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        handler.connected(peer.clone());
    }));
    let owner = swarm.clone();
    // Construct before enqueueing: cancellation while this future is still
    // queued must have exactly one local outcome as well.
    let completion = SessionCompletion {
        swarm: swarm.clone(),
        generation,
        direction,
        completed: false,
    };
    if !spawn
        .spawn(async move {
            let result = driver
                .run(move |peer, frame| {
                    let owner = owner.clone();
                    let handler = handler.clone();
                    async move { owner.handle(handler.as_ref(), peer, frame).await }
                })
                .await;
            completion.finish(result);
        })
        .await
    {
        return false;
    }
    spawn
        .spawn(async move {
            let _ = swarm.exchange(&peer).await;
            let _ = swarm.send_profiles(&peer).await;
        })
        .await
}

async fn dial(
    swarm: Swarm,
    generation: u64,
    endpoint: &Endpoint,
    listen_port: u16,
    handler: Arc<dyn Handler>,
    spawn: Spawner,
) -> bool {
    {
        let s = swarm.state();
        if !s.running || s.generation != generation || !swarm.capacity(&s, PeerClass::Validator) {
            let outcome = if s.running {
                Outcome::Capacity
            } else {
                Outcome::Stopped
            };
            drop(s);
            swarm.note(generation, Direction::Outbound, Phase::Admission, outcome);
            return false;
        }
    }
    let proxy = swarm.state().proxy;
    let stream = match super::super::proxy::connect_diagnosed(endpoint, proxy).await {
        Ok(stream) => {
            swarm.note(
                generation,
                Direction::Outbound,
                Phase::Transport,
                Outcome::Accepted,
            );
            stream
        }
        Err(failure) => {
            swarm.note(
                generation,
                Direction::Outbound,
                Phase::Transport,
                failure.socks_reply.map_or_else(
                    || diagnostics::failure(Phase::Transport, &failure.error),
                    diagnostics::proxy_reply,
                ),
            );
            return false;
        }
    };
    let Ok(local) = swarm.hello(listen_port) else {
        swarm.note(
            generation,
            Direction::Outbound,
            Phase::Handshake,
            Outcome::Config,
        );
        return false;
    };
    let result = super::super::session::dial(
        stream,
        &local,
        &swarm.0.key,
        &swarm.0.config.allowed_public_keys,
        &mut OsRng,
        swarm.0.config.timeouts,
    )
    .await;
    let connection = match result {
        Ok(connection) => {
            swarm.note(
                generation,
                Direction::Outbound,
                Phase::Handshake,
                Outcome::Accepted,
            );
            connection
        }
        Err(error) => {
            swarm.note(
                generation,
                Direction::Outbound,
                Phase::Handshake,
                diagnostics::failure(Phase::Handshake, &error),
            );
            return false;
        }
    };
    launch(
        swarm,
        generation,
        Direction::Outbound,
        connection,
        endpoint.host.clone(),
        handler,
        spawn,
    )
    .await
}

fn bootstraps(
    swarm: &Swarm,
    generation: u64,
    listen_port: u16,
    handler: &Arc<dyn Handler>,
    spawn: &Spawner,
    tasks: &mut JoinSet<()>,
) {
    for endpoint in &swarm.0.config.bootstrap {
        let key = endpoint.encode();
        {
            let mut s = swarm.state();
            if !s.running || s.generation != generation || !s.dialing.insert(key.clone()) {
                continue;
            }
        }
        let swarm = swarm.clone();
        let endpoint = endpoint.clone();
        let handler = handler.clone();
        let spawn = spawn.clone();
        let guard = DialGuard {
            swarm: swarm.clone(),
            generation,
            endpoint: key,
        };
        tasks.spawn(async move {
            let _guard = guard;
            let mut delay = Duration::from_secs(1);
            loop {
                {
                    let s = swarm.state();
                    if !s.running
                        || s.generation != generation
                        || Swarm::counts(&s).0 >= swarm.0.config.bootstrap.len() as i64
                    {
                        return;
                    }
                }
                if dial(
                    swarm.clone(),
                    generation,
                    &endpoint,
                    listen_port,
                    handler.clone(),
                    spawn.clone(),
                )
                .await
                {
                    return;
                }
                if !active(&swarm, generation) {
                    return;
                }
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(60));
            }
        });
    }
}
fn records(
    swarm: &Swarm,
    generation: u64,
    listen_port: u16,
    handler: &Arc<dyn Handler>,
    spawn: &Spawner,
    tasks: &mut JoinSet<()>,
) {
    let mut s = swarm.state();
    let now = now();
    let endpoints: Vec<_> = s
        .registry
        .values(now)
        .cloned()
        .map(|r| {
            let mut address = r.host;
            address.push(b':');
            address.extend(r.port.to_string().bytes());
            (r.node_id, address)
        })
        .collect();
    let live: BTreeSet<_> = endpoints.iter().map(|(_, e)| e.clone()).collect();
    s.due.retain(|e, _| live.contains(e));
    for (id, address) in endpoints {
        if !s.running
            || s.generation != generation
            || id == swarm.node_id()
            || s.peers.get(&id).is_some_and(|p| p.peer.is_connected())
            || s.dialing.contains(&address)
            || !swarm.capacity(&s, PeerClass::Validator)
        {
            continue;
        }
        let Some(endpoint) = Endpoint::parse(&address) else {
            continue;
        };
        let Some(due) =
            policy::record_dial_due(now, s.due.get(&address).copied(), s.record_dialing.len())
        else {
            continue;
        };
        s.due.insert(address.clone(), due);
        s.dialing.insert(address.clone());
        s.record_dialing.insert(address.clone());
        let swarm = swarm.clone();
        let handler = handler.clone();
        let spawn = spawn.clone();
        let guard = DialGuard {
            swarm: swarm.clone(),
            generation,
            endpoint: address,
        };
        tasks.spawn(async move {
            let _guard = guard;
            dial(swarm, generation, &endpoint, listen_port, handler, spawn).await;
        });
    }
}
use crate::network::accept::delay as accept_delay;
pub(super) async fn run(
    swarm: Swarm,
    listener: TcpListener,
    handler: Arc<dyn Handler>,
) -> Result<(), Error> {
    let port = listener
        .local_addr()
        .map_err(|e| Error::from(e.to_string()))?
        .port();
    let generation = {
        let mut s = swarm.state();
        if s.started {
            return Err("p2p swarm is active".into());
        }
        s.generation = s
            .generation
            .checked_add(1)
            .ok_or_else(|| Error::from("swarm generation exhausted"))?;
        s.started = true;
        s.running = true;
        s.connections = diagnostics::Counters::default();
        swarm.0.stop.send_replace(false);
        s.generation
    };
    let _run = RunGuard {
        swarm: swarm.clone(),
        generation,
    };
    let mut tasks = JoinSet::new();
    let (tx, mut rx) = mpsc::channel(64);
    let spawn = Spawner(tx);
    let mut stop = swarm.0.stop.subscribe();
    // This is an operational resource ceiling, independent of peer roles and consensus.
    let pending = Arc::new(Semaphore::new(512));
    let mut reconnect = tokio::time::interval_at(
        Instant::now() + Duration::from_secs(10),
        Duration::from_secs(10),
    );
    reconnect.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let owner = swarm.clone();
    tasks.spawn(async move {
        while active(&owner, generation) {
            tokio::time::sleep(Duration::from_secs(15)).await;
            let mut sends = JoinSet::new();
            for peer in owner.peers() {
                let owner = owner.clone();
                sends.spawn(async move {
                    let _ = owner.exchange(&peer).await;
                });
            }
            while sends.join_next().await.is_some() {}
        }
    });
    bootstraps(&swarm, generation, port, &handler, &spawn, &mut tasks);
    let mut attempt = 0;
    let mut next_accept = Instant::now();
    let result = loop {
        if !active(&swarm, generation) {
            break Ok(());
        }
        tokio::select! {
            _=stop.changed()=>break Ok(()),
            Some(task)=rx.recv()=>{tasks.spawn(task);},
            Some(result)=tasks.join_next(),if !tasks.is_empty()=>{if let Err(e)=result{break Err(Error::from(format!("peer service failed: {e}")));}},
            accepted=async{tokio::time::sleep_until(next_accept).await;listener.accept().await}=>{
                match accepted{
                    Err(e)=>match accept_delay(attempt,&e){Some(delay)=>{attempt=(attempt+1).min(7);next_accept=Instant::now()+delay;},None=>break Err(Error::from(e.to_string()))},
                    Ok((stream,address))=>{
                        swarm.note(generation,Direction::Inbound,Phase::Transport,Outcome::Accepted);
                        attempt=0;next_accept=Instant::now();
                        let key=address.ip().to_string().into_bytes();
                        let allowed={let mut s=swarm.state();
                            if let Err(reason)=s.guard.admit(guard::Config::default(),now(),&key){
                                s.connections.record(Direction::Inbound,Phase::Admission,if reason=="banned"{Outcome::Banned}else{Outcome::ConnectionBudget});
                                continue;
                            }
                            if !(swarm.capacity(&s,PeerClass::Validator)||(swarm.accepts_observers(&s)&&swarm.capacity(&s,PeerClass::Observer))){
                                s.connections.record(Direction::Inbound,Phase::Admission,Outcome::Capacity);
                                continue;
                            }
                            if swarm.accepts_observers(&s){Vec::new()}else{swarm.0.config.allowed_public_keys.clone()}
                        };
                        let Ok(permit)=pending.clone().try_acquire_owned()else{swarm.note(generation,Direction::Inbound,Phase::Admission,Outcome::PendingLimit);continue;};
                        let owner=swarm.clone();let handler=handler.clone();let spawn=spawn.clone();
                        tasks.spawn(async move{
                            let Ok(local)=owner.hello(port)else{owner.note(generation,Direction::Inbound,Phase::Handshake,Outcome::Config);return;};
                            let result=super::super::session::accept(stream,&local,&owner.0.key,&allowed,&mut OsRng,owner.0.config.timeouts).await;
                            drop(permit);
                            match result{Ok(connection)=>{owner.note(generation,Direction::Inbound,Phase::Handshake,Outcome::Accepted);launch(owner,generation,Direction::Inbound,connection,key.clone(),handler,spawn).await;},Err(e)=>{
                                owner.note(generation,Direction::Inbound,Phase::Handshake,diagnostics::failure(Phase::Handshake,&e));
                                if let Some(reason)=guard::handshake_penalty(e.as_bytes()){owner.state().guard.report(guard::Config::default(),now(),&key,reason.as_bytes());}
                            }}
                        });
                    }
                }
            },
            _=reconnect.tick()=>{
                swarm.peers();
                if Swarm::counts(&swarm.state()).0<swarm.0.config.bootstrap.len() as i64{bootstraps(&swarm,generation,port,&handler,&spawn,&mut tasks);}
                records(&swarm,generation,port,&handler,&spawn,&mut tasks);
            },
            ()=swarm.0.wake.notified()=>records(&swarm,generation,port,&handler,&spawn,&mut tasks),
        }
    };
    swarm.stop();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
}
