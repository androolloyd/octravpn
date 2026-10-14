#!/usr/bin/env python3
"""Generate native OCE1/authenticated P2P transport fixtures without network access."""
import argparse
import copy
import hashlib
import json
import pathlib
import random
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCES = ["net/oce1.ml", "net/hash_domain.ml", "net/p2p_frame.ml", "net/p2p_frame_budget.ml",
           "net/p2p_handshake.ml", "net/p2p_tx_gossip.ml", "crypto_guard/octra_ed25519.ml"]


def cases():
    rng = random.Random(202610131909)
    output = [{"op": "frame_meta", "message": i} for i in range(256)]
    known = list(range(1, 6))+list(range(16, 19))+[32, 33]+list(range(48, 66))
    limits = {1:65536, 2:65536, 5:65536, 3:4096, 4:4096, 16:4096, 17:524288,
              32:5004096, 48:262144, 60:262144, 50:1048576, 55:8388608, 57:8388608,
              59:8388608, 64:8388608, 65:393216}
    for message in known+[0, 255]:
        cap = limits.get(message, 16384 if message in known else 4096)
        for length in [0, 1, cap-1, cap, cap+1, 10_000_000]:
            output.append({"op":"frame_encode", "message":message, "length":length, "byte":(message*7)%256})
        for length in [0, 1, cap+2, 10_000_001, (1<<32)-1]:
            output.append({"op":"frame_decode", "wire":(length.to_bytes(4,"big")+bytes([message])).hex(), "cap":9_999_999})
    for wire in [b"", b"\0", b"\0\0", b"\0\0\0", b"\0\0\0\1", b"\0\0\0\3\3ab", b"\0\0\0\2\3"]:
        output.append({"op":"frame_decode", "wire":wire.hex(), "cap":65536})
    for length in [65537,65538]:
        output.append({"op":"frame_decode","wire":(length.to_bytes(4,"big")+b"\x37").hex(),"cap":65536})
    for kind, size in [("u8",1),("u16",2),("u32",4),("u64",8)]:
        for width in range(size+2):
            for byte in [0,255]:output.append({"op":"oce1","kind":kind,"wire":(bytes([byte])*width).hex()})
    for kind in ["bool","option"]:
        for wire in [b"",b"\0",b"\1",b"\2",b"\xff",b"\1\xff",b"\0\0"]:
            output.append({"op":"oce1","kind":kind,"wire":wire.hex()})
    for kind in ["bytes","list"]:
        for count in [0,1,7,8,9,(1<<31)-1,1<<31,(1<<32)-1]:
            for payload in [b"",bytes(range(8))]:output.append({"op":"oce1","kind":kind,"maximum":8,"wire":(count.to_bytes(4,"big")+payload).hex()})
    for value in [bytes(32),rng.randbytes(32),b"a"*64,b"A"*64,b"f"*63,b"z"*64,b"",b"0"*65]:
        output.append({"op":"hash32","value":value.hex()})
    def make_hello(index):
        return {"seed":(bytes([index])*32).hex(),"chain_id":b"octra-fixture".hex(),"protocol_version":3,
                "node_address":b"oct-fixture-address".hex(),"config_hash":bytes(range(32)).hex(),"listen_port":10000+index,
                "best_epoch":str([0,1,-1,-(1<<63),(1<<63)-1][index%5]),"best_root":rng.randbytes(32).hex(),"nonce":rng.randbytes(32).hex()}
    hellos=[make_hello(i) for i in range(1,9)]
    for hello in hellos:
        output.append({"op":"hello","hello":hello,"chain_id":hello["chain_id"],"config_hash":hello["config_hash"],"allowed":[]})
    baseline=hellos[0]
    for key,value in [("chain_id",b"different\xff".hex()),("protocol_version",0),("protocol_version",65535),("config_hash",bytes(32).hex()),
                      ("node_id",b"bad".hex()),("listen_port",0),("signature",bytes(64).hex()),("signature",""),("signature",bytes(65).hex()),
                      ("node_address",bytes(129).hex()),("chain_id",bytes(129).hex())]:
        hello=copy.deepcopy(baseline);hello[key]=value
        output.append({"op":"hello","hello":hello,"chain_id":baseline["chain_id"],"config_hash":baseline["config_hash"],"allowed":[]})
    output.append({"op":"hello","hello":baseline,"chain_id":baseline["chain_id"],"config_hash":baseline["config_hash"],"allowed":[bytes(32).hex()]})
    for i in range(8):
        for mutation in ["none","ack_nonce","ack_signature","finish_nonce","finish_identity","finish_chain","finish_config","finish_signature"]:
            output.append({"op":"exchange","initiator":hellos[i],"responder":hellos[(i+1)%8],"mutation":mutation})
    for hello in hellos:
        for signature in [None,bytes(64).hex()]:
            case={"op":"profile","seed":hello["seed"],"chain_id":hello["chain_id"],"node_id":b"a"*64,"epoch":hello["best_epoch"],"config_hash":hello["config_hash"]}
            case["node_id"]=case["node_id"].hex()
            if signature is not None:case["signature"]=signature
            output.append(case)
    for i in range(12):
        for kind in ["normal","weak_r","malleable","corrupt"]:
            output.append({"op":"ed25519_seed","seed":rng.randbytes(32).hex(),"message":rng.randbytes(i*17).hex(),"kind":kind})
    prime=(1<<255)-19
    public_keys=[n.to_bytes(32,"little") for n in [0,1,2,prime-1,prime,prime+1,(1<<255)-1,1<<255,(1<<256)-1]]
    public_keys += [(n+(1<<255)).to_bytes(32,"little") for n in [0,1,2,prime-1,prime]]
    public_keys += [rng.randbytes(32) for _ in range(32)]+[b"",bytes(31),bytes(33)]
    for pub in public_keys:output.append({"op":"ed25519","public":pub.hex(),"message":"","signature":bytes(64).hex()})
    for cls in ["validator","observer"]:
        for message,maximum in [(3,16*1024*1024),(49,128*1024*1024 if cls=="validator" else 16*1024*1024),(55,512*1024*1024 if cls=="validator" else 128*1024*1024),(32,64*1024*1024),(17,128*1024*1024)]:
            steps=[{"now":0.0,"message":message,"bytes":n} for n in [-1,maximum+1,maximum,0,1]]
            steps += [{"now":t,"message":message,"bytes":1} for t in [-1.0,59.999999,60.0,61.0,120.0]]
            steps += [{"now":120.0,"message":message,"bytes":maximum,"class":"observer"},{"now":180.0,"message":message,"bytes":maximum,"class":"validator"}]
            output.append({"op":"budget","class":cls,"now":0.0,"steps":steps})
        counts={3:2048,49:2048 if cls=="validator" else 256,55:512,32:4096,17:512}
        for message,count in counts.items():
            output.append({"op":"budget","class":cls,"now":0.0,"steps":[{"now":0.0,"message":message,"bytes":0} for _ in range(count+2)]})
    return output


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream",type=pathlib.Path,required=True)
    parser.add_argument("--builder-image",required=True)
    parser.add_argument("--out",type=pathlib.Path,required=True)
    args=parser.parse_args()
    pin=subprocess.check_output(["git","-C",str(args.upstream),"rev-parse","HEAD"],text=True).strip()
    manifest=json.loads((ROOT/"docs/rust-node/source-map.json").read_text())
    if pin!=json.loads((ROOT/"docs/rust-node/upstream.json").read_text())["commit"] or args.out.exists():raise SystemExit("require pinned upstream and a fresh fixture path")
    hashes={}
    inputs=cases()
    with tempfile.TemporaryDirectory(prefix="octra-network-oracle-") as temp:
        fixture=pathlib.Path(temp)
        for name in SOURCES:
            source=subprocess.check_output(["git","-C",str(args.upstream),"show",f"HEAD:{name}"])
            if (args.upstream/name).read_bytes()!=source:raise SystemExit(f"modified source: {name}")
            hashes[name]=hashlib.sha256(source).hexdigest()
            if hashes[name]!=manifest["files"][name]:raise SystemExit(f"source hash mismatch: {name}")
            destination=fixture/name;destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(source)
        shutil.copyfile(ROOT/"scripts/node-port/network-oracle.ml",fixture/"main.ml")
        (fixture/"dune").write_text("(executable (name main) (libraries octra_net octra_crypto_guard yojson lwt.unix zarith))\n")
        comparisons=" && ".join(f"cmp {name} /fixture/{name}" for name in SOURCES)
        command=comparisons+" && mkdir vpn_network_oracle && cp /fixture/main.ml /fixture/dune vpn_network_oracle/ && opam exec -- dune build ./vpn_network_oracle/main.exe && opam exec -- dune exec ./vpn_network_oracle/main.exe -- /fixture/cases.json"
        (fixture/"cases.json").write_text(json.dumps(inputs))
        native=subprocess.check_output(["docker","run","--rm","--network","none","--mount",f"type=bind,source={fixture},target=/fixture,readonly",args.builder_image,"bash","-lc",command],text=True)
        results=json.loads(native)
        # Decode genuine native messages, every truncated offset, trailing bytes and hostile lengths.
        extra=[]
        for kind,encoded in [("hello",next(c for c in results if c["input"]["op"]=="hello")["expected"]["encoded"]["hex"]),
                             ("ack",next(c for c in results if c["input"]["op"]=="exchange")["expected"]["ack"]["hex"]),
                             ("finish",next(c for c in results if c["input"]["op"]=="exchange")["expected"]["finish"]["hex"]),
                             ("profile",next(c for c in results if c["input"]["op"]=="profile")["expected"]["encoded"]["hex"])]:
            wire=bytes.fromhex(encoded)
            for end in range(len(wire)+1):extra.append({"op":"decode","kind":kind,"wire":wire[:end].hex()})
            for mutated in [wire+b"\0",b"\xff"*4+wire[4:],b"\x80\0\0\0"+wire[4:]]:extra.append({"op":"decode","kind":kind,"wire":mutated.hex()})
        for case in results:
            if case["input"]["op"]=="hello" and "encoded" in case["expected"]:
                extra.append({"op":"decode","kind":"hello","wire":case["expected"]["encoded"]["hex"]})
        (fixture/"cases.json").write_text(json.dumps(extra))
        native=subprocess.check_output(["docker","run","--rm","--network","none","--mount",f"type=bind,source={fixture},target=/fixture,readonly",args.builder_image,"bash","-lc",command],text=True)
        results+=json.loads(native)
    report={"upstream_commit":pin,"source_sha256":hashes,"oracle_sha256":hashlib.sha256((ROOT/"scripts/node-port/network-oracle.ml").read_bytes()).hexdigest(),"builder_image":args.builder_image,
            "scope":"OCE1, native authenticated P2P handshake/profile, frame bounds, peer budgets; consensus execution remains open","cases":results}
    args.out.parent.mkdir(parents=True,exist_ok=True);args.out.write_text(json.dumps(report,indent=2)+"\n")
    print(f"Generated {len(results)} native network cases")


if __name__=="__main__":main()
