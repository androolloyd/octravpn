module Core=Octra_core
module Pack=Native_pack
module Store=Core.Store_irmin
open Yojson.Safe.Util
let field v k=member k v
let text v k=field v k|>to_string
let bytes v k=text v k|>Base64.decode_exn
let opt v k=match field v k with `String v->Some(Base64.decode_exn v)|_->None
let b64 v=`String(Base64.encode_exn v)
let option f=function None->`Null|Some v->f v
let account v=Core.Ledger_types.{balance=Z.of_string(text v"balance");nonce=int_of_string(text v"nonce");public_key=opt v"public_key";encrypted_balance=opt v"encrypted_balance";decrypt_allowance=Z.of_string(text v"decrypt_allowance")}
let account_json a=b64(Pack.old a)
let result f=function Ok v->`Assoc["ok",f v]|Error e->`Assoc["error",`String e]
let part(p:Core.Blob_chunk.part)=`List[b64 p.id;b64 p.raw]
let run index input=match text input"kind"with
|"image"->let a=account(field input"account")in let image=Pack.image a in
 `Assoc["data",b64 image.data;"meta",option b64 image.meta;"parts",`List(List.map part image.parts);"id",option b64 image.id;
 "restore",result account_json(Pack.read(Pack.data image.data|>Result.get_ok)~meta:image.meta ~get:(fun id->List.find_opt(fun(p:Core.Blob_chunk.part)->p.id=id)image.parts|>Option.map(fun(p:Core.Blob_chunk.part)->p.raw)))]
|"data"->result(function Pack.Old a->`List[`String"old";account_json a]|Pack.Parts(a,id)->`List[`String"parts";account_json a;b64 id])(Pack.data(bytes input"raw"))
|"meta"->result(fun m->b64(Pack.meta_json m))(Pack.meta(bytes input"raw"))
|"join"->let parts=field input"parts"|>to_list|>List.map(function `List[`String id;`String raw]->Base64.decode_exn id,Base64.decode_exn raw|_->failwith"part")in result b64(Core.Blob_chunk.join ~id:(bytes input"id")~size:(int_of_string(text input"size"))parts)
|"store"->
 let store=Lwt_main.run(Store.open_store ~fresh:true(Printf.sprintf"/tmp/account-store-oracle-%d"index))in Lwt_main.run(Store.begin_epoch_batch store);
 let address=bytes input"address"in
 let outputs=field input"steps"|>to_list|>List.map(fun step->
  let action=try(match text step"op"with
   |"set"->store.account_mode<-(if field step"active"=`Bool true then Core.Rule_graph.Active else Core.Rule_graph.Prior);Lwt_main.run(Store.set_account store address(account(field step"account")))
   |"remove"->Lwt_main.run(Store.remove_path store(List.map(fun v->Base64.decode_exn(to_string v))(field step"path"|>to_list)))
   |"write"->Lwt_main.run(Store.write store(List.map(fun v->Base64.decode_exn(to_string v))(field step"path"|>to_list))(bytes step"raw"))
   |_ ->failwith"unknown action");`Null with Failure e->`String e in
  let load=try `Assoc["ok",option account_json(Lwt_main.run(Store.get_account store address))]with Failure e->`Assoc["error",`String e]in
  `Assoc["action",action;"load",load;"data",option b64(Lwt_main.run(Store.read store["accounts";address;"data"]));"meta",option b64(Lwt_main.run(Store.read store["accounts";address;"cipher";"meta"]));"root",`String(Irmin.Type.to_string Store.Store.Hash.t (Store.Store.Tree.hash(Option.get store.batch_tree)))])in
 Lwt_main.run(Store.close store);`List outputs
|_->failwith"unknown kind"
let ()=let inputs=Yojson.Safe.from_file Sys.argv.(1)|>to_list in print_endline("ORACLE_RESULT="^Yojson.Safe.to_string(`List(List.mapi(fun i input->`Assoc["input",input;"output",run i input])inputs)))
