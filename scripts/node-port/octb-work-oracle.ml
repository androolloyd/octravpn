(* SPDX-License-Identifier: BSD-3-Clause *)
(* Copyright (c) 2023-2026 Octra Labs <dev@octra.org> *)
open Yojson.Basic.Util
module W=Octra_vm.Byte_work
module I=Octra_vm.Int_work
module C=Octra_vm.Cost
let n v = v |> to_string |> int_of_string
let num v=`String(string_of_int v)
let opt f = function None->`Null|Some v->f v
let nums v=v|>to_list|>List.map n
let req v=match to_list v with
 |[`String"write";a;b]->W.Write(n a,n b)|[`String"erase";a]->W.Erase(n a)
 |[`String"copy";a;b]->W.Copy(n a,n b)|[`String"alloc";a]->W.Allocate(n a)
 |[`String"scan";a]->W.Scan(n a)|_->failwith"request"
let request=function W.Write(a,b)->`List[`String"write";num a;num b]|W.Erase a->`List[`String"erase";num a]|W.Copy(a,b)->`List[`String"copy";num a;num b]|W.Allocate a->`List[`String"alloc";num a]|W.Scan a->`List[`String"scan";num a]
let requests xs=`List(List.map request xs)
let limits v=match nums v with
 |[key_bytes;value_bytes;copy_bytes;write_bytes;alloc_bytes;unit_bytes]->W.limits ~key_bytes ~value_bytes ~copy_bytes ~write_bytes ~alloc_bytes ~unit_bytes
 |_->failwith"limits"
let bytes v=Base64.decode_exn(to_string v)
let run input=
 let get key=member key input in let int key=n(get key) in
 match get"op"|>to_string with
 |"cost"->`Assoc["charge",opt num (C.charge ~used:(int"used") ~cost:(int"cost") ~limit:(int"limit"));"charge_z",opt num (C.charge_z ~used:(int"used") ~cost:(Z.of_string(to_string(get"z"))) ~limit:(int"limit"));"product",opt num (C.scaled_product (nums(get"factors")) ~divisor:(int"divisor"))]
 |"integer"->
  let left=Z.of_string(to_string(get"left")) and right=Z.of_string(to_string(get"right")) in
  let op=match get"kind"|>to_string with"add"->I.Add|"sub"->I.Sub|"mul"->I.Mul|"div"->I.Div|"mod"->I.Mod|"neg"->I.Neg|"abs"->I.Abs|_->failwith"integer op" in
  let value=match I.eval op left right with I.Value z->`String(Z.to_string z)|I.Reject->`Null in
  `Assoc["variable",`String(Z.to_string(I.variable op left right));"prior",`String(Z.to_string(I.cost ~base:(int"base") I.Prior op left right));"active",`String(Z.to_string(I.cost ~base:(int"base") I.Active op left right));"value",value]
 |"helpers"->
  `Assoc["parsing",opt(fun(base,rs)->`List[num base;requests rs])(W.parsing ~length:(int"length") ~cells:(int"count"));"encoded_size",opt num(W.encoded_size(int"length"));"cell_bytes",opt num(W.cell_bytes ~count:(int"count") ~bits:(int"bits"));"decoding",opt(fun(d:W.decoding)->`Assoc["max_bytes",num d.max_bytes;"requests",requests d.requests])(W.decoding ~length:(int"length") ~cells:(int"count") ~bits:(int"bits") ~cached:(get"cached"|>to_bool))]
 |"plan"->opt(fun limits->opt(fun(a,b,c)->`List[num a;num b;num c])(W.plan limits ~remaining:(int"remaining") ~available:(int"available") ~used:(int"used") ~limit:(int"limit") ~base:(int"base") (get"requests"|>to_list|>List.map req)))(limits(get"limits"))
 |"budget"->opt(fun limits->
  let budget=W.create limits in
  `List(List.map(fun action->
   let a key=member key action in
   let used=n(a"used") and limit=n(a"limit") in
   let value=match a"action"|>to_string with
    |"charge"->W.charge budget ~used ~limit ~base:(n(a"base")) (a"requests"|>to_list|>List.map req)
    |"output"->W.output budget ~used ~limit (n(a"size"))
    |"emit"->W.emit budget ~used ~limit (n(a"size"))|_->failwith"action" in
   `Assoc["result",opt num value;"remaining",num(W.remaining budget);"available",num(W.available budget);"event_left",num(W.event_left budget)])(get"actions"|>to_list)))(limits(get"limits"))
 |"text"->opt num(W.text_size ~limit:(int"limit") (bytes(get"value")))
 |"event"->opt num(W.event_size ~limit:(int"limit") ~address:(bytes(get"address")) ~depth:(int"depth") ~name:(bytes(get"name")) ~values:(get"values"|>to_list|>List.map bytes))
 |_->failwith"operation"
let ()=let inputs=Yojson.Basic.from_channel stdin|>to_list in
 let cases=List.map(fun input->`Assoc["input",input;"expected",run input])inputs in
 assert(Sys.max_string_length=144115188075855863);
 Yojson.Basic.to_channel stdout(`List cases);print_newline()
