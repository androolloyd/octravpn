(* Bounded adopted-native AML graph, entropy and standalone VM oracle. *)
open Yojson.Safe.Util
module G = Octra_vm.C_graph
module E = Octra_vm.C_ent
module V = Octra_vm.C_vm
module O = Octra_vm.C_octb
module L = Octra_vm.C_emit
module N = Octra_vm.C_nat
let get j k = member k j
let n j = to_int j
let z j = Z.of_string (to_string j)
let nat j = match N.of_int (n j) with Some n -> n | None -> invalid_arg "oracle natural"
let num z = `String (Z.to_string z)
let int n = `Int n
let str s = `String s
let err s = `Assoc ["error", str s]
let lit j = match to_list j with
| [`String "int"; v] -> L.Int (z v)
| [`String "bool"; v] -> L.Bool (to_bool v)
| [`String "bytes"; v] -> L.Bytes (Base64.decode_exn (to_string v))
| [`String "cap"; a; b] -> L.Cap (nat a, nat b)
| _ -> invalid_arg "oracle literal"
let lit_json = function
| L.Int z -> `List [str "int"; num z]
| L.Bool b -> `List [str "bool"; `Bool b]
| L.Bytes s -> `List [str "bytes"; str (Base64.encode_exn s)]
| L.Cap (a,b) -> `List [str "cap"; int (N.to_int a); int (N.to_int b)]
| L.Data _ -> invalid_arg "oracle data literal"
let op j = match to_list j with
| [`String "load"; a; value] -> O.Load (n a, lit value)
| [`String "move"; a; b] -> O.Move (n a, n b)
| [`String "plus"; a; b; c] -> O.Plus (n a,n b,n c)
| [`String "minus"; a; b; c] -> O.Minus (n a,n b,n c)
| [`String "times"; a; b; c] -> O.Times (n a,n b,n c)
| [`String "quotient"; a; b; c] -> O.Quotient (n a,n b,n c)
| [`String "remainder"; a; b; c] -> O.Remainder (n a,n b,n c)
| [`String "negate"; a; b] -> O.Negate (n a,n b)
| [`String "absolute"; a; b] -> O.Absolute (n a,n b)
| [`String "same"; a; b; c] -> O.Same (n a,n b,n c)
| [`String "different"; a; b; c] -> O.Different (n a,n b,n c)
| [`String "less"; a; b; c] -> O.Less (n a,n b,n c)
| [`String "greater"; a; b; c] -> O.Greater (n a,n b,n c)
| [`String "join"; a; b; c] -> O.Join (n a,n b,n c)
| [`String "size"; a; b] -> O.Size (n a,n b)
| [`String "slice"; a; b; c; d] -> O.Slice (n a,n b,n c,n d)
| [`String "close"; a; b] -> O.Cap_close (nat a,n b)
| [`String "jump"; a] -> O.Jump (n a)
| [`String "jump_if"; a; b] -> O.Jump_if (n a,n b)
| [`String "mark"; a] -> O.Mark (n a)
| [`String "noop"] -> O.Noop
| [`String "stop"] -> O.Stop
| _ -> invalid_arg "oracle instruction"
let vm j =
 let activate = match get j "activate" with `Null -> None | v -> Some (z v) in
 match V.make_in ~cap:(n (get j "cap")) ~activate ~epoch:(z (get j "epoch")) (get j "inputs" |> to_list |> List.map lit) with
 | Error e -> err (V.text e)
 | Ok vm ->
   let result = V.run vm (get j "code" |> to_list |> List.map op |> Array.of_list) in
   `Assoc ["error", (match result with Ok () -> `Null | Error e -> str (V.text e));
     "pc", int (V.pc vm); "steps", int (V.steps vm); "work", num (V.work vm);
     "halted", `Bool (V.halted vm); "registers", `List (List.init 8 (fun n -> lit_json (V.value vm n)));
     "closes", `List (List.map (fun (a,b) -> `List [int (N.to_int a);int (N.to_int b)]) (V.closes vm))]
let layer j = match to_list j with
| [tag; `String "base"] -> G.base ~tag:(nat tag)
| [tag; `String "prod"; left; right] -> G.prod ~tag:(nat tag) ~left:(nat left) ~right:(nat right)
| _ -> invalid_arg "oracle graph layer"
let layer_json (v:G.layer) = `List (int (N.to_int v.tag) :: (match v.rule with G.Base -> [str "base"] | G.Prod (a,b) -> [str "prod";int (N.to_int a);int (N.to_int b)]))
let edge j = match to_list j with
| [layer; index; sign; weight; sigma] -> G.edge ~layer:(nat layer) ~index:(nat index) ~sign:(if to_string sign = "+" then G.Pos else G.Neg) ~weight:(to_list weight |> List.map z) ~sigma:(to_list sigma |> List.map to_bool)
| _ -> invalid_arg "oracle graph edge"
let edge_json (v:G.edge) = `List [int (N.to_int v.layer);int (N.to_int v.index);str (match v.sign with G.Pos -> "+" | G.Neg -> "-");`List (List.map num v.weight);`List (List.map (fun b -> `Bool b) v.sigma)]
let rec edges acc = function [] -> Ok (List.rev acc) | v::rest -> match edge v with Error e -> Error e | Ok v -> edges (v::acc) rest
let graph j =
 match G.cfg ~basis:(nat (get j "basis")) ~slots:(nat (get j "slots")) ~sigma:(nat (get j "sigma")) ~edge_cap:(z (get j "cap")) with
 | Error e -> err (G.text e)
 | Ok cfg -> match edges [] (get j "edges" |> to_list) with
 | Error e -> err (G.text e)
 | Ok edges ->
 let graph = G.graph (get j "layers" |> to_list |> List.map layer) edges in
 let depth = match G.mul_depth graph with Ok n -> int (N.to_int n) | Error e -> err (G.text e) in
 let norm = match G.norm cfg graph with Error e -> err (G.text e) | Ok info ->
  `Assoc ["merged",`Bool info.merged;"layers",`List (List.map layer_json info.graph.layers);"edges",`List (List.map edge_json info.graph.edges);"layer_count",num info.layer_count;"edge_count",num info.edge_count;"removed",num info.removed] in
 `Assoc ["valid",`Bool (G.valid cfg graph);"depth",depth;"norm",norm]
let entropy j = match E.plan E.prod (nat (get j "depth")) with
 | Error e -> err (E.text e)
 | Ok v -> `Assoc ["depth",int (N.to_int v.depth);"cap",num v.cap;"binary",num v.n2;"ternary",num v.n3;"groups",num v.groups;"edges",num v.edges]
let run j = try match get j "kind" |> to_string with "vm" -> vm j | "graph" -> graph j | "entropy" -> entropy j | _ -> invalid_arg "oracle operation" with Invalid_argument s -> err s
let () =
 let input = Yojson.Safe.from_channel stdin |> to_list in
 let rows = List.map (fun input -> `Assoc ["input",input;"expected",run input]) input in
 print_endline (Yojson.Safe.to_string (`List rows))
