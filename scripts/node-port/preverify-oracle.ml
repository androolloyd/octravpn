(* Controlled workers exercise the unchanged native scheduler, not cryptography. *)
open Yojson.Safe.Util
module T = Octra_core.Transaction
module P = Octra_node_runtime.Consensus_preverify_pool
module A = Octra_core.Preverify_availability
let n j k = member k j |> to_int
let s j k = member k j |> to_string
let indices j = member "indices" j |> to_list |> List.map to_int
let tx i : T.t = {
  from="octFrom"; to_="octFrom"; amount=Z.zero; nonce=i+1; ou=Z.of_int 3000;
  timestamp=1.; signature="sig"; public_key=Some "pub"; message=None;
  op_type=(if i=7 then T.Standard else T.KeySwitch); encrypted_data=Some "payload" }
let availability = function
  | A.Unmanaged -> `String "unmanaged" | A.Pending -> `String "pending"
  | A.Ready a -> `Assoc ["ready",`Int a] | A.Invalid e -> `Assoc ["invalid",`String e]
let advance () = Lwt_main.run (let rec loop n = if n=0 then Lwt.return_unit
  else Lwt.bind (Lwt.pause ()) (fun () -> loop (n-1)) in loop 20)
let run input =
  let now=ref 0. and source=ref 1 and mode=ref "source" and calls=ref [] in
  let jobs=Hashtbl.create 8 and waiters=Hashtbl.create 8 in
  let pool=P.create ~now:(fun () -> !now) ~max_running:(n input "running")
    ~max_queued:(n input "queued") ~max_complete:(n input "complete") {
      eligible=(fun t -> t.T.op_type<>T.Standard);
      verify=(fun priority t ->
        let i=t.T.nonce-1 in
        calls:= !calls @ [`List [`Int i;`String (match priority with Octra_core.Compute_pool.Required -> "required" | Octra_core.Compute_pool.Speculative -> "speculative")]];
        let pending,resolve=Lwt.wait () in Hashtbl.replace jobs i (!source,resolve); pending);
      bind=(fun _ artifact -> match !mode with
        | "invalid" -> Lwt.return (P.Source_invalid "invalid proof")
        | "changed" -> Lwt.return P.Source_changed
        | "error" -> Lwt.fail (Failure "binding failed")
        | _ -> Lwt.return (if artifact= !source then P.Bound artifact else P.Source_changed)) } in
  let wrapped p = Lwt.catch (fun () -> p) (function Lwt.Canceled -> Lwt.fail Lwt.Canceled
    | _ -> Lwt.return (`Assoc ["error",`String "binding failed"])) in
  let waiter j p = Hashtbl.replace waiters (s j "id") (wrapped p); `Null in
  let snapshot () =
    let stats=P.stats pool in
    let waits=Hashtbl.fold (fun id p xs -> (id,(match Lwt.state p with
      | Lwt.Sleep -> `String "pending" | Lwt.Return v -> v
      | Lwt.Fail Lwt.Canceled -> `String "cancelled"
      | Lwt.Fail _ -> `Assoc ["error",`String "binding failed"]))::xs) waiters [] |> List.sort compare in
    `Assoc ["stats",`List (List.map (fun n -> `Int n) [stats.pending;stats.queued;stats.running;stats.ready;stats.invalid]);
      "artifacts",`List (List.init 8 (fun i -> match P.artifact pool (tx i) with None -> `Null | Some a -> `Int a));
      "calls",`List !calls; "waiters",`Assoc waits] in
  let results=member "steps" input |> to_list |> List.map (fun j ->
    now:=float_of_int (n j "time");
    let i=n j "index" in
    let result=match s j "kind" with
      | "admit" -> availability (P.admit pool (tx i))
      | "observe" -> Lwt_main.run (wrapped (Lwt.map availability (P.observe pool (tx i))))
      | "wait" -> waiter j (Lwt.map availability (P.await pool (tx i)))
      | "collect" -> waiter j (Lwt.map (fun xs -> `List (List.map (fun (h,a) ->
          let index=List.init 8 Fun.id |> List.find (fun i -> T.hash (tx i)=h) in
          `List [`Int index;`Int a]) xs)) (P.collect pool (List.map tx (indices j))))
      | "cancel" -> Option.iter Lwt.cancel (Hashtbl.find_opt waiters (s j "id")); `Null
      | "source" -> source:=n j "value"; `Null
      | "bind" -> mode:=s j "mode"; `Null
      | "retain" -> let keep=List.map (fun i -> T.hash (tx i)) (indices j) in P.retain pool (fun h -> List.mem h keep); `Null
      | "resolve" -> (match Hashtbl.find_opt jobs i with
          | None -> `Bool false
          | Some (artifact,resolve) ->
            Hashtbl.remove jobs i;
            (match s j "mode" with
              | "error" -> Lwt.wakeup resolve (Error "worker unavailable")
              | "panic" -> Lwt.wakeup_exn resolve (Failure "worker failed")
              | "stale" -> Lwt.wakeup resolve (Ok P.Verification_stale)
              | "rejected" -> Lwt.wakeup resolve (Ok (P.Verification_rejected (artifact,"invalid proof")))
              | _ -> Lwt.wakeup resolve (Ok (P.Verification_ready artifact)));
            `Bool true)
      | _ -> `Null in
    advance (); `Assoc ["result",result; "state",snapshot ()]) in
  Hashtbl.iter (fun _ p -> Lwt.cancel p) waiters;
  `List results
let () =
  let cases=Yojson.Safe.from_channel stdin |> to_list |> List.map (fun input ->
    `Assoc ["input",input;"expected",run input]) in
  Yojson.Safe.to_channel stdout (`List cases); print_newline ()
