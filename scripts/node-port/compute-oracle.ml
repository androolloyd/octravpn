(* Real native queueing/cancellation with controlled asynchronous work. *)
open Yojson.Safe.Util
module P = Octra_core.Compute_pool
let n j k = member k j |> to_int
let s j k = member k j |> to_string
let priority j = if s j "priority"="required" then P.Required else P.Speculative
let advance () = Lwt_main.run (let rec loop n = if n=0 then Lwt.return_unit else Lwt.bind (Lwt.pause ()) (fun () -> loop (n-1)) in loop 20)
let run input =
  let pool=P.create ~capacity:(n input "capacity") ~required_limit:(n input "required")
    ~speculative_limit:(n input "speculative") ~required_burst:(n input "burst") () in
  let jobs=Hashtbl.create 8 and callers=Hashtbl.create 8 and started=ref [] in
  let call id = started:= !started @ [`Int id]; let pending,resolve=Lwt.wait () in
    Hashtbl.add jobs id resolve; pending in
  let snapshot () =
    let stats=P.stats pool in
    let values=Hashtbl.fold (fun id p values ->
      (string_of_int id,(match Lwt.state p with
        | Lwt.Sleep -> `String "pending" | Lwt.Return None -> `Null
        | Lwt.Return (Some v) -> `Int v | Lwt.Fail Lwt.Canceled -> `String "cancelled"
        | Lwt.Fail _ -> `String "failed"))::values) callers [] in
    `Assoc ["stats",`List (List.map (fun n -> `Int n) [stats.active;stats.required_waiting;stats.speculative_waiting;stats.required_streak]);
      "started",`List !started;"callers",`Assoc values] in
  let result=member "steps" input |> to_list |> List.map (fun j ->
    let id=n j "id" in
    let result=match s j "kind" with
      | "start" -> Hashtbl.add callers id (P.run_async pool (priority j) (fun () -> call id)); `Null
      | "cancel" -> Option.iter Lwt.cancel (Hashtbl.find_opt callers id); `Null
      | "resolve" -> (match Hashtbl.find_opt jobs id with None -> `Bool false | Some resolve ->
          Hashtbl.remove jobs id;
          if member "fail" j = `Bool true then Lwt.wakeup_exn resolve (Failure "worker failed") else Lwt.wakeup resolve id;
          `Bool true)
      | "try" -> (match P.try_run_sync pool (priority j) (fun () -> id) with None -> `Null | Some v -> `Int v)
      | _ -> `Null in
    advance (); `Assoc ["result",result;"state",snapshot ()]) in
  Hashtbl.iter (fun _ p -> Lwt.cancel p) callers;
  `List result
let () =
  let cases=Yojson.Safe.from_channel stdin |> to_list |> List.map (fun input ->
    `Assoc ["input",input;"expected",run input]) in
  Yojson.Safe.to_channel stdout (`List cases); print_newline ()
