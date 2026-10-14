"""Candidate native query ownership fix; no wire, validation or consensus changes."""
REPLACEMENTS={'lib/consensus/c_driver.ml':[
 {'before':'  bundle_responses : (string, bundle_response_record list) Hashtbl.t;','after':'  bundle_responses : (string, bundle_response_record list) Hashtbl.t;\n  bundle_query_gates : (string, Lwt_mutex.t * int ref) Hashtbl.t;'},
 {'before':'    bundle_responses = Hashtbl.create 16;','after':'    bundle_responses = Hashtbl.create 16;\n    bundle_query_gates = Hashtbl.create 16;'},
 {'before':'let query_bundle t ~epoch_id ~proposal_id ~timeout_seconds','after':'let query_bundle_unlocked t ~epoch_id ~proposal_id ~timeout_seconds'},
 {'before':'''  Hashtbl.remove t.bundle_responses proposal_id;
  Lwt.return result

let query_catchup_range''','after':'''  Lwt.return result

let query_bundle t ~epoch_id ~proposal_id ~timeout_seconds ~validate =
  let gate, users =
    match Hashtbl.find_opt t.bundle_query_gates proposal_id with
    | Some owned -> owned
    | None ->
      let owned = Lwt_mutex.create (), ref 0 in
      Hashtbl.add t.bundle_query_gates proposal_id owned;
      owned
  in
  incr users;
  Lwt.finalize
    (fun () -> Lwt_mutex.with_lock gate (fun () ->
      Lwt.finalize
        (fun () -> query_bundle_unlocked t
          ~epoch_id ~proposal_id ~timeout_seconds ~validate)
        (fun () ->
          Hashtbl.remove t.bundle_responses proposal_id;
          Lwt.return_unit)))
    (fun () ->
      decr users;
      if !users = 0 then Hashtbl.remove t.bundle_query_gates proposal_id;
      Lwt.return_unit)

let query_catchup_range'''}]}
