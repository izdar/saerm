(* Heavily borrowed from Kind 2 *)

let ok v = Ok v

let error e = Error e

let bind r f = match r with Ok v -> f v | Error _ as e -> e

let (>>=) = fun r f -> bind r f 

let (>>) = fun r1 r2 -> bind r1 (fun _ -> r2)

let join = function Ok r -> r | Error _ as e -> e

let map f = function Ok v -> Ok (f v) | Error _ as e -> e

let rec seq: ('a, 'e) result list -> ('a list, 'e) result  =
  function
  | [] -> ok []
  | h :: t -> h >>= fun h' -> 
              seq t >>= fun t' ->
              ok (h' :: t')

let rec seq_chain: ('a -> 'b -> ('a, 'e) result) -> 'a -> 'b list -> ('a, 'e) result =
  fun f e -> function
  | [] -> ok e
  | h :: t -> f e h >>= fun e' -> 
              seq_chain f e' t

let ifM: (bool, 'e) result -> ('a, 'e) result -> ('a, 'e) result -> ('a, 'e) result
  = fun cond p1 p2 -> cond >>= (fun cond_true -> if cond_true then p1 else p2)

let guard_with: (bool, 'e) result -> (unit, 'e) result -> (unit, 'e) result
  = fun cond p -> cond >>= (fun cond_true -> if cond_true then ok () else p)
                    
let foldM: ('a -> 'b -> 'a) -> 'a -> ('b list, 'e) result -> ('a, 'e) result
  = fun f e l -> map (List.fold_left f e) l

let seqM: ('a -> 'b -> 'a) -> 'a -> ('b, 'e) result list -> ('a, 'e) result
  = fun f e m -> foldM f e (seq m)  

let seq_: (unit, 'e) result list -> (unit, 'e) result  =
  fun m -> seqM (fun _ _ -> ()) () m

let safe_unwrap: 'a -> ('a, 'e) result -> 'a =
  fun d -> function
        | Ok v -> v
        | _ -> d
             
(** Unwraps a result. *)
let unwrap = function
  | Ok arg -> arg
  | Error err ->
    Format.printf "%t" err ;
    Invalid_argument "Res.unwrap" |> raise

(** Maps functions to [Ok] or [Err]. *)
let map_res f_ok f_err = function
  | Ok arg -> Ok (f_ok arg)
  | Error err -> Error (f_err err)
  
let identity = fun a -> a

(** Maps a function to a result if it's [Error]. *)
let map_err f = map_res identity f

(** Feeds a result to a function returning a result, propagates if argument's
an error. *)
let chain ?fmt:(fmt = identity) f = function
  | Ok arg -> f arg |> map_err fmt
  | Error err -> Error err

(** Fold over a list of results. *)
let l_fold ?fmt:(fmt = identity) f init =
  let rec loop acc = function
    | head :: tail -> (
      match f acc head with
      | Ok acc -> loop acc tail
      | Error err -> Error (fmt err)
    )
    | [] -> Ok acc
  in
  loop init

(** Map over a list with a result-producing function. *)
let l_map ?fmt:(fmt = identity) f =
  let rec loop pref = function
    | head :: tail -> (
      match f head with
      | Ok res -> loop (res :: pref) tail
      | Error err -> Error (fmt err)
    )
    | [] -> Ok (List.rev pref)
  in
  loop []

(** Iterate over a list with a result-producing function. *)
let l_iter ?fmt:(fmt = identity) f =
  let rec loop = function
    | head :: tail -> (
      match f head with
      | Ok () -> loop tail
      | Error err -> Error (fmt err)
    )
    | [] -> Ok ()
  in
  loop
