module OAuth

open System
open System.Text
open System.Security.Cryptography

type OAuthParameter = OAuthParameter of string * string

type SignatureParameter = { consumer_secret : string; token_secret : string option }

let parameterize key value = OAuthParameter (key, value)

let parameterizeMany kvList = List.map (fun (key, value) -> parameterize key value) kvList

let keyValue oParam =
    match oParam with
    | OAuthParameter (key, value) -> key + "=" + value

let keyValueMany oParams =
    oParams
    |> List.map keyValue
    |> List.fold (fun s t -> if s = "" then t else s + "&" + t) ""

let generateNonce () =
    DateTime.Now.Ticks.ToString ()

let generateTimeStamp () =
    DateTime.UtcNow - DateTime (1970, 1, 1, 0, 0, 0, 0)
    |> fun ts -> ts.TotalSeconds
    |> Convert.ToInt64
    |> fun l -> l.ToString ()

let generateSignature sigParam =
    let genAlgorithmParam = function
        | { consumer_secret=cs; token_secret=Some(ts) } ->
            cs + "&" + ts
            |> Encoding.ASCII.GetBytes
        | { consumer_secret=cs; token_secret=_ } ->
            cs + "&"
            |> Encoding.ASCII.GetBytes
    new HMACSHA1 (sigParam |> genAlgorithmParam)
