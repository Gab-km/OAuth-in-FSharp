module OAuth

open System
open System.Text

type OAuthParameter = OAuthParameter of string * string

type HashAlgorithm = HMACSHA1 | PLAINTEXT
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

let generateSignature algorithmType sigParam (baseString : string) =
    let genAlgorithmParam = function
        | { consumer_secret=cs; token_secret=Some(ts) } ->
            cs + "&" + ts
            |> Encoding.ASCII.GetBytes
        | { consumer_secret=cs; token_secret=_ } ->
            cs + "&"
            |> Encoding.ASCII.GetBytes
    match algorithmType with
    | HMACSHA1 ->
        use algorithm = new System.Security.Cryptography.HMACSHA1 (sigParam |> genAlgorithmParam)
        baseString
        |> Encoding.ASCII.GetBytes
        |> algorithm.ComputeHash
        |> Convert.ToBase64String
    | PLAINTEXT ->
        baseString
        |> System.Web.HttpUtility.HtmlEncode
        
