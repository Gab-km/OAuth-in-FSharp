module OAuth

open System
open System.Text
open System.Web

type OAuthParameter = OAuthParameter of string * string

type HashAlgorithm = HMACSHA1 | PLAINTEXT | RSASHA1
type SignatureParameter = { consumer_secret : string; token_secret : string option }

type HttpMethod = GET | HEAD | POST | PUT | DELETE | OPTIONS | TRACE | CONNECT | PATCH

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
    ((DateTime.UtcNow - DateTime (1970, 1, 1, 0, 0, 0, 0)).TotalSeconds
     |> Convert.ToInt64).ToString ()

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
        |> System.Web.HttpUtility.HtmlEncode
        |> Encoding.ASCII.GetBytes
        |> algorithm.ComputeHash
        |> Convert.ToBase64String
    | PLAINTEXT ->
        baseString
        |> HttpUtility.HtmlEncode
    | RSASHA1 -> raise (NotImplementedException("'RSA-SHA1' algorithm is not implemented."))

let generateSignatureWithHMACSHA1 = generateSignature HMACSHA1
let generateSignatureWithPLAINTEXT = generateSignature PLAINTEXT
let generateSignatureWithRSASHA1 = generateSignature RSASHA1

let getHttpMethodString = function
    | GET -> "GET"
    | HEAD -> "HEAD"
    | POST -> "POST"
    | PUT -> "PUT"
    | DELETE -> "DELETE"
    | OPTIONS -> "OPTIONS"
    | TRACE -> "TRACE"
    | CONNECT -> "CONNECT"
    | PATCH -> "PATCH"

let assembleBaseString httpMethod targetUrl oauthParameter =
    let meth =getHttpMethodString httpMethod
    let sanitizedUrl = targetUrl |> HttpUtility.HtmlEncode
    let sortParameters = List.sortBy (fun (OAuthParameter (key, value)) -> key)
    let sanitizeAndSetParameters = function
        | OAuthParameter (key, value) -> key + "=" + (HttpUtility.HtmlEncode value)
    let arrangedParams = oauthParameter
                        |> sortParameters
                        |> List.map sanitizeAndSetParameters
                        |> List.fold (fun s t -> if s = "" then t else s + "&" + t) ""
    meth + "&" + sanitizedUrl + "&" + arrangedParams