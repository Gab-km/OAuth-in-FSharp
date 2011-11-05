module OAuth.APIs

open System
open System.Text
open OAuth.ExtendedWebClient

type OAuthParameter = OAuthParameter of string * string

type HashAlgorithm = HMACSHA1 | PLAINTEXT | RSASHA1
type SignatureParameter = { consumer_key : string; token_secret : string option }

type HttpMethod = GET | POST

let parameterize key value = OAuthParameter (key, value)

let parameterizeMany kvList = List.map (fun (key, value) -> parameterize key value) kvList

let urlEncode (urlString : string) =
    let urlChars = List.ofSeq urlString
    let encodeChar c =
        let validChars = List.ofSeq "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~"
        if List.exists (fun v -> v = c) validChars then c.ToString()
            else
                let bt = Text.Encoding.ASCII.GetBytes (c.ToString ())
                String.Format ("%{0:X2}", bt.[0])
    urlChars
    |> List.map encodeChar
    |> List.fold (fun s1 s2 -> s1 + s2) ""

let concatStringsWithToken token s1 s2 =
    if s1 = "" then s2 else s1 + token + s2

let headerKeyValue oParams =
    match oParams with
    | x::xs -> oParams
                |> List.map (fun (OAuthParameter (key, value)) ->
                                key + "=\"" + value + "\"")
                |> List.fold (concatStringsWithToken ", ") ""
    | _ -> ""

let keyValue oParam =
    match oParam with
    | OAuthParameter (key, value) -> key + "=" + (urlEncode value)

let keyValueMany oParams =
    let keyValues = oParams |> List.map keyValue
    match keyValues with
    | x::y::xs ->  List.fold (concatStringsWithToken "&") "" keyValues
    | x::xs -> x + "&"
    | _ -> ""

let generateNonce () =
    DateTime.Now.Ticks.ToString ()

let generateTimeStamp () =
    ((DateTime.UtcNow - DateTime (1970, 1, 1, 0, 0, 0, 0)).TotalSeconds
     |> Convert.ToInt64).ToString ()

let makeSignatureParameter consumerKey tokenSecret =
    { consumer_key=consumerKey; token_secret=tokenSecret }

let concatSecretKeys = function
    | x::y::xs -> List.fold (concatStringsWithToken "&") "" (x::y::xs)
    | x::xs -> x + "&"
    | _ -> ""

let generateSignature algorithmType secretKeys (baseString : string) =
    let keysParam = secretKeys |> concatSecretKeys |> Encoding.ASCII.GetBytes
    match algorithmType with
    | HMACSHA1 ->
        use algorithm =
            new System.Security.Cryptography.HMACSHA1 (keysParam)
        baseString
        |> Encoding.ASCII.GetBytes
        |> algorithm.ComputeHash
        |> Convert.ToBase64String
        |> urlEncode
    | PLAINTEXT ->
        baseString
        |> urlEncode
    | RSASHA1 -> raise (NotImplementedException("'RSA-SHA1' algorithm is not implemented."))

let generateSignatureWithHMACSHA1 = generateSignature HMACSHA1
let generateSignatureWithPLAINTEXT = generateSignature PLAINTEXT
let generateSignatureWithRSASHA1 = generateSignature RSASHA1

let getHttpMethodString = function
    | GET -> "GET"
    | POST -> "POST"

let assembleBaseString meth targetUrl oauthParameter =
    let sanitizedUrl = targetUrl |> urlEncode
    let sortParameters = List.sortBy (fun (OAuthParameter (key, value)) -> key)
    let arrangedParams = oauthParameter
                        |> sortParameters
                        |> keyValueMany
                        |> urlEncode
    meth + "&" + sanitizedUrl + "&" + arrangedParams

let generateAuthorizationHeaderForRequestToken target httpMethod consumerKey secretKeys =
    let oParams = [("oauth_consumer_key", consumerKey);
                    ("oauth_nonce", generateNonce ());
                    ("oauth_signature_method", "HMAC-SHA1");
                    ("oauth_timestamp", generateTimeStamp ())]
                    |> List.sortBy (fun (key, value) -> key)
                    |> List.map (fun (key, value) -> (key, urlEncode value))
    let baseString = oParams
                    |> parameterizeMany
                    |> assembleBaseString httpMethod target
    let signature = generateSignatureWithHMACSHA1 secretKeys baseString
    let oParamsWithSignature =
        ("oauth_signature", signature) :: oParams
        |> parameterizeMany
        |> headerKeyValue
    "OAuth " + oParamsWithSignature

let getRequestToken target httpMethod consumerKey secretKeys =
    async {
        let wc = new System.Net.WebClient ()
        let url = Uri (target)
        let meth = getHttpMethodString httpMethod
        let header = generateAuthorizationHeaderForRequestToken target meth consumerKey secretKeys
        wc.Headers.Add ("Authorization", header)
        let! result = wc.AsyncUploadString url meth ""
        return result
    } |> Async.RunSynchronously