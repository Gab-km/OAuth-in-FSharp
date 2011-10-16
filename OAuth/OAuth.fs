module OAuth.APIs

open System
open System.Text
open System.Web
open OAuth.ExtendedWebClient

type OAuthParameter = OAuthParameter of string * string

type HashAlgorithm = HMACSHA1 | PLAINTEXT | RSASHA1
type SignatureParameter = { consumer_key : string; token_secret : string option }

type HttpMethod = GET | POST

let parameterize key value = OAuthParameter (key, value)

let parameterizeMany kvList = List.map (fun (key, value) -> parameterize key value) kvList

let keyValue oParam =
    match oParam with
    | OAuthParameter (key, value) -> key + "=" + (HttpUtility.HtmlEncode value)

let keyValueMany oParams =
    let keyValues = oParams |> List.map keyValue
    match keyValues with
    | x::y::xs ->  List.fold (fun s t -> if s = "" then t else s + "&" + t) "" keyValues
    | x::xs -> x + "&"
    | _ -> ""

let generateNonce () =
    DateTime.Now.Ticks.ToString ()

let generateTimeStamp () =
    ((DateTime.UtcNow - DateTime (1970, 1, 1, 0, 0, 0, 0)).TotalSeconds
     |> Convert.ToInt64).ToString ()

let makeSignatureParameter consumerKey tokenSecret =
    { consumer_key=consumerKey; token_secret=tokenSecret }

let generateSignature algorithmType sigParam (baseString : string) =
    let genAlgorithmParam = function
        | { consumer_key=cs; token_secret=Some(ts) } ->
            cs + "&" + ts
            |> Encoding.ASCII.GetBytes
        | { consumer_key=cs; token_secret=_ } ->
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
    | POST -> "POST"

let assembleBaseString httpMethod targetUrl oauthParameter =
    let meth =getHttpMethodString httpMethod
    let sanitizedUrl = targetUrl |> HttpUtility.HtmlEncode
    let sortParameters = List.sortBy (fun (OAuthParameter (key, value)) -> key)
    let arrangedParams = oauthParameter
                        |> sortParameters
                        |> keyValueMany
    meth + "&" + sanitizedUrl + "&" + arrangedParams

let generateAuthorizationHeaderForRequestToken consumerKey =
    let baseString = parameterizeMany [("oauth_consumer_key", consumerKey)]
                    |> assembleBaseString POST "http://hoge.com"
    let signature = makeSignatureParameter consumerKey None
                    |> generateSignatureWithHMACSHA1 <| baseString
    let oParams = [("oauth_consumer_key", consumerKey);
                    ("oauth_nonce", generateNonce ());
                    ("oauth_signature", signature);
                    ("oauth_signature_method", "HMACSHA1");
                    ("oauth_timestamp", generateTimeStamp ())]
                    |> parameterizeMany
                    |> keyValueMany
    "OAuth " + oParams

let getRequestToken target consumerKey =
    async {
        let wc = new System.Net.WebClient ()
        wc.Headers.Add ("Authorization", (generateAuthorizationHeaderForRequestToken consumerKey))
        let! result = wc.AsyncUploadString (new Uri (target)) "POST" ""
        return result
    } |> Async.RunSynchronously