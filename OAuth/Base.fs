module OAuth.Base

open System
open System.Text
open OAuth.Utilities

type OAuthParameter = OAuthParameter of string * string

type HashAlgorithm = HMACSHA1 | PLAINTEXT | RSASHA1

type HttpMethod = GET | POST

type ConsumerInfo = { consumerKey : string; consumerSecret : string }
type RequestInfo = { requestToken : string; requestSecret : string }

let parameterize key value = OAuthParameter (key, value)

let parameterizeMany kvList = List.map (fun (key, value) -> parameterize key value) kvList

let headerKeyValue oParams =
    match oParams with
    | x::xs ->
        oParams
        |> List.map (fun (OAuthParameter (key, value)) ->
                        key + "=\"" + value + "\"")
        |> List.fold (concatStringsWithToken ", ") ""
    | _ -> ""

let keyValue oParam =
    let (OAuthParameter (key, value)) = oParam
    key + "=" + (urlEncode value)

let keyValueMany oParams =
    let keyValues = oParams |> List.map keyValue
    match keyValues with
    | x::y::xs ->  List.fold (concatStringsWithToken "&") "" keyValues
    | x::xs -> x + "&"
    | _ -> ""

let fromKeyValue (keyValueString : string) =
    keyValueString.Split [|'&'|]
    |> List.ofArray
    |> List.map ((fun (s : string) -> s.Split [|'='|] ) >>
                (fun kv -> parameterize kv.[0] kv.[1]))

let inline generateNonce () = DateTime.Now.Ticks.ToString ()

let generateTimeStamp () =
    ((DateTime.UtcNow - DateTime (1970, 1, 1, 0, 0, 0, 0)).TotalSeconds
     |> Convert.ToInt64).ToString ()

let generateSignature algorithmType secretKeys (baseString : string) =
    let keysParam = secretKeys |> concatSecretKeys |> Encoding.ASCII.GetBytes
    match algorithmType with
    | HMACSHA1 ->
        use algorithm = new System.Security.Cryptography.HMACSHA1 (keysParam)
        baseString
        |> Encoding.ASCII.GetBytes
        |> algorithm.ComputeHash
        |> Convert.ToBase64String
        |> urlEncode
    | PLAINTEXT -> baseString |> urlEncode
    | RSASHA1 -> raise (NotImplementedException("'RSA-SHA1' algorithm is not implemented."))

let inline generateSignatureWithHMACSHA1 secretKeys baseString = generateSignature HMACSHA1 secretKeys baseString
let inline generateSignatureWithPLAINTEXT secretKeys baseString = generateSignature PLAINTEXT secretKeys baseString
let inline generateSignatureWithRSASHA1 secretKeys baseString = generateSignature RSASHA1 secretKeys baseString

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

let makeOParamsForGenerateHeader consumerInfo requestInfo pinCode =
    let { consumerKey=consumerKey; consumerSecret=_ } = consumerInfo
    let oParams = [("oauth_consumer_key", consumerKey);
                    ("oauth_nonce", generateNonce ());
                    ("oauth_signature_method", "HMAC-SHA1");
                    ("oauth_timestamp", generateTimeStamp ())]
    match (requestInfo, pinCode) with
    | (Some rInfo, Some pCode) ->
        let { requestToken=requestToken; requestSecret=_ } = rInfo
        ("oauth_token", requestToken)::("oauth_verifier", pCode)::oParams
    | _ -> oParams

let generateAuthorizationHeaderForAccessToken target httpMethod consumerKey requestToken pinCode secretKeys =
    let oParams = [("oauth_consumer_key", consumerKey);
                    ("oauth_token", requestToken);
                    ("oauth_verifier", pinCode);
                    ("oauth_nonce", generateNonce ());
                    ("oauth_signature_method", "HMAC-SHA1");
                    ("oauth_timestamp", generateTimeStamp ())]
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
