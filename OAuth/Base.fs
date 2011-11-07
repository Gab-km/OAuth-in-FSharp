module OAuth.Base

open System
open System.Text
open OAuth.Utilities

type ParameterKeyValue = KeyValue of string * string

type HashAlgorithm = HMACSHA1 | PLAINTEXT | RSASHA1

type HttpMethod = GET | POST

type ConsumerInfo = { consumerKey : string; consumerSecret : string }
type RequestInfo = { requestToken : string; requestSecret : string }

let makeParameterKeyValue key value = KeyValue (key, value)

let keyValueMany tupleList = List.map KeyValue tupleList

let headerKeyValue oParams =
    match oParams with
    | x::xs ->
        oParams
        |> List.map (fun (KeyValue (key, value)) ->
                        key + "=\"" + value + "\"")
        |> List.fold (concatStringsWithToken ", ") ""
    | _ -> ""

let parameterize keyValue =
    let (KeyValue (key, value)) = keyValue
    key + "=" + (urlEncode value)

let toParameter oParams =
    let keyValues = oParams |> List.map parameterize
    match keyValues with
    | x::y::xs ->  List.fold (concatStringsWithToken "&") "" keyValues
    | x::xs -> x + "&"
    | _ -> ""

let fromKeyValue (keyValueString : string) =
    keyValueString.Split [|'&'|]
    |> List.ofArray
    |> List.map ((fun (s : string) -> s.Split [|'='|] ) >>
                (fun kv -> makeParameterKeyValue kv.[0] kv.[1]))

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
    let sortParameters = List.sortBy (fun (KeyValue (key, value)) -> key)
    let arrangedParams = oauthParameter
                        |> sortParameters
                        |> toParameter
                        |> urlEncode
    meth + "&" + sanitizedUrl + "&" + arrangedParams

let makeKeyValueTuplesForGenerateHeader consumerInfo requestInfo pinCode =
    let { consumerKey=consumerKey; consumerSecret=_ } = consumerInfo
    let keyValues = [("oauth_consumer_key", consumerKey);
                    ("oauth_nonce", generateNonce ());
                    ("oauth_signature_method", "HMAC-SHA1");
                    ("oauth_timestamp", generateTimeStamp ())]
    match (requestInfo, pinCode) with
    | (Some rInfo, Some pCode) ->
        let { requestToken=requestToken; requestSecret=_ } = rInfo
        ("oauth_token", requestToken)::("oauth_verifier", pCode)::keyValues
    | _ -> keyValues

let generateAuthorizationHeaderForRequestToken target httpMethod consumerInfo =
    let keyValues = (consumerInfo, None, None)
                    |||> makeKeyValueTuplesForGenerateHeader
                    |> List.map (fun (key, value) -> (key, urlEncode value))
    let baseString = keyValues
                    |> keyValueMany
                    |> assembleBaseString httpMethod target
    let signature = generateSignatureWithHMACSHA1 [consumerInfo.consumerSecret] baseString
    let oParamsWithSignature =
        ("oauth_signature", signature) :: keyValues
        |> keyValueMany
        |> headerKeyValue
    "OAuth " + oParamsWithSignature

let generateAuthorizationHeaderForAccessToken target httpMethod consumerInfo requestInfo pinCode =
    let keyValues = (consumerInfo, Some requestInfo, Some pinCode)
                    |||> makeKeyValueTuplesForGenerateHeader
                    |> List.map (fun (key, value) -> (key, urlEncode value))
    let baseString = keyValues
                    |> keyValueMany
                    |> assembleBaseString httpMethod target
    let signature = generateSignatureWithHMACSHA1 [consumerInfo.consumerSecret;
                                                    requestInfo.requestSecret] baseString
    let oParamsWithSignature =
        ("oauth_signature", signature) :: keyValues
        |> keyValueMany
        |> headerKeyValue
    "OAuth " + oParamsWithSignature
