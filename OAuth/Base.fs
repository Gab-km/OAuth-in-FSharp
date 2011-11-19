namespace OAuth

module Base =

    open System
    open System.Text
    open OAuth.Utilities
    open OAuth.Types

    let keyValueMany tupleList = List.map KeyValue tupleList

    let headerParameter keyValues =
        match keyValues with
        | [] -> ""
        | _ ->
            keyValues
            |> List.map (fun (KeyValue (key, value)) ->
                            key + "=\"" + value + "\"")
            |> List.fold (concatStringsWithToken ", ") ""

    let parameterize encode keyValue =
        let (KeyValue (key, value)) = keyValue
        key + "=" + (urlEncode encode value)

    let toParameter encode keyValues =
        let parameterized = keyValues |> List.map (parameterize encode)
        match parameterized with
        | x::y::xs ->  List.fold (concatStringsWithToken "&") "" parameterized
        | x::xs -> x + "&"
        | _ -> ""

    let fromParameter (parameterString : string) =
        parameterString.Split [|'&'|]
        |> List.ofArray
        |> List.map ((fun (s : string) -> s.Split [|'='|] ) >>
                    (fun kv -> KeyValue (kv.[0], kv.[1])))

    let tryGetValue key keyValues =
        List.tryPick (fun (KeyValue (k, v)) ->
                    if k = key then Some v else None) keyValues

    let inline generateNonce () = DateTime.Now.Ticks.ToString ()

    let generateTimeStamp () =
        ((DateTime.UtcNow - DateTime (1970, 1, 1, 0, 0, 0, 0)).TotalSeconds
         |> Convert.ToInt64).ToString ()

    let generateSignature encode algorithmType secretKeys (baseString : string) =
        let keysParam = secretKeys |> concatSecretKeys |> Encoding.ASCII.GetBytes
        match algorithmType with
        | HMACSHA1 ->
            use algorithm = new System.Security.Cryptography.HMACSHA1 (keysParam)
            baseString
            |> Encoding.ASCII.GetBytes
            |> algorithm.ComputeHash
            |> Convert.ToBase64String
            |> urlEncode encode
        | PLAINTEXT -> baseString |> urlEncode encode
        | RSASHA1 -> raise (NotImplementedException("'RSA-SHA1' algorithm is not implemented."))

    let inline generateSignatureWithHMACSHA1 encode secretKeys baseString = generateSignature encode HMACSHA1 secretKeys baseString
    let inline generateSignatureWithPLAINTEXT encode secretKeys baseString = generateSignature encode PLAINTEXT secretKeys baseString
    let inline generateSignatureWithRSASHA1 encode secretKeys baseString = generateSignature encode RSASHA1 secretKeys baseString

    let getHttpMethodString = function
        | GET -> "GET"
        | POST -> "POST"

    let assembleBaseString encode meth targetUrl keyValues =
        let sanitizedUrl = targetUrl |> urlEncode encode
        let sorKeyValues = List.sortBy (fun (KeyValue (key, value)) -> key)
        let arrangedParams = keyValues
                            |> sorKeyValues
                            |> toParameter encode
                            |> urlEncode encode
        meth + "&" + sanitizedUrl + "&" + arrangedParams

    let makeKeyValueTuplesForGenerateHeader useFor =
        let keyValues = [("oauth_nonce", generateNonce ());
                        ("oauth_signature_method", "HMAC-SHA1");
                        ("oauth_timestamp", generateTimeStamp ())]
        match useFor with
        | ForRequestToken (consumerInfo) ->
            ("oauth_consumer_key", consumerInfo.consumerKey)::keyValues
        | ForAccessToken (consumerInfo, requestInfo, pinCode) ->
            ("oauth_consumer_key", consumerInfo.consumerKey)::
            ("oauth_token", requestInfo.requestToken)::
            ("oauth_verifier", pinCode)::
            keyValues
        | ForWebService (consumerInfo, accessInfo, _) ->
            ("oauth_consumer_key", consumerInfo.consumerKey)::
            ("oauth_token", accessInfo.accessToken)::
            keyValues

    let generateAuthorizationHeader encode targetUrl httpMethod useFor =
        let keyValues = useFor
                        |> makeKeyValueTuplesForGenerateHeader
                        |> List.map (fun (key, value) -> (key, urlEncode encode value))
        let baseString = match useFor with
                            | ForWebService (_, _, Some (key, value)) -> (key, value) :: keyValues
                            | _ -> keyValues
                            |> keyValueMany
                            |> assembleBaseString encode httpMethod targetUrl
        let secretKeys =
            match useFor with
            | ForRequestToken (consumerInfo) -> [consumerInfo.consumerSecret]
            | ForAccessToken (consumerInfo, requestInfo, pinCode) -> [consumerInfo.consumerSecret; requestInfo.requestSecret]
            | ForWebService (consumerInfo, accessInfo, _) -> [consumerInfo.consumerSecret; accessInfo.accessSecret]
        let signature = generateSignatureWithHMACSHA1 encode secretKeys baseString
        let oParamsWithSignature =
            ("oauth_signature", signature) :: keyValues
            |> keyValueMany
            |> headerParameter
        "OAuth " + oParamsWithSignature

    let generateAuthorizationHeaderForRequestToken encode targetUrl httpMethod consumerInfo =
        generateAuthorizationHeader encode targetUrl httpMethod (ForRequestToken consumerInfo)

    let generateAuthorizationHeaderForAccessToken encode targetUrl httpMethod consumerInfo requestInfo pinCode =
        generateAuthorizationHeader encode targetUrl httpMethod (ForAccessToken (consumerInfo, requestInfo, pinCode))

    let generateAuthorizationHeaderForWebService encode targetUrl httpMethod consumerInfo accessInfo =
        generateAuthorizationHeader encode targetUrl httpMethod (ForWebService (consumerInfo, accessInfo, None))

    let generateAuthorizationHeaderForWebServiceWithData encode targetUrl httpMethod consumerInfo accessInfo data =
        generateAuthorizationHeader encode targetUrl httpMethod (ForWebService (consumerInfo, accessInfo, Some ("status",data)))
