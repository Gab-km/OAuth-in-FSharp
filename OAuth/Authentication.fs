namespace OAuth.Core

module Authentication =
    open System
    open System.Text
    open OAuth.Utilities
    open OAuth.Types
    open OAuth.Core.Base
        
    [<CompiledName("GenerateNonce")>]
    let inline generateNonce () = DateTime.Now.Ticks.ToString ()

    [<CompiledName("GenerateTimeStamp")>]
    let generateTimeStamp () =
        ((DateTime.UtcNow - DateTime (1970, 1, 1, 0, 0, 0, 0)).TotalSeconds
         |> Convert.ToInt64).ToString ()

    [<CompiledName("GenerateSignature")>]
    let generateSignature (encoder : string -> string) algorithmType secretKeys (baseString : string) =
        let keysParam = secretKeys |> concatSecretKeys |> Encoding.ASCII.GetBytes
        match algorithmType with
        | HMACSHA1 ->
            use algorithm = new System.Security.Cryptography.HMACSHA1 (keysParam)
            baseString
            |> Encoding.ASCII.GetBytes
            |> algorithm.ComputeHash
            |> Convert.ToBase64String
            |> encoder
        | PLAINTEXT -> baseString |> encoder
        | RSASHA1 -> raise (NotImplementedException("'RSA-SHA1' algorithm is not implemented."))

    [<CompiledName("GenerateSignatureWithHMACSHA1")>]
    let inline generateSignatureWithHMACSHA1 encoder secretKeys baseString = generateSignature encoder HMACSHA1 secretKeys baseString
    
    [<CompiledName("GenerateSignatureWithPLAINTEXT")>]
    let inline generateSignatureWithPLAINTEXT encoder secretKeys baseString = generateSignature encoder PLAINTEXT secretKeys baseString
    
    [<CompiledName("GenerateSignatureWithRSASHA1")>]
    let inline generateSignatureWithRSASHA1 encoder secretKeys baseString = generateSignature encoder RSASHA1 secretKeys baseString

    [<CompiledName("AssembleBaseString")>]
    let assembleBaseString requirement keyValues =
        let (Requirement (encoding, targetUrl, httpMethod)) = requirement
        let encoder = urlEncode encoding
        let sanitizedUrl = targetUrl |> encoder
        let sorKeyValues = List.sortBy (fun (KeyValue (key, value)) -> key)
        let meth = getHttpMethodString httpMethod
        let arrangedParams = keyValues
                            |> sorKeyValues
                            |> toParameter encoder
                            |> encoder
        meth + "&" + sanitizedUrl + "&" + arrangedParams

    [<CompiledName("MakeStringPairForGenerateHeader")>]
    let makeStringPairForGenerateHeader useFor =
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

    [<CompiledName("GenerateAuthorizationHeader")>]
    let generateAuthorizationHeader requirement useFor =
        let (Requirement (encoding, _, _)) = requirement
        let encoder = urlEncode encoding
        let keyValuePair = useFor
                        |> makeStringPairForGenerateHeader
                        |> List.map (fun (key, value) -> (key, encoder value))
        let baseString = match useFor with
                            | ForWebService (_, _, kvs) -> kvs
                            | _ -> []
                            |> List.append (toKeyValue keyValuePair)
                            |> assembleBaseString requirement
        let secretKeys =
            match useFor with
            | ForRequestToken (consumerInfo) -> [consumerInfo.consumerSecret]
            | ForAccessToken (consumerInfo, requestInfo, pinCode) -> [consumerInfo.consumerSecret; requestInfo.requestSecret]
            | ForWebService (consumerInfo, accessInfo, _) -> [consumerInfo.consumerSecret; accessInfo.accessSecret]
        let signature = generateSignatureWithHMACSHA1 encoder secretKeys baseString
        let oParamsWithSignature =
            ("oauth_signature", signature) :: keyValuePair
            |> toKeyValue
            |> headerParameter
        "OAuth " + oParamsWithSignature

    [<CompiledName("GenerateAuthorizationHeaderForRequestToken")>]
    let generateAuthorizationHeaderForRequestToken requirement consumerInfo =
        generateAuthorizationHeader requirement (ForRequestToken consumerInfo)

    [<CompiledName("GenerateAuthorizationHeaderForAccessToken")>]
    let generateAuthorizationHeaderForAccessToken requirement consumerInfo requestInfo pinCode =
        generateAuthorizationHeader requirement (ForAccessToken (consumerInfo, requestInfo, pinCode))

    [<CompiledName("GenerateAuthorizationHeaderForWebService")>]
    let generateAuthorizationHeaderForWebService requirement consumerInfo accessInfo param =
        generateAuthorizationHeader requirement (ForWebService (consumerInfo, accessInfo, param))
