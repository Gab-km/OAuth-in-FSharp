module OAuth.Core.Scenario

open NaturalSpec

module Base =
    open System.Text
    open OAuth.Utilities
    open OAuth.Core.Base
    open OAuth.Types

    [<Scenario>]
    let ``require function returns the HTTP requirement parameter.`` () =
        Given (Encoding.ASCII, "http://hoge.com", GET)
        |||> When require
        |> It should equal (Requirement (Encoding.ASCII, "http://hoge.com", GET))
        |> Verify

    [<Scenario>]
    let ``getHttpMethodString function returns the string that represents the HTTP method.`` () =
        Given [GET; POST]
        |> When List.map getHttpMethodString
        |> It should equal ["GET"; "POST"]
        |> Verify

    [<Scenario>]
    let ``toKeyValue function returns the ParameterKeyValue list from the paired string list.`` () =
        Given [("oauth_consumer_key", "XXXX");
                ("oauth_nonce", "1111");
                ("oauth_signature", "YYYY")]
        |> When toKeyValue
        |> It should equal [KeyValue ("oauth_consumer_key", "XXXX");
                            KeyValue ("oauth_nonce", "1111");
                            KeyValue ("oauth_signature", "YYYY")]
        |> Verify

    [<Scenario>]
    let ``fromKeyValue function returns the paired string list from the ParameterKeyValue list.`` () =
        Given [KeyValue ("hoge", "fuga")]
        |> When fromKeyValue
        |> It should equal [("hoge", "fuga")]
        |> Verify

    [<Scenario>]
    let ``headerParameter function returns the 'key="value", ...' formatted string from the ParameterKeyValue list.`` () =
        Given [KeyValue ("oauth_consumer_key", "XXXX");
                KeyValue ("oauth_nonce", "1111");
                KeyValue ("oauth_signature", "YYYY")]
        |> When headerParameter
        |> It should equal ("oauth_consumer_key=\"XXXX\", " +
                            "oauth_nonce=\"1111\", " +
                            "oauth_signature=\"YYYY\"")
        |> Verify

    [<Scenario>]
    let ``parameterize function returns the parameterized string from the ParameterKeyValue.`` () =
        Given (KeyValue ("oauth_nonce", "1111"))
        |> When parameterize (fun s -> s)
        |> It should equal "oauth_nonce=1111"
        |> Verify

    [<Scenario>]
    let ``toParameter function returns the 'key=value&...' formatted string from the multi-valued ParameterKeyValue list.`` () =
        Given [KeyValue ("oauth_consumer_key", "XXXX");
                KeyValue ("oauth_nonce", "1111");
                KeyValue ("oauth_signature", "YYYY")]
        |> When toParameter (fun s -> s)
        |> It should equal "oauth_consumer_key=XXXX&oauth_nonce=1111&oauth_signature=YYYY"
        |> Verify

    [<Scenario>]
    let ``toParameter function returns the 'key=value&...' formatted string from the single-valued ParameterKeyValue list.`` () =
        Given [KeyValue ("oauth_consumer_key", "XXXX")]
        |> When toParameter (fun s -> s)
        |> It should equal "oauth_consumer_key=XXXX&"
        |> Verify

    [<Scenario>]
    let ``fromParameter function returns the ParameterKeyValue list from the 'key=value&...' formatted string.`` () =
        Given "oauth_consumer_key=XXXX&oauth_nonce=1111&oauth_signature=YYYY"
        |> When fromParameter
        |> It should equal [KeyValue ("oauth_consumer_key", "XXXX");
                            KeyValue ("oauth_nonce", "1111");
                            KeyValue ("oauth_signature", "YYYY")]
        |> Verify

    [<Scenario>]
    let ``tryGetValue function returns the Some value from the ParameterKeyValue list when the key matches.`` () =
        Given ("oauth_nonce",
                [KeyValue ("oauth_consumer_key", "XXXX");
                KeyValue ("oauth_nonce", "1111");
                KeyValue ("oauth_signature", "YYYY")])
        ||> When tryGetValue
        |> It should equal (Some "1111")
        |> Verify

    [<Scenario>]
    let ``tryGetValue function returns None from the ParameterKeyValue list when the key doesn't match.`` () =
        Given ("oauth_hoge",
                [KeyValue ("oauth_consumer_key", "XXXX");
                KeyValue ("oauth_nonce", "1111");
                KeyValue ("oauth_signature", "YYYY")])
        ||> When tryGetValue
        |> It should equal None
        |> Verify

module Authentication =
    open System.Text
    open OAuth.Utilities
    open OAuth.Types
    open OAuth.Core.Base
    open OAuth.Core.Authentication
    
    [<Scenario>]
    let ``generateNonce function returns the ticks string of DateTime.Now .`` () =
        Given ()
        |> When generateNonce
        |> It should be (fun nonce ->
            System.Text.RegularExpressions.Regex.IsMatch (nonce, "\d{18}"))
        |> Verify

    [<Scenario>]
    let ``generateTimeStamp function returns the time stamp string.`` () =
        Given ()
        |> When generateTimeStamp
        |> calculating (fun s -> s.Length)
        |> It should equal 10
        |> Verify

    [<Scenario>]
    let ``generateSignatureWithHMACSHA1 function returns the signature string with HMAC-SHA1 algorithm.`` () =
        Given (["fuga"], "hoge")
        ||> When generateSignatureWithHMACSHA1 (urlEncode Encoding.UTF8)
        |> It should equal "jMn6Vt7g5k4F4S666n%2FLeFwmJWI%3D"
        |> Verify

    [<Scenario>]
    let ``generateSignatureWithPLAINTEXT function returns the signature string without any algorithms.`` () =
        Given (["fuga"], "hoge")
        ||> When generateSignatureWithPLAINTEXT (fun s -> s)
        |> It should equal "hoge"
        |> Verify

    [<Scenario>]
    [<FailsWithType (typeof<System.NotImplementedException>)>]
    let ``generateSignatureWithRSASHA1 function raises the NotImplementedException.`` () =
        Given (["fuga"], "hoge")
        ||> When generateSignatureWithRSASHA1 (fun s -> s)
        |> Verify

    [<Scenario>]
    let ``assembleBaseString function returns the base string from the ParameterKeyValue list.`` () =
        Given [KeyValue ("oauth_consumer_key", "XXXX");
                KeyValue ("oauth_signature_method", "HMACSHA1");
                KeyValue ("oauth_timestamp", "1234567890");
                KeyValue ("oauth_nonce", "1111");
                KeyValue ("oauth_signature", "YYYY")]
        |> When assembleBaseString (require Encoding.ASCII "http://hoge.com" POST)
        |> It should equal ("POST&http%3A%2F%2Fhoge.com&"
                            + "oauth_consumer_key%3DXXXX%26oauth_nonce%3D1111%26"
                            + "oauth_signature%3DYYYY%26oauth_signature_method%3DHMACSHA1%26"
                            + "oauth_timestamp%3D1234567890")
        |> Verify

    [<Scenario>]
    let ``makeStringPairForGenerateHeader function returns the paired string list from the ForRequestToken value.`` () =
        Given ForRequestToken { consumerKey="XXXX"; consumerSecret="hoge" }
        |> When makeStringPairForGenerateHeader
        |> (fun ls ->
            match ls with
            | [("oauth_consumer_key", "XXXX");
                ("oauth_nonce", _);
                ("oauth_signature_method", "HMAC-SHA1");
                ("oauth_timestamp", _)] -> None
            | _ as bad -> Some bad)
        |> It should equal None
        |> Verify

    [<Scenario>]
    let ``makeStringPairForGenerateHeader function returns the paired string list from the ForAccessToken value.`` () =
        Given ForAccessToken ({ consumerKey="XXXX"; consumerSecret="hoge" },
                            { requestToken="YYYY"; requestSecret="fuga"},
                            "123456")
        |> When makeStringPairForGenerateHeader
        |> (fun ls ->
            match ls with
            | [("oauth_consumer_key", "XXXX");
                ("oauth_token", "YYYY");
                ("oauth_verifier", "123456");
                ("oauth_nonce", _);
                ("oauth_signature_method", "HMAC-SHA1");
                ("oauth_timestamp", _)] -> None
            | _ as bad -> Some bad)
        |> It should equal None
        |> Verify

    [<Scenario>]
    let ``makeStringPairForGenerateHeader function returns the paired string list from the ForWebService value.`` () =
        Given ForWebService ({ consumerKey="XXXX"; consumerSecret="hoge" },
                            { accessToken="ZZZZ"; accessSecret="bar"},
                            [KeyValue ("hoge", "fuga")])
        |> When makeStringPairForGenerateHeader
        |> (fun ls ->
            match ls with
            | [("oauth_consumer_key", "XXXX");
                ("oauth_token", "ZZZZ");
                ("oauth_nonce", _);
                ("oauth_signature_method", "HMAC-SHA1");
                ("oauth_timestamp", _)] -> None
            | _ as bad -> Some bad)
        |> It should equal None
        |> Verify

    [<Scenario>]
    let ``generateAuthorizationHeaderForRequestToken function returns the Authorization parameter string.`` () =
        Given ((require Encoding.ASCII "http://hoge.com" POST),
                { consumerKey="test_consumer_key"; consumerSecret="fuga" })
        ||> When generateAuthorizationHeaderForRequestToken
        |> It should be (fun auth ->
            (System.Text.RegularExpressions.Regex.IsMatch
                (auth, "OAuth " +
                        "oauth_signature=\"[A-Za-z0-9\+\-%]+%3D\", " +
                        "oauth_consumer_key=\"test_consumer_key\", " +
                        "oauth_nonce=\"\d{18}\", " +
                        "oauth_signature_method=\"HMAC-SHA1\", " +
                        "oauth_timestamp=\"\d{10}\"")))
        |> Verify

    [<Scenario>]
    let ``generateAuthorizationHeaderForAccessToken function returns the Authorization parameter string.`` () =
        Given ({ consumerKey="test_consumer_key"; consumerSecret="fuga" },
                { requestToken="test_request_token"; requestSecret="bar"},
                "123456")
        |||> When generateAuthorizationHeaderForAccessToken (require Encoding.ASCII "http://hoge.com" POST)
        |> It should be (fun auth ->
            (System.Text.RegularExpressions.Regex.IsMatch
                (auth, "OAuth " +
                        "oauth_signature=\"[A-Za-z0-9\+\-%]+%3D\", " +
                        "oauth_consumer_key=\"test_consumer_key\", " +
                        "oauth_token=\"test_request_token\", " +
                        "oauth_verifier=\"123456\", " +
                        "oauth_nonce=\"\d{18}\", " +
                        "oauth_signature_method=\"HMAC-SHA1\", " +
                        "oauth_timestamp=\"\d{10}\"")))
        |> Verify

    [<Scenario>]
    let ``generateAuthorizationHeaderForWebService function returns the Authorization parameter string.`` () =
        Given ({ consumerKey="test_consumer_key"; consumerSecret="fuga" },
                { accessToken="test_access_token"; accessSecret="blur"},
                [KeyValue ("spam", "eggs")])
        |||> When generateAuthorizationHeaderForWebService (require Encoding.ASCII "http://hoge.com" POST)
        |> It should be (fun auth ->
            (System.Text.RegularExpressions.Regex.IsMatch
                (auth, "OAuth " +
                        "oauth_signature=\"[A-Za-z0-9\+\-%]+%3D\", " +
                        "oauth_consumer_key=\"test_consumer_key\", " +
                        "oauth_token=\"test_access_token\", " +
                        "oauth_nonce=\"\d{18}\", " +
                        "oauth_signature_method=\"HMAC-SHA1\", " +
                        "oauth_timestamp=\"\d{10}\"")))
        |> Verify
