module OAuthScenario

open NaturalSpec

module Utilities =
    open OAuth.Utilities

    [<Scenario>]
    let ``区切り文字を指定して空でない2つの文字列を連結する`` () =
        Given [(", ", "hoge", "fuga"); ("&", "spam", "eggs")]
        |> When List.map ((<|||) concatStringsWithToken)
        |> It should equal ["hoge, fuga"; "spam&eggs"]
        |> Verify

    [<Scenario>]
    let ``concatSecretKeysで秘密鍵を2つ与えたとき＆で連結する`` () =
        Given ["hoge"; "fuga"]
        |> When concatSecretKeys
        |> It should equal "hoge&fuga"
        |> Verify

    [<Scenario>]
    let ``concatSecretKeysで秘密鍵を1つ与えたとき＆で終わる`` () =
        Given ["hoge"]
        |> When concatSecretKeys
        |> It should equal "hoge&"
        |> Verify

    [<Scenario>]
    let ``concatSecretKeysで秘密鍵を3つ与えたとき＆で連結する`` () =
        Given ["hoge"; "fuga"; "bar"]
        |> When concatSecretKeys
        |> It should equal "hoge&fuga&bar"
        |> Verify

    [<Scenario>]
    let ``[A-Za-z0-9\-\_\.\~]以外の文字列を16進数に変換する`` () =
        Given ["hoge"; "http://fuga.com"]
        |> When List.map urlEncode
        |> It should equal ["hoge"; "http%3A%2F%2Ffuga.com"]
        |> Verify

module Base =
    open OAuth.Base
    open OAuth.Types

    [<Scenario>]
    let ``KeyValueをパラメータ形式の文字列に変換する`` () =
        Given (KeyValue ("oauth_nonce", "1111"))
        |> When parameterize
        |> It should equal "oauth_nonce=1111"
        |> Verify

    [<Scenario>]
    let ``複数のKeyValueを一度に作る`` () =
        Given [("oauth_consumer_key", "XXXX");
                ("oauth_nonce", "1111");
                ("oauth_signature", "YYYY")]
        |> When keyValueMany
        |> It should equal [KeyValue ("oauth_consumer_key", "XXXX");
                            KeyValue ("oauth_nonce", "1111");
                            KeyValue ("oauth_signature", "YYYY")]
        |> Verify

    [<Scenario>]
    let ``KeyValueリストをパラメータ形式の文字列に変換して連結する`` () =
        Given [KeyValue ("oauth_consumer_key", "XXXX");
                KeyValue ("oauth_nonce", "1111");
                KeyValue ("oauth_signature", "YYYY")]
        |> When toParameter
        |> It should equal "oauth_consumer_key=XXXX&oauth_nonce=1111&oauth_signature=YYYY"
        |> Verify

    [<Scenario>]
    let ``KeyValueが1つだけの場合パラメータ形式の文字列＋＆に変換する`` () =
        Given [KeyValue ("oauth_consumer_key", "XXXX")]
        |> When toParameter
        |> It should equal "oauth_consumer_key=XXXX&"
        |> Verify

    [<Scenario>]
    let ``KeyValueリストを'key="value", ...'の形式に変換する`` () =
        Given [KeyValue ("oauth_consumer_key", "XXXX");
                KeyValue ("oauth_nonce", "1111");
                KeyValue ("oauth_signature", "YYYY")]
        |> headerKeyValue
        |> It should equal ("oauth_consumer_key=\"XXXX\", " +
                            "oauth_nonce=\"1111\", " +
                            "oauth_signature=\"YYYY\"")
        |> Verify

    [<Scenario>]
    let ``パラメータ形式の文字列をKeyValueリストに変換する`` () =
        Given "oauth_consumer_key=XXXX&oauth_nonce=1111&oauth_signature=YYYY"
        |> When fromKeyValue
        |> It should equal [KeyValue ("oauth_consumer_key", "XXXX");
                            KeyValue ("oauth_nonce", "1111");
                            KeyValue ("oauth_signature", "YYYY")]
        |> Verify

    [<Scenario>]
    let ``generateNonceしてみる`` () =
        Given ()
        |> When generateNonce
        |> It should be (fun nonce ->
            System.Text.RegularExpressions.Regex.IsMatch (nonce, "\d{18}"))
        |> Verify

    [<Scenario>]
    let ``generateTimeStampしてみる`` () =
        Given ()
        |> When generateTimeStamp
        |> calculating (fun s -> s.Length)
        |> It should equal 10
        |> Verify

    [<Scenario>]
    let ``HMAC-SHA1でgenerateSignatureする`` () =
        Given (["fuga"], "hoge")
        ||> When generateSignatureWithHMACSHA1
        |> It should equal "jMn6Vt7g5k4F4S666n%2FLeFwmJWI%3D"
        |> Verify

    [<Scenario>]
    let ``PLAINTEXTでgenerateSignatureする`` () =
        Given (["fuga"], "hoge")
        ||> When generateSignatureWithPLAINTEXT
        |> It should equal "hoge"
        |> Verify

    [<Scenario>]
    [<FailsWithType (typeof<System.NotImplementedException>)>]
    let ``RSA-SHA1でgenerateSignatureしようとするとNotImplementedExceptionが送出される`` () =
        Given (["fuga"], "hoge")
        ||> When generateSignatureWithRSASHA1
        |> Verify

    [<Scenario>]
    let ``与えられたクエリパラメータを使ってベース文字列を作成するする`` () =
        Given [KeyValue ("oauth_consumer_key", "XXXX");
                KeyValue ("oauth_signature_method", "HMACSHA1");
                KeyValue ("oauth_timestamp", "1234567890");
                KeyValue ("oauth_nonce", "1111");
                KeyValue ("oauth_signature", "YYYY")]
        |> When assembleBaseString "POST" "http://hoge.com"
        |> It should equal ("POST&http%3A%2F%2Fhoge.com&"
                            + "oauth_consumer_key%3DXXXX%26oauth_nonce%3D1111%26"
                            + "oauth_signature%3DYYYY%26oauth_signature_method%3DHMACSHA1%26"
                            + "oauth_timestamp%3D1234567890")
        |> Verify

    [<Scenario>]
    let ``ConsumerInfoのみでgenerateHeader用のタプルリストを作成する`` () =
        Given ForRequestToken { consumerKey="XXXX"; consumerSecret="hoge" }
        |> When makeKeyValueTuplesForGenerateHeader
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
    let ``ConsumerInfo、RequestInfo、pinCodeでgenerateHeader用のタプルリストを作成する`` () =
        Given ForAccessToken ({ consumerKey="XXXX"; consumerSecret="hoge" },
                            { requestToken="YYYY"; requestSecret="fuga"},
                            "123456")
        |> When makeKeyValueTuplesForGenerateHeader
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
    let ``ConsumerInfo、AccessInfoでgenerateHeader用のタプルリストを作成する`` () =
        Given ForWebService ({ consumerKey="XXXX"; consumerSecret="hoge" },
                            { accessToken="ZZZZ"; accessSecret="bar"})
        |> When makeKeyValueTuplesForGenerateHeader
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
    let ``リクエストトークンを要求するHTTPのAuthorizationヘッダを構成する`` () =
        Given ({ consumerKey="test_consumer_key"; consumerSecret="fuga" })
        |> When generateAuthorizationHeaderForRequestToken "http://hoge.com" "POST"
        |> It should be (fun auth ->
            (System.Text.RegularExpressions.Regex.IsMatch
                (auth, "OAuth " +
                        "oauth_signature=\"[A-Za-z0-9\+\-%]+%3D\", " +
                        "oauth_consumer_key=\"test_consumer_key\", " +
                        "oauth_nonce=\"\d{18}\", " +
                        "oauth_signature_method=\"HMAC-SHA1\", " +
                        "oauth_timestamp=\"\d{10}\"")))
        |> Verify
