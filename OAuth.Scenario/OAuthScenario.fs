module OAuthScenario

open System.Text.RegularExpressions
open NaturalSpec
open NUnit.Framework
open OAuth.Utilities
open OAuth.Base

module Utilities =
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
    [<Scenario>]
    let ``OAuthパラメータを作る`` () =
        Given ("oauth_nonce", "1111")
        ||> When parameterize
        |> It should equal (OAuthParameter ("oauth_nonce", "1111"))
        |> Verify

    [<Scenario>]
    let ``OAuthパラメータをKeyValue形式の文字列に変換する`` () =
        Given (parameterize "oauth_nonce" "1111")
        |> When keyValue
        |> It should equal "oauth_nonce=1111"
        |> Verify

    [<Scenario>]
    let ``複数のOAuthパラメータを一度に作る`` () =
        Given [("oauth_consumer_key", "XXXX");
                ("oauth_nonce", "1111");
                ("oauth_signature", "YYYY")]
        |> When parameterizeMany
        |> It should equal [OAuthParameter ("oauth_consumer_key", "XXXX");
                            OAuthParameter ("oauth_nonce", "1111");
                            OAuthParameter ("oauth_signature", "YYYY")]
        |> Verify

    [<Scenario>]
    let ``複数のOAuthパラメータをKeyValue形式の文字列に変換して連結する`` () =
        Given [OAuthParameter ("oauth_consumer_key", "XXXX");
                OAuthParameter ("oauth_nonce", "1111");
                OAuthParameter ("oauth_signature", "YYYY")]
        |> When keyValueMany
        |> It should equal "oauth_consumer_key=XXXX&oauth_nonce=1111&oauth_signature=YYYY"
        |> Verify

    [<Scenario>]
    let ``OAuthパラメータが1つだけの場合KeyValue形式の文字列＋＆に変換する`` () =
        Given [OAuthParameter ("oauth_consumer_key", "XXXX")]
        |> When keyValueMany
        |> It should equal "oauth_consumer_key=XXXX&"
        |> Verify

    [<Scenario>]
    let ``OAuthパラメータを'key="value", ...'の形式に変換する`` () =
        Given [OAuthParameter ("oauth_consumer_key", "XXXX");
                OAuthParameter ("oauth_nonce", "1111");
                OAuthParameter ("oauth_signature", "YYYY")]
        |> headerKeyValue
        |> It should equal ("oauth_consumer_key=\"XXXX\", " +
                            "oauth_nonce=\"1111\", " +
                            "oauth_signature=\"YYYY\"")
        |> Verify

    [<Scenario>]
    let ``generateNonceしてみる`` () =
        Given ()
        |> When generateNonce
        |> It should be (fun nonce -> Regex.IsMatch (nonce, "\d{18}"))
        |> Verify

    [<Scenario>]
    let ``generateTimeStampしてみる`` () =
        Given ()
        |> When generateTimeStamp
        |> calculating (fun s -> s.Length)
        |> It should equal 10
        |> Verify

    [<Scenario>]
    let ``generateSignatureParameterする`` () =
        Given ("hoge", Some("fuga"))
        ||> When makeSignatureParameter
        |> It should equal { consumer_key="hoge"; token_secret=Some("fuga") }
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
        Given [OAuthParameter ("oauth_consumer_key", "XXXX");
                OAuthParameter ("oauth_signature_method", "HMACSHA1");
                OAuthParameter ("oauth_timestamp", "1234567890");
                OAuthParameter ("oauth_nonce", "1111");
                OAuthParameter ("oauth_signature", "YYYY")]
        |> When assembleBaseString "POST" "http://hoge.com"
        |> It should equal ("POST&http%3A%2F%2Fhoge.com&"
                            + "oauth_consumer_key%3DXXXX%26oauth_nonce%3D1111%26"
                            + "oauth_signature%3DYYYY%26oauth_signature_method%3DHMACSHA1%26"
                            + "oauth_timestamp%3D1234567890")
        |> Verify

    [<Scenario>]
    let ``リクエストトークンを要求するHTTPのAuthorizationヘッダを構成する`` () =
        Given ("test_consumer_key",  ["fuga"])
        ||> When generateAuthorizationHeaderForRequestToken "http://hoge.com" "POST"
        |> It should be (fun auth ->
            (Regex.IsMatch
                (auth, "OAuth " +
                        "oauth_signature=\"[A-Za-z0-9\+\-%]+%3D\", " +
                        "oauth_consumer_key=\"test_consumer_key\", " +
                        "oauth_nonce=\"\d{18}\", " +
                        "oauth_signature_method=\"HMAC-SHA1\", " +
                        "oauth_timestamp=\"\d{10}\"")))
        |> Verify
