module OAuthScenario

open System.Text.RegularExpressions
open NaturalSpec
open NUnit.Framework
open OAuth.APIs

[<Scenario>]
let ``OAuthパラメータを作る`` () =
    Given (parameterize "oauth_nonce" "1111")
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
    |> When (fun (ck, ts) -> makeSignatureParameter ck ts)
    |> It should equal { consumer_key="hoge"; token_secret=Some("fuga") }
    |> Verify

[<Scenario>]
let ``HMAC-SHA1でgenerateSignatureする`` () =
    Given { consumer_key="hoge"; token_secret=None }
    |> When generateSignatureWithHMACSHA1
    |> calculating
        (fun genSig -> genSig "fuga")
    |> It should equal "iEthh4M9ZXZRe6DajdapqLDDBFU="
    |> Verify

[<Scenario>]
let ``PLAINTEXTでgenerateSignatureする`` () =
    Given { consumer_key="hoge"; token_secret=None }
    |> When generateSignatureWithPLAINTEXT
    |> calculating
        (fun genSig -> genSig "fuga")
    |> It should equal "fuga"
    |> Verify

[<Scenario>]
[<FailsWithType (typeof<System.NotImplementedException>)>]
let ``RSA-SHA1でgenerateSignatureしようとするとNotImplementedExceptionが送出される`` () =
    Given { consumer_key="hoge"; token_secret=None }
    |> When generateSignatureWithRSASHA1
    |> calculating
        (fun genSig -> genSig "fuga")
    |> Verify

[<Scenario>]
let ``与えられたクエリパラメータをキーの昇順でソートする`` () =
    Given [OAuthParameter ("oauth_consumer_key", "XXXX");
            OAuthParameter ("oauth_signature_method", "HMACSHA1");
            OAuthParameter ("oauth_timestamp", "1234567890");
            OAuthParameter ("oauth_nonce", "1111");
            OAuthParameter ("oauth_signature", "YYYY")]
    |> When assembleBaseString POST "http://hoge.com"
    |> It should equal ("POST&http://hoge.com&"
                        + "oauth_consumer_key=XXXX&oauth_nonce=1111&"
                        + "oauth_signature=YYYY&oauth_signature_method=HMACSHA1&"
                        + "oauth_timestamp=1234567890")
    |> Verify

[<Scenario>]
let ``リクエストトークンを要求するHTTPのAuthorizationヘッダを構成する`` () =
    Given "test_consumer_key"
    |> When generateAuthorizationHeaderForRequestToken
    |> It should be (fun auth ->
                        (Regex.IsMatch
                            (auth, "OAuth oauth_consumer_key=test_consumer_key" +
                                    "&oauth_nonce=\d{18}" +
                                    "&oauth_signature=[A-Za-z0-9\+\-]+=" +
                                    "&oauth_signature_method=HMACSHA1" +
                                    "&oauth_timestamp=\d{10}")))
    |> Verify