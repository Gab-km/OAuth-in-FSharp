module OAuthScenario

open NaturalSpec
open NUnit.Framework
open OAuth

[<Scenario>]
let ``OAuthパラメータを作る`` () =
    Given (OAuth.parameterize "oauth_nonce" "1111")
    |> It should equal (OAuthParameter ("oauth_nonce", "1111"))
    |> Verify

[<Scenario>]
let ``OAuthパラメータをKeyValue形式の文字列に変換する`` () =
    Given (OAuth.parameterize "oauth_nonce" "1111")
    |> When OAuth.keyValue
    |> It should equal "oauth_nonce=1111"
    |> Verify

[<Scenario>]
let ``複数のOAuthパラメータを一度に作る`` () =
    Given [("oauth_consumer_key", "XXXX");
            ("oauth_nonce", "1111");
            ("oauth_signature", "YYYY")]
    |> When OAuth.parameterizeMany
    |> It should equal [OAuthParameter ("oauth_consumer_key", "XXXX");
                        OAuthParameter ("oauth_nonce", "1111");
                        OAuthParameter ("oauth_signature", "YYYY")]
    |> Verify

[<Scenario>]
let ``複数のOAuthパラメータをKeyValue形式の文字列に変換して連結する`` () =
    Given [OAuthParameter ("oauth_consumer_key", "XXXX");
            OAuthParameter ("oauth_nonce", "1111");
            OAuthParameter ("oauth_signature", "YYYY")]
    |> When OAuth.keyValueMany
    |> It should equal "oauth_consumer_key=XXXX&oauth_nonce=1111&oauth_signature=YYYY"
    |> Verify

[<Scenario>]
let ``generateNonceしてみる`` () =
    Given ()
    |> When generateNonce
    |> It shouldn't equal ""
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
    Given { consumer_secret="hoge"; token_secret=None }
    |> When generateSignature
    |> calculating
        (fun algorithm ->
            algorithm.ComputeHash ("fuga" |> System.Text.Encoding.ASCII.GetBytes))
    |> It should equal [|136uy; 75uy; 97uy; 135uy; 131uy; 61uy; 101uy; 118uy;
                        81uy; 123uy; 160uy; 218uy; 141uy; 214uy; 169uy; 168uy;
                        176uy; 195uy; 4uy; 85uy|]
    |> Verify
