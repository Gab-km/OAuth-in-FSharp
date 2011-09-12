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