module OAuthScenario

open NaturalSpec
open NUnit.Framework
open OAuth

[<Scenario>]
let ``OAuthパラメータを作る`` () =
    Given (OAuth.parameterize "oauth_nonce" "1111")
    |> It should equal (OAuthParameter ("oauth_nonce", "1111"))
    |> Verify