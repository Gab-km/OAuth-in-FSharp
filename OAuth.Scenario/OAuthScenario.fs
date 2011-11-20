module OAuth.Scenario

open NaturalSpec

module Utilities =
    open System.Text
    open OAuth.Utilities

    [<Scenario>]
    let ``concatStringsWithToken function returns the concatenated string with certain tokens.`` () =
        Given [(", ", "hoge", "fuga"); ("&", "spam", "eggs")]
        |> When List.map ((<|||) concatStringsWithToken)
        |> It should equal ["hoge, fuga"; "spam&eggs"]
        |> Verify

    [<Scenario>]
    let ``concatSecretKeys function returns the concatenated string with '&' when multi-valued list is given.`` () =
        Given ["hoge"; "fuga"]
        |> When concatSecretKeys
        |> It should equal "hoge&fuga"
        |> Verify

    [<Scenario>]
    let ``concatSecretKeys function returns the string ended with '&' when single-valued list is given.`` () =
        Given ["hoge"]
        |> When concatSecretKeys
        |> It should equal "hoge&"
        |> Verify

    [<Scenario>]
    let ``urlEncode function returns the encoded string that encoded to hexadecimal characters without [A-Za-z0-9\-\_\.\~] and multibyte characters.`` () =
        Given ["hoge"; "http://fuga.com"]
        |> When List.map (urlEncode Encoding.ASCII)
        |> It should equal ["hoge"; "http%3A%2F%2Ffuga.com"]
        |> Verify

    [<Scenario>]
    let ``urlEncode function returns the encoded string that encoded from certain character coded to hexadecimal coded.`` () =
        Given "はろーわーるど"
        |> When urlEncode Encoding.UTF8
        |> It should equal "%E3%81%AF%E3%82%8D%E3%83%BC%E3%82%8F%E3%83%BC%E3%82%8B%E3%81%A9"
        |> Verify
