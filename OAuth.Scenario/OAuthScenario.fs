module OAuth.Scenario

open NaturalSpec

module Utilities =
    open System.Text
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
        |> When List.map (urlEncode Encoding.ASCII)
        |> It should equal ["hoge"; "http%3A%2F%2Ffuga.com"]
        |> Verify

    [<Scenario>]
    let ``When multiple bytes characters are given, urlEncode should returns no encoded characters`` () =
        Given "はろーわーるど"
        |> When urlEncode Encoding.UTF8
        |> It should equal "%E3%81%AF%E3%82%8D%E3%83%BC%E3%82%8F%E3%83%BC%E3%82%8B%E3%81%A9"
        |> Verify
