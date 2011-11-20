namespace OAuth.Core

module Base =
    open System
    open System.Text
    open OAuth.Utilities
    open OAuth.Types

    [<CompiledName("Require")>]
    let require encoding targetUrl httpMethod = Requirement (encoding, targetUrl, httpMethod)

    [<CompiledName("GetHttpMethodString")>]
    let getHttpMethodString = function
        | GET -> "GET"
        | POST -> "POST"

    [<CompiledName("ToKeyValue")>]
    let toKeyValue tupleList = List.map KeyValue tupleList

    [<CompiledName("FromKeyValue")>]
    let fromKeyValue keyValues = List.map (fun (KeyValue (key, value)) -> (key, value)) keyValues

    [<CompiledName("HeaderParameter")>]
    let headerParameter keyValues =
        match keyValues with
        | [] -> ""
        | _ ->
            keyValues
            |> List.map (fun (KeyValue (key, value)) ->
                            key + "=\"" + value + "\"")
            |> List.fold (concatStringsWithToken ", ") ""

    [<CompiledName("Parameterize")>]
    let parameterize encoder keyValue =
        let (KeyValue (key, value)) = keyValue
        key + "=" + (encoder value)

    [<CompiledName("ToParameter")>]
    let toParameter encoder keyValues =
        let parameterized = keyValues |> List.map (parameterize encoder)
        match parameterized with
        | x::y::xs ->  List.fold (concatStringsWithToken "&") "" parameterized
        | x::xs -> x + "&"
        | _ -> ""

    [<CompiledName("FromParameter")>]
    let fromParameter (parameterString : string) =
        parameterString.Split [|'&'|]
        |> List.ofArray
        |> List.map ((fun (s : string) -> s.Split [|'='|] ) >>
                    (fun kv -> KeyValue (kv.[0], kv.[1])))

    [<CompiledName("TryGetValue")>]
    let tryGetValue key keyValues =
        List.tryPick (fun (KeyValue (k, v)) ->
                    if k = key then Some v else None) keyValues