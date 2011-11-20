namespace OAuth

module Utilities =

    [<CompiledName("ConcatStringsWithToken")>]
    let inline concatStringsWithToken token s1 s2 =
        if s1 = "" then s2 else s1 + token + s2

    [<CompiledName("ConcatSecretKeys")>]
    let concatSecretKeys = function
        | x::y::xs -> List.fold (concatStringsWithToken "&") "" (x::y::xs)
        | x::xs -> x + "&"
        | _ -> ""

    [<CompiledName("UrlEncode")>]
    let urlEncode (encode : System.Text.Encoding) (urlString : string) =
        let urlBytes = encode.GetBytes urlString |> List.ofArray
        let encodeChar b =
            let validChars = List.ofSeq "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~"
            if b < 128uy && List.exists (fun v -> v = char b) validChars then (char b).ToString()
            else
                System.String.Format ("%{0:X2}", b)
        urlBytes
        |> List.map encodeChar
        |> List.fold (fun s1 s2 -> s1 + s2) ""
