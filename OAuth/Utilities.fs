module OAuth.Utilities

let inline concatStringsWithToken token s1 s2 =
    if s1 = "" then s2 else s1 + token + s2

let concatSecretKeys = function
    | x::y::xs -> List.fold (concatStringsWithToken "&") "" (x::y::xs)
    | x::xs -> x + "&"
    | _ -> ""

let urlEncode (urlString : string) =
    let urlChars = List.ofSeq urlString
    let encodeChar c =
        let validChars = List.ofSeq "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~"
        if List.exists (fun v -> v = c) validChars then c.ToString()
        else
            let bt = System.Text.Encoding.ASCII.GetBytes (c.ToString ())
            System.String.Format ("%{0:X2}", bt.[0])
    urlChars
    |> List.map encodeChar
    |> List.fold (fun s1 s2 -> s1 + s2) ""
