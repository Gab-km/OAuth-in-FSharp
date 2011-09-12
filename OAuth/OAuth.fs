module OAuth

type OAuthParameter = OAuthParameter of string * string

let parameterize key value = OAuthParameter (key, value)

let parameterizeMany kvList = List.map (fun (key, value) -> parameterize key value) kvList

let keyValue oParam =
    match oParam with
    | OAuthParameter (key, value) -> key + "=" + value