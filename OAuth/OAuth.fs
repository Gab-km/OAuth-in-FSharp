module OAuth

type OAuthParameter = OAuthParameter of string * string

let parameterize key value = OAuthParameter (key, value)