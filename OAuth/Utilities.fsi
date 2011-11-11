namespace OAuth

module Utilities = begin

    val inline concatStringsWithToken : string -> string -> string -> string

    val concatSecretKeys : string list -> string

    val urlEncode : string -> string
end