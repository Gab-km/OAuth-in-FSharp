namespace OAuth

module Base = begin
    open OAuth.Utilities
    open OAuth.Types
    
    val keyValueMany : (string * string) list -> ParameterKeyValue list

    val headerParameter : ParameterKeyValue list -> string

    val parameterize : ParameterKeyValue -> string

    val toParameter : ParameterKeyValue list -> string

    val fromParameter : string -> ParameterKeyValue list

    val tryGetValue : ParameterKeyValue list -> string -> string option

    val inline generateNonce : unit -> string

    val generateTimeStamp : unit -> string

    val generateSignature : HashAlgorithm -> string list -> string -> string

    val inline generateSignatureWithHMACSHA1 : string list -> string -> string

    val inline generateSignatureWithPLAINTEXT : string list -> string -> string

    val inline generateSignatureWithRSASHA1 : string list -> string -> string

    val getHttpMethodString : HttpMethod -> string

    val assembleBaseString : string -> string -> ParameterKeyValue list -> string

    val makeKeyValueTuplesForGenerateHeader : UseFor -> (string * string) list

    val generateAuthorizationHeader : string -> string -> UseFor -> string

    val generateAuthorizationHeaderForRequestToken : string -> string -> ConsumerInfo -> string

    val generateAuthorizationHeaderForAccessToken : string -> string -> ConsumerInfo -> RequestInfo -> string -> string

    val generateAuthorizationHeaderForWebService : string -> string -> ConsumerInfo -> AccessInfo -> string
end