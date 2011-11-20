namespace OAuth.Core

module Base = begin
    open OAuth.Utilities
    open OAuth.Types

    /// <summary>Returns a HTTP requirement parameter.</summary>
    /// <param name="encoding">The encoding.</param>
    /// <param name="targetUrl">The URL string.</param>
    /// <param name="httpMethod">The HTTP method.</param>
    /// <returns>The HTTP requirement parameter.</returns>
    [<CompiledName("Require")>]
    val require : System.Text.Encoding -> string -> HttpMethod -> HttpRequirement

    /// <summary>Returns the string that represents the HTTP method.</summary>
    /// <param name="httpMethod">The Http Method.</param>
    /// <returns>The string of the HTTP method.</returns>
    [<CompiledName("GetHttpMethodString")>]
    val getHttpMethodString : HttpMethod -> string
    
    /// <summary>Returns a ParameterKeyValue list from a string tuple list.</summary>
    /// <param name="tupleList">The list of 2 strings tuple.</param>
    /// <returns>The ParameterKeyValue list.</returns>
    [<CompiledName("ToKeyValue")>]
    val toKeyValue : (string * string) list -> ParameterKeyValue list

    /// <summary>Returns a string tuple list from a ParameterKeyValue list.</summary>
    /// <param name="keyValue">The ParameterKeyValue list.</param>
    /// <returns>The string tuple list.</returns>
    [<CompiledName("FromKeyValue")>]
    val fromKeyValue : ParameterKeyValue list -> (string * string) list

    /// <summary>Returns a string as a HTTP header parameter.</summary>
    /// <param name="keyValues">The ParameterKeyValue list.</param>
    /// <returns>The HTTP header parameter.</returns>
    [<CompiledName("HeaderParameter")>]
    val headerParameter : ParameterKeyValue list -> string

    /// <summary>Returns a string combined with an equal sign.</summary>
    /// <param name="encoder">The encoding function.</param>
    /// <param name="keyValue">The ParameterKeyValue.</param>
    /// <returns>The key and value strings combined with an equal sign.</returns>
    [<CompiledName("Parameterize")>]
    val parameterize : (string -> string) -> ParameterKeyValue -> string

    /// <summary>Returns a parameterized string combined with an ampersand sign.</summary>
    /// <param name="encoder">The encoding function.</param>
    /// <param name="keyValues">The ParameterKeyValue list.</param>
    /// <returns>The parameterized strings combined with an ampersand sign.
    /// Or the parameterized string with an ampersand with its tail.</returns>
    [<CompiledName("ToParameter")>]
    val toParameter : (string -> string) -> ParameterKeyValue list -> string

    /// <summary>Returns a ParameterKeyValue list from a parameterized string.</summary>
    /// <param name="parameterString">The parameterized string combined with an ampersand sign.</param>
    /// <returns>The ParameterKeyValue list.</returns>
    [<CompiledName("FromParameter")>]
    val fromParameter : string -> ParameterKeyValue list

    /// <summary>Try to return a value from a ParameterKeyValue list.<br />
    /// Returns a Some value when the key matches a given key.<br />
    /// Returns None when the key doesn't match.</summary>
    /// <param name="key">The input key.</param>
    /// <param name="keyValues">The ParameterKeyValue list.</param>
    /// <returns>The value mapped to the given key.</returns>
    [<CompiledName("TryGetValue")>]
    val tryGetValue : string -> ParameterKeyValue list -> string option
end