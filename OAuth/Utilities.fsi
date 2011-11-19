namespace OAuth

module Utilities = begin

    /// <summary>Returns a concatenated strings with a token.</summary>
    /// <param name="token">The token.</param>
    /// <param name="s1">The first string.</param>
    /// <param name="s2">The second string.</param>
    /// <returns>The concatenated string.</returns>
    [<CompiledName("ConcatStringsWithToken")>]
    val inline concatStringsWithToken : token:string -> s1:string -> s2:string -> string

    /// <summary>Returns a concatenated strings with '&amp;' when a list contains more than one string.<br />
    /// Returns a string with '&amp;' at its tail when a list contains the string alone.<br />
    /// Returns <c>string.empty</c> when a list is empty.</summary>
    /// <param name="secretKeys">The string list contains secret keys.</param>
    /// <returns>The concatenated string.</returns>
    [<CompiledName("ConcatSecretKeys")>]
    val concatSecretKeys : secretKeys:string list -> string

    /// <summary>Returns an sanitized string.<br />
    /// Be sanitized a character in the string when the character isn't
    /// any alphabets, numbers, a hiphen, an underscore, a period or a tilde.</summary>
    /// <param name="urlString">The url string.</param>
    /// <returns>The sanitized string.</returns>
    [<CompiledName("UrlEncode")>]
    val urlEncode : encode:System.Text.Encoding -> urlString:string -> string

//    [<CompiledName("UrlEncodeInASCII")>]
//    val urlEncodeInASCII : urlString:string -> string
end