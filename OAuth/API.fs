module OAuth.API

open OAuth.Base
open OAuth.ExtendedWebClient

let getRequestToken target httpMethod consumerKey secretKeys =
    async {
        let wc = new System.Net.WebClient ()
        let url = System.Uri (target)
        let meth = getHttpMethodString httpMethod
        let header = generateAuthorizationHeaderForRequestToken target meth consumerKey secretKeys
        wc.Headers.Add ("Authorization", header)
        let! result = wc.AsyncUploadString url meth ""
        return result
    } |> Async.RunSynchronously
