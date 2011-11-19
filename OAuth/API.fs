namespace OAuth

module API =
    open System.Text
    open OAuth.Types
    open OAuth.Utilities
    open OAuth.Base
    open OAuth.ExtendedWebClient

    let asyncAPIBase encode targetUrl httpMethod header data =
        async {
            let wc = new System.Net.WebClient ()
            let url = System.Uri (targetUrl)
            let meth = getHttpMethodString httpMethod
            let! result =
                match httpMethod with
                | GET ->
                    wc.Headers.Add ("Authorization", header)
                    wc.AsyncDownloadString url
                | POST ->
                    wc.Headers.Add ("Authorization", header)
                    match data with
                    | Some d ->
                        let param = System.Collections.Specialized.NameValueCollection()
                        param.Add ("status", urlEncode encode d)
                        wc.QueryString <- param
                    | None -> ()
                    wc.AsyncUploadString url meth ""
            return result
        } |> Async.RunSynchronously

    let getRequestToken encode targetUrl httpMethod consumerInfo data =
        let encoder = urlEncode encode
        let header = generateAuthorizationHeaderForRequestToken encoder targetUrl httpMethod consumerInfo
        asyncAPIBase encode targetUrl httpMethod header data

    let getRequestTokenByGet encode target consumerInfo data = getRequestToken encode target GET consumerInfo data
    let getRequestTokenByPost encode target consumerInfo data = getRequestToken encode target POST consumerInfo data

    let getAccessToken encode targetUrl httpMethod consumerInfo requestInfo pinCode data =
        let encoder = urlEncode encode
        let header = generateAuthorizationHeaderForAccessToken encoder targetUrl httpMethod consumerInfo requestInfo pinCode
        asyncAPIBase encode targetUrl httpMethod header data

    let getAccessTokenByGet encode target consumerInfo requestInfo pinCode data = getAccessToken encode target GET consumerInfo requestInfo pinCode data
    let getAccessTokenByPost encode target consumerInfo requestInfo pinCode data = getAccessToken encode target POST consumerInfo requestInfo pinCode data

    let useWebService encode targetUrl httpMethod consumerInfo accessInfo data =
        let encoder = urlEncode encode
        let header = generateAuthorizationHeaderForWebService encoder targetUrl httpMethod consumerInfo accessInfo
        asyncAPIBase encode targetUrl httpMethod header data

    let useWebServiceByGet encode target consumerInfo accessInfo data = useWebService encode target GET consumerInfo accessInfo data
    let useWebServiceByPost encode target consumerInfo accessInfo data = useWebService encode target POST consumerInfo accessInfo data
