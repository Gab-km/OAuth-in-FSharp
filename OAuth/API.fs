namespace OAuth

module API =
    open System.Text
    open OAuth.Types
    open OAuth.Utilities
    open OAuth.Base
    open OAuth.ExtendedWebClient

    let asyncAPIBase requirement header data =
        async {
            let (Requirement (encoding, targetUrl, httpMethod)) = requirement
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
                        param.Add ("status", urlEncode encoding d)
                        wc.QueryString <- param
                    | None -> ()
                    wc.AsyncUploadString url meth ""
            return result
        } |> Async.RunSynchronously

    let getRequestToken requirement consumerInfo data =
        let header = generateAuthorizationHeaderForRequestToken requirement consumerInfo
        asyncAPIBase requirement header data

    let getAccessToken requirement consumerInfo requestInfo pinCode data =
        let header = generateAuthorizationHeaderForAccessToken requirement consumerInfo requestInfo pinCode
        asyncAPIBase requirement header data

    let useWebService requirement consumerInfo accessInfo data =
        let header = generateAuthorizationHeaderForWebService requirement consumerInfo accessInfo
        asyncAPIBase requirement header data
