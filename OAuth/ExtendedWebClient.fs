module OAuth.ExtendedWebClient

open System

type System.Net.WebClient with

    [<CompiledName("AsyncDownloadString")>]
    member this.AsyncDownloadString (address:Uri) : Async<string> =
        let downloadAsync =
            Async.FromContinuations (fun (cont, econt, ccont) ->
                let userToken = new obj()
                let rec handler =
                    System.Net.DownloadStringCompletedEventHandler (fun _ args ->
                        if userToken = args.UserState then
                            this.DownloadStringCompleted.RemoveHandler(handler)
                            if args.Cancelled then
                                ccont (new OperationCanceledException())
                            elif args.Error <> null then
                                econt args.Error
                            else
                                cont args.Result
                    )
                this.DownloadStringCompleted.AddHandler(handler)
                this.DownloadStringAsync(address, userToken)
            )
        async {
            use! _holder = Async.OnCancel(fun _ -> this.CancelAsync())
            return! downloadAsync
        }

    [<CompiledName("AsyncUploadString")>]
    member this.AsyncUploadString (address:Uri) meth data : Async<string> =
        let uploadAsync =
            Async.FromContinuations (fun (cont, econt, ccont) ->
                let userToken = new obj()
                let rec handler =
                    System.Net.UploadStringCompletedEventHandler (fun _ args ->
                        if userToken = args.UserState then
                            this.UploadStringCompleted.RemoveHandler(handler)
                        if args.Cancelled then
                            ccont (new OperationCanceledException())
                        elif args.Error <> null then
                            econt args.Error
                        else
                            cont args.Result
                    )
                this.UploadStringCompleted.AddHandler(handler)
                this.UploadStringAsync(address, meth, data, userToken)
            )
        async {
            use! _holder = Async.OnCancel(fun _ -> this.CancelAsync())
            return! uploadAsync
        }