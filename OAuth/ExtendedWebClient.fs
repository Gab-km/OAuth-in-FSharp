module OAuth.ExtendedWebClient

open System

type System.Net.WebClient with
  // AsyncDownloadStringメソッドは、技術評論社「実践F#」第11章
  // 「ワークフローと非同期ワークフロー」P.397-398からサンプルコードを
  // 改変することなく記載している。
  [<CompiledName("AsyncDownloadString")>]
  member this.AsyncDownloadString (address:Uri) : Async<string> =
    // 継続用の非同期ワークフローを作成します(処理、例外、キャンセル)
    let downloadAsync =
      Async.FromContinuations (fun (cont, econt, ccont) ->
        let userToken = new obj()
        // イベントハンドラを宣言します
        let rec handler =
            // デリゲートの宣言を行います
            System.Net.DownloadStringCompletedEventHandler (fun _ args ->
              if userToken = args.UserState then
                // イベントが発生したらハンドラを削除
                this.DownloadStringCompleted.RemoveHandler(handler)
                if args.Cancelled then
                  // キャンセル時の処理
                  ccont (new OperationCanceledException())
                elif args.Error <> null then
                  // エラー時の処理
                  econt args.Error
                else
                  // 結果を返す
                  cont args.Result
            )
        // イベントハンドラを登録して、呼び出します
        this.DownloadStringCompleted.AddHandler(handler)
        this.DownloadStringAsync(address, userToken)
    )

    // キャンセル時の処理を使用する、非同期ワークフローを返します
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