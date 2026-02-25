axios の脆弱性 CVE-2023-45857 の動作を確認するデモ

1. dev container で起動する
1. app コンテナで`npm run dev`する
1. http://app.localhostへアクセスする
1. ブラウザの開発者ツールで Cookie に`XSRF-TOKEN`がセットされていることを確認する
   - 値が`CREDENTIAL_TOKEN`となっていること
   - HttpOnly が false となっていること
   - SameSite が Strict となっていること
1. ボタンを押す
1. 開発者ツールで`whoami.localhost/api`へのリクエストにヘッダーの`x-xsrf-token`が存在し値が`CREDENTIAL_TOKEN`となっていること
   - whoami はリクエストをそのまま返却するのでブラウザ上でも確認ができる
