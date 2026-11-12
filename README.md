# MCP-Trust-Check

MCP の公式 SDK を「修正版に上げた」のに、修正が効いていない状態を探すための点検スクリプトと、その問題を手元で再現する検証環境です。

2025年12月から2026年10月にかけて、MCP の公式 SDK（Python・TypeScript・Go）には通信と認可まわりのアドバイザリが続けて出ました。そのうちいくつかは、修正版に更新しただけでは何も変わらず、新しい引数を渡すか、保存済みの資格情報を作り直す必要があります。このリポジトリはそこを点検します。

- 記事：[MCPのOAuthは更新だけでは塞がらない――手元で再現して点検ツールを作った](https://qiita.com/01rabbit/)（公開予定）

## 特徴

- Python 3.8 以上の標準ライブラリだけで動きます。追加のインストールは要りません。
- 読み取り専用です。ファイルを書き換えず、ネットワークにも接続しません。
- 版が古いことだけでは HIGH にしません。対象のアドバイザリはどれも HTTP 経路の問題で、stdio で使う分には影響がないためです。HIGH は「修正版なのに修正が効いていない」コードに限っています。

## 収録しているもの

| ファイル | 役割 |
|---|---|
| `mcp_trust_check.py` | 点検スクリプト本体 |
| `tests/` | 試験と、わざと問題を仕込んだ素材（`fixtures/`） |
| `lab/` | GHSA-qx49-fqc8-xw99 を 127.0.0.1 の中だけで再現する検証環境 |
| `results/` | 記事で使った再現結果（JSONL） |

## 使い方

```bash
# プロジェクトのフォルダを点検する
python3 mcp_trust_check.py ~/src/my-agent

# Claude Desktop / Claude Code の設定も読む。JSON で出す
python3 mcp_trust_check.py ~/src/my-agent --claude-config --json

# 試験コード（tests/ など）も対象にする（既定では外す）
python3 mcp_trust_check.py ~/src/my-agent --include-tests
```

HIGH が1件でもあれば終了コード 1 を返すので、CI にそのまま組み込めます。

## 何を見ているか

| 種別 | 重さ | 内容 |
|---|---|---|
| `issuer-not-set` | HIGH | `ClientCredentialsOAuthProvider` / `PrivateKeyJWTOAuthProvider`（Python）、`ClientCredentialsProvider` などの同梱プロバイダ（TypeScript）を、期待する issuer（`issuer=` / `expectedIssuer`）なしで作っている |
| `no-issuer-option` | HIGH | Python の `RFC7523OAuthClientProvider` を使っている。このクラスには issuer を渡す手段がない |
| `issuer-check-disabled` | HIGH | `skipIssuerMetadataValidation: true` で issuer の検査を切っている |
| `audience-not-checked` | MEDIUM | `requireBearerAuth(...)` に `expectedResource` がなく、他のサービス向けのトークンを受け付ける |
| `redirect-follow` | MEDIUM | `redirectPolicy: 'follow'` で、別オリジンへのリダイレクト先にヘッダや本文を送り直す |
| `http-all-interfaces` | MEDIUM | HTTP で動く MCP サーバーを 0.0.0.0 で待ち受けている |
| `outdated-sdk` | MEDIUM | 修正版より古い SDK がある（lock ファイル、インストール済みのパッケージ、go.mod） |
| `oauth-client-in-use` | INFO | 対話型の `OAuthClientProvider` を使っている。修正版への更新に加え、保存済みのクライアント登録を一度消して issuer に結び付け直す必要がある |
| `issuer-unknown` | INFO | 引数を `**kwargs` などで間接的に渡しているため、issuer の有無を判定できない |
| `http-transport` | INFO | HTTP で動く MCP サーバーがある。Origin の検証、認証、セッションごとのインスタンス分離を確かめる |

版の照合に使う表は `mcp_trust_check.py` の先頭にあります。各行の `src` が `G` のものは GitHub のアドバイザリ本文で確認した値、`C` のものは Cloud Security Alliance の研究ノート（2026-11-09）の表から取った値で、こちらでは再確認していません。

## 再現環境（lab）

GHSA-qx49-fqc8-xw99（OAuth クライアントが、MCP サーバーの選んだ認可サーバーへ資格情報を送る）を、Python SDK の複数の版で再現します。

```bash
cd lab
bash run_all.sh            # 1.29.1 / 1.30.0 / 2.3.0 を試す。初回は PyPI から取得する
VERSIONS="1.30.0" bash run_all.sh
```

- 127.0.0.1 の 9100（正規の認可サーバー）、9200（悪性の MCP サーバー）、9300（悪性の認可サーバー）だけを使います。外部とは通信しません。
- クライアントの秘密はラボ専用の偽物（`LAB-ONLY-not-a-real-secret`）です。
- 悪性の認可サーバーは、トークン要求で届いた項目名を記録するだけです。受け取った値を使ったり転送したりはしません。

2026-11-12 に実行した結果です（`results/` に生データ）。

| mcp | `issuer=` | 生成した場所 | 表示された警告 | 秘密が悪性の認可サーバーに届いたか |
|---|---|---|---|---|
| 1.29.1 | なし | アプリのモジュール | なし | 届いた |
| 1.29.1 | なし | `__main__` | なし | 届いた |
| 1.30.0 | なし | アプリのモジュール | なし | 届いた |
| 1.30.0 | なし | `__main__` | DeprecationWarning | 届いた |
| 1.30.0 | あり | アプリのモジュール | なし | 届かない |
| 2.3.0 | なし | アプリのモジュール | MCPDeprecationWarning | 届いた |
| 2.3.0 | なし | `__main__` | MCPDeprecationWarning | 届いた |
| 2.3.0 | あり | アプリのモジュール | なし | 届かない |

## 限界

- コードの点検は正規表現によるものです。プロバイダを別の関数で包んでいる、設定ファイルから組み立てている、といった書き方は見逃すことがあります（判定できない場合は `issuer-unknown` を出します）。
- 再現しているのは Python SDK だけです。TypeScript と Go の項目は、アドバイザリ本文と CSA の研究ノートに依拠しています。
- Python・TypeScript・Go の公式 SDK 以外（Rust の SDK や独自実装）は対象外です。
- 何も出なかったことは安全の保証になりません。

## 試験

```bash
python3 -m unittest discover -s tests -v
```

## 参考

- [GHSA-qx49-fqc8-xw99（Python SDK）](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-qx49-fqc8-xw99)
- [GHSA-6qxp-vccf-f47h（TypeScript SDK）](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-6qxp-vccf-f47h)
- [MCP 仕様 2026-07-28 版 Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- [Cloud Security Alliance: MCP's Transport Trust Gap（2026-11-09）](https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-transport-trust-gap-20261109-csa-style/)

## ライセンス

MIT License（Copyright (c) 2026 Mr.Rabbit）
