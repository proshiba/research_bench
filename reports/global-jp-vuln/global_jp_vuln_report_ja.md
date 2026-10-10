# GLOBAL_JP_VULN — 日本のレポーターが脆弱性攻撃として報告した送信元IP（過去90日）

> **この文書は Claude（AI）が自動生成したものです。人の確認を前提としてください。**

送信元の所在地は限定していません。「**日本の人が、脆弱性攻撃として報告した**」ことだけを
抽出の条件にしています。対象 IP への接続・走査は一切行っていません。

## 1. 取得条件

| 項目 | 値 |
| --- | --- |
| データセット | GLOBAL_JP_VULN |
| 作成日時 | 2026-10-10T01:41:57Z |
| 調査期間 | 2026-07-12T01:41:57Z 〜 2026-10-10T01:41:57Z（ローリング 90 日） |
| Blacklist 条件 | `confidenceMinimum=75` `limit=100000` `ipVersion=4`（国フィルタなし） |
| Blacklist 生成日時 | 2026-10-10T01:38:16Z |
| Check 条件 | `maxAgeInDays=90` `verbose` |
| 乱数シード | 20261010 |

## 2. 件数

| 項目 | 件数 |
| --- | --- |
| Blacklist 取得 | 100000 |
| うち候補（30日以内・信頼度75以上） | 99339 |
| Check 対象に選定 | 9499 |
| Check 成功 | 9499 |
| Check 失敗 | 0 |
| キャッシュ再利用 | 0 |
| **日本の脆弱性報告あり（採用候補）** | **3226** |
| **GLOBAL_JP_VULN 採用** | **2763** |

### 優先度

| 優先度 | 意味 | 件数 |
| --- | --- | --- |
| **P1** 最優先 | 複数の日本レポーター＋E2/E3、または具体的証拠が複数 | **177** |
| **P2** 優先 | 日本の strict 報告が複数、または単独＋E2 以上 | **435** |
| P3 参考 | 日本レポーター1人・根拠が弱い | 2151 |
| 除外 | 研究スキャナ・走査のみ・脆弱性カテゴリなし | 6736 |

## 3. 日本報告のカテゴリ別件数

**IP 全体ではなく、日本の報告だけから数えています。**

| カテゴリ | IP 数 |
| --- | --- |
| 15 Hacking | 1846 |
| 21 Web App Attack | 1405 |
| 16 SQL Injection | 156 |
| 23 IoT Targeted | 7 |

## 4. 証拠の段階

コメントから決定論的に判定したものです。語の一致だけで決めており、意味は読んでいません。

| 段階 | 内容 | IP 数 |
| --- | --- | --- |
| E3 | CVE番号・SQLiペイロード・RCE要求・Webシェル等の具体的な攻撃証跡 | 136 |
| E2 | 製品・脆弱性に固有の探索（phpunit、HNAP1、boaform、製品名つきパス等） | 116 |
| E1 | 一般的な攻撃的探索（.env、.git/config、wp-login.php、管理画面等） | 320 |
| E0 | 根拠不足（カテゴリのみ、コメントなし、通常のクローラと区別できない） | 2191 |

## 5. 日本の脆弱性レポーター数の分布

| レポーター数 | IP 数 |
| --- | --- |
| 1 人 | 1682 |
| 2 人 | 663 |
| 3 人 | 184 |
| 4 人 | 80 |
| 5+ 人 | 154 |

## 6. 送信元の分布（採用分）

### 国

| 国 | IP 数 |
| --- | --- |
| US | 696 |
| NL | 237 |
| DE | 220 |
| SG | 185 |
| GB | 182 |
| HK | 130 |
| CN | 120 |
| IN | 85 |
| KR | 81 |
| ID | 70 |
| CA | 70 |
| FR | 65 |

**所在地は攻撃者の国籍や所属を意味しません。** クラウド、VPN、NAT、侵害されたホスト、
IP の再割り当てをいずれも含みます。

### ISP

| ISP | IP 数 |
| --- | --- |
| Infrawatch Limited | 324 |
| Microsoft Corporation | 304 |
| UCLOUD INFORMATION TECHNOLOGY (HK) LIMITED | 124 |
| VPN Consumer Singapore, Republic of Singapore | 115 |
| DigitalOcean, LLC | 76 |
| Google LLC | 67 |
| NL MODAT | 56 |
| Asia Pacific Network Information Center, Pty. Ltd. | 53 |
| Microsoft Limited | 47 |
| Korea Telecom | 37 |
| Linode | 34 |
| TECHOFF SRV LIMITED | 30 |

### usageType

| 種別 | IP 数 |
| --- | --- |
| Data Center/Web Hosting/Transit | 2157 |
| Fixed Line ISP | 533 |
| Commercial | 27 |
| University/College/School | 23 |
| Mobile ISP | 12 |
| Content Delivery Network | 6 |
| Government | 5 |

## 7. 研究スキャナ

**削除していません。** 印を付けて、高確度のものだけ主対象から外しています。

| 項目 | 件数 |
| --- | --- |
| 判定した総数 | 1274 |
| 高確度として主対象から除外 | 1077 |

| 名称 | 件数 |
| --- | --- |
| Shadowserver Foundation | 358 |
| Censys | 302 |
| 名称に scanner を含む | 145 |
| Driftnet / internet-measurement.com | 144 |
| BinaryEdge | 123 |
| Stretchoid | 48 |
| BitSight | 47 |
| LeakIX | 40 |
| Shodan | 36 |
| CriminalIP | 14 |
| ipip.net | 8 |
| SecurityTrails | 5 |
| 大学等の研究スキャン | 4 |

判定は hostname・domain・ISP の**名乗り**で行っています。クラウドの AS に属するというだけでは
判定していません。

## 8. Exploited Host

**413 件**の採用 IP に、日本からのカテゴリ20（Exploited Host）報告が付いています。
これは攻撃の技法ではなく、**送信元自体が侵害されている可能性**を示す補助情報です。
踏み台にされた正規ホストである場合、送信元の所有者も被害者です。

## 9. 除外の内訳

| 理由 | 件数 |
| --- | --- |
| 日本報告が走査・総当たりのみで脆弱性カテゴリなし | 4449 |
| 日本からの報告なし | 1794 |
| 既知研究スキャナ（Shadowserver Foundation） | 159 |
| 既知研究スキャナ（Censys） | 126 |
| 既知研究スキャナ（Driftnet / internet-measurement.com） | 46 |
| 既知研究スキャナ（LeakIX） | 40 |
| 既知研究スキャナ（Stretchoid） | 35 |
| 日本報告に脆弱性カテゴリなし | 30 |
| 既知研究スキャナ（BinaryEdge） | 28 |
| 既知研究スキャナ（Shodan） | 24 |
| 既知研究スキャナ（ipip.net） | 3 |
| 既知研究スキャナ（CriminalIP） | 1 |
| 既知研究スキャナ（大学等の研究スキャン） | 1 |

## 10. 後続調査を推奨する上位 50 件

優先度と優先スコアの順です。**スコアは AbuseIPDB の信頼度そのままではなく**、
日本の観測者数・証拠の具体性・新しさから別に計算したものです。

| # | IP | 優先 | 点 | 国 | 証拠 | 日本レポーター | 最新 | カテゴリ | ISP |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 20.219.185.206 | P1 | 93 | IN | E3 | 11 | 2026-10-09 | Hacking;SQL Injection;Web App Attack | Microsoft Corporation |
| 2 | 195.178.110.204 | P1 | 93 | NL | E3 | 6 | 2026-10-09 | Hacking;SQL Injection;Web App Attack;IoT Targeted | TECHOFF SRV LIMITED |
| 3 | 179.43.150.26 | P1 | 93 | CH | E3 | 11 | 2026-10-09 | Hacking;SQL Injection;Web App Attack | PRIVATE LAYER INC |
| 4 | 49.0.202.115 | P1 | 93 | SG | E3 | 8 | 2026-10-09 | Hacking;SQL Injection;Web App Attack | Huawei Cloud Singapore Regio |
| 5 | 13.70.107.184 | P1 | 93 | AU | E3 | 11 | 2026-10-09 | Hacking;SQL Injection;Web App Attack | Microsoft Corporation |
| 6 | 103.63.101.24 | P1 | 93 | ID | E3 | 11 | 2026-10-09 | Hacking;SQL Injection;Web App Attack | PT Berkah Maju Interasional |
| 7 | 20.210.186.186 | P1 | 93 | JP | E3 | 10 | 2026-10-09 | Hacking;SQL Injection;Web App Attack | Microsoft Corporation |
| 8 | 20.194.96.114 | P1 | 93 | KR | E3 | 13 | 2026-10-09 | Hacking;SQL Injection;Web App Attack | Microsoft Corporation |
| 9 | 144.225.6.182 | P1 | 93 | US | E3 | 8 | 2026-10-09 | Hacking;SQL Injection;Web App Attack | Ace Data Centers II, L.L.C. |
| 10 | 45.91.64.10 | P1 | 93 | RU | E3 | 7 | 2026-10-08 | Hacking;SQL Injection;Web App Attack | F6 |
| 11 | 89.126.211.166 | P1 | 93 | UZ | E3 | 12 | 2026-10-08 | Hacking;SQL Injection;Web App Attack | Uzbektelekom Joint Stock Com |
| 12 | 94.154.43.164 | P1 | 93 | NL | E3 | 8 | 2026-10-08 | Hacking;SQL Injection;Web App Attack | Storm Industries LLC |
| 13 | 102.244.97.185 | P1 | 93 | CM | E3 | 10 | 2026-10-08 | Hacking;SQL Injection;Web App Attack | Orange Cameroun SA |
| 14 | 167.71.233.141 | P1 | 93 | IN | E3 | 8 | 2026-10-08 | Hacking;SQL Injection;Web App Attack | DigitalOcean, LLC |
| 15 | 109.105.209.19 | P1 | 93 | US | E3 | 6 | 2026-10-08 | Hacking;SQL Injection;Web App Attack | ICG-ZEN-LAX-1 |
| 16 | 160.250.132.238 | P1 | 93 | VN | E3 | 7 | 2026-10-07 | Hacking;SQL Injection;Web App Attack | VPS4U TECHNOLOGY COMPANY LIM |
| 17 | 20.249.5.100 | P1 | 93 | KR | E3 | 11 | 2026-10-07 | Hacking;SQL Injection;Web App Attack | Microsoft Corporation |
| 18 | 45.138.12.51 | P1 | 93 | PL | E3 | 9 | 2026-10-07 | Hacking;SQL Injection;Web App Attack | TC DATACENTER LIMITED MANAGE |
| 19 | 103.46.186.148 | P1 | 93 | ID | E3 | 12 | 2026-10-07 | Hacking;SQL Injection;Web App Attack | PT Air Lintas Komunikasi |
| 20 | 45.91.64.6 | P1 | 93 | RU | E3 | 8 | 2026-10-07 | Hacking;SQL Injection;Web App Attack | F6 |
| 21 | 45.43.37.254 | P1 | 93 | TW | E3 | 8 | 2026-10-07 | Hacking;SQL Injection;Web App Attack | UCLOUD |
| 22 | 107.155.48.46 | P1 | 93 | US | E3 | 8 | 2026-10-05 | Hacking;SQL Injection;Web App Attack | UCLOUD |
| 23 | 31.57.62.245 | P1 | 93 | LV | E3 | 10 | 2026-10-04 | Hacking;SQL Injection;Web App Attack | CGI GLOBAL LIMITED |
| 24 | 163.7.1.156 | P1 | 93 | ID | E3 | 8 | 2026-10-03 | Hacking;SQL Injection;Web App Attack | BYTEPLUS |
| 25 | 45.138.12.14 | P1 | 85 | HK | E3 | 5 | 2026-10-10 | Web App Attack | TC DATACENTER LIMITED MANAGE |
| 26 | 20.213.164.192 | P1 | 85 | AU | E3 | 10 | 2026-10-10 | Hacking;Web App Attack | Microsoft Corporation |
| 27 | 20.219.160.77 | P1 | 85 | IN | E3 | 9 | 2026-10-10 | Hacking;Web App Attack | Microsoft Corporation |
| 28 | 185.177.72.24 | P1 | 85 | FR | E3 | 7 | 2026-10-09 | Hacking;Web App Attack | FBW NETWORKS SAS |
| 29 | 52.141.3.247 | P1 | 85 | KR | E3 | 7 | 2026-10-09 | Hacking;Web App Attack | Microsoft Corporation |
| 30 | 4.224.122.112 | P1 | 85 | IN | E3 | 7 | 2026-10-09 | Hacking;Web App Attack | Microsoft Corporation |
| 31 | 23.100.83.23 | P1 | 85 | US | E3 | 9 | 2026-10-09 | Hacking;Web App Attack | Microsoft Corporation |
| 32 | 158.23.176.177 | P1 | 85 | MX | E3 | 10 | 2026-10-09 | Hacking;Web App Attack | Microsoft Singapore Pte. Ltd |
| 33 | 45.115.26.203 | P1 | 85 | NL | E3 | 8 | 2026-10-09 | Hacking;Web App Attack | SolidCore Hosting LTD |
| 34 | 45.148.10.16 | P1 | 85 | NL | E3 | 8 | 2026-10-09 | Hacking;Web App Attack | TECHOFF SRV LIMITED |
| 35 | 20.197.26.46 | P1 | 85 | IN | E3 | 13 | 2026-10-09 | Hacking;Web App Attack | Microsoft Corporation |
| 36 | 20.92.239.62 | P1 | 85 | AU | E3 | 10 | 2026-10-09 | Hacking;Web App Attack | Microsoft Corporation |
| 37 | 20.239.176.5 | P1 | 85 | HK | E3 | 6 | 2026-10-09 | Hacking;Web App Attack | Microsoft Corporation |
| 38 | 130.12.180.117 | P1 | 85 | DE | E3 | 14 | 2026-10-09 | Hacking;Web App Attack | Virtualine Technologies |
| 39 | 20.214.170.255 | P1 | 85 | KR | E3 | 9 | 2026-10-09 | Hacking;Web App Attack | Microsoft Corporation |
| 40 | 20.210.128.125 | P1 | 85 | JP | E3 | 11 | 2026-10-09 | Hacking;Web App Attack | Microsoft Corporation |
| 41 | 77.83.39.94 | P1 | 85 | NL | E3 | 6 | 2026-10-09 | Hacking;Web App Attack | Pitline Ltd |
| 42 | 20.210.166.54 | P1 | 85 | JP | E3 | 7 | 2026-10-09 | Hacking;Web App Attack | Microsoft Corporation |
| 43 | 40.74.77.37 | P1 | 85 | JP | E3 | 9 | 2026-10-09 | Hacking;Web App Attack | Microsoft Corporation |
| 44 | 20.204.16.113 | P1 | 85 | IN | E3 | 9 | 2026-10-09 | Hacking;Web App Attack | Microsoft Corporation |
| 45 | 20.92.83.244 | P1 | 85 | AU | E3 | 8 | 2026-10-09 | Hacking;Web App Attack | Microsoft Corporation |
| 46 | 104.208.73.227 | P1 | 85 | HK | E3 | 9 | 2026-10-09 | Hacking;Web App Attack | Microsoft Corporation |
| 47 | 213.209.159.133 | P1 | 85 | DE | E3 | 6 | 2026-10-09 | Hacking;Web App Attack | Feo Prest SRL |
| 48 | 46.151.182.7 | P1 | 85 | DE | E3 | 6 | 2026-10-09 | Hacking;Web App Attack | Ghosty Networks LLC |
| 49 | 94.154.43.74 | P1 | 85 | NL | E3 | 6 | 2026-10-09 | Hacking;Web App Attack | Storm Industries LLC |
| 50 | 93.123.109.101 | P1 | 85 | NL | E3 | 8 | 2026-10-08 | Hacking;Web App Attack | TECHOFF SRV LIMITED |

## 11. 抽出上の偏りと制約

### 母集団の偏り

- **Blacklist が上限で打ち切られています。** `limit=100000` に対して
  100000 件が返っており、これは Basic の上限そのものです。信頼度の高い順に
  切られているため、**信頼度 75〜84 の帯は 1 件も含まれていません**。層化サンプルも
  85〜94 と 95〜100 の 2 帯からしか引けていません。
- **候補 99339 件に対し、確認できたのは 9499 件**（1 日の API 上限）です。
  `lastReportedAt` の新しい順を主軸にしているので、**古い報告しかない IP は見ていません**。
- したがって「P1 が 177 件」は**この母集団での件数**であり、世界全体の件数ではありません。

### 判定の限界

- **AbuseIPDB のカテゴリはレポーターの自己申告**です。誤分類を含みます。
- **証拠段階は語の一致だけ**で決めています。文意は読んでいないので、無害な文脈で
  CVE 番号に触れただけのコメントが E3 になることがあります。逆に、言い回しが
  一覧に無ければ具体的な攻撃でも E0 になります。
- **カテゴリ15（Hacking）は範囲が広い**ため、単独では優先度を上げていません。
- reports 配列は最大 10,000 件です。超えた IP では確認数が下限値になります
  （`reports_truncated=true`）。

### 解釈の注意

- **レポーターが日本に所在することは、日本企業や日本所在システムへの攻撃を意味しません。**
  日本に観測者や監視機器が多いというだけでも同じ結果になります。
- **IP の所在地・ISP・ASN は、攻撃者の国籍や所属を示しません。**
- **コメント中の CVE 名や攻撃名だけで帰属を断定しないでください。**
- 本調査は AbuseIPDB の公開情報のみを使用しています。能動調査は行っていません。
