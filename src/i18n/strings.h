// 唯一文案表。
//
// 格式：X(枚举, en, zh-Hans, zh-Hant, zh-Hk, ja)
//  - 五个语言列必须同时存在，scripts/check_i18n.py 与 tools/genfont.py 会在
//    构建期检查缺翻译与缺字，缺一即构建失败。
//  - 固定 UI 文案与风险模板都在这里；外部文本永远不会进入本表，
//    因此外部文本无法伪造标题、按钮或可信徽标（需求 §6.3）。
//  - 金额、公钥、协议字段不因本地化改变规范值（需求 §7）。
#ifndef ROCKEY_I18N_STRINGS_H
#define ROCKEY_I18N_STRINGS_H

#define ROCKEY_STRING_TABLE(X)                                                                       \
  X(kImportTitle, "Import same key", "导入同一私钥", "匯入同一私鑰", "匯入同一私鑰", "同じ鍵を取り込む") \
  X(kImportWaiting, "Connect Keymaster to import", "连接 Keymaster 导入", "連接 Keymaster 匯入", "連接 Keymaster 匯入", "Keymaster を接続して取り込む") \
  X(kImportWarning, "Import this identity and its payment ledger. Software password is not kept on device.", "导入此身份与付款账本。设备不保存软件密码封装。", "匯入此身份與付款帳本。裝置不保留軟件密碼封裝。", "匯入此身份與付款帳本。裝置不保留軟件密碼封裝。", "この識別情報と支払台帳を取り込む。ソフトウェアの暗号化鍵は保存しない。") \
  X(kInitializeChoice, "New key or import", "新建私钥或导入", "新建私鑰或匯入", "新建私鑰或匯入", "新しい鍵または取り込み") \
  X(kInitializeNew, "New key", "新建私钥", "新建私鑰", "新建私鑰", "新しい鍵") \
  /* 通用 */                                                                                        \
  X(kSoundAutoOn, "Auto approval sound ON", "开启自动授权声音", "開啟自動授權聲音", "開啟自動授權聲音", "自動許可の音をオン") \
  X(kSoundAutoOff, "Auto approval sound OFF", "关闭自动授权声音", "關閉自動授權聲音", "關閉自動授權聲音", "自動許可の音をオフ") \
  X(kSoundManualOn, "Manual approval sound ON", "开启手动授权声音", "開啟手動授權聲音", "開啟手動授權聲音", "手動許可の音をオン") \
  X(kSoundManualOff, "Manual approval sound OFF", "关闭手动授权声音", "關閉手動授權聲音", "關閉手動授權聲音", "手動許可の音をオフ") \
  X(kAppName, "Rockey", "Rockey", "Rockey", "Rockey", "Rockey")                                       \
  X(kOk, "OK", "确定", "確定", "確定", "OK")                                                         \
  X(kCancel, "Cancel", "取消", "取消", "取消", "キャンセル")                                           \
  X(kBack, "Back", "返回", "返回", "返回", "戻る")                                                    \
  X(kYes, "Yes", "是", "是", "是", "はい")                                                          \
  X(kNo, "No", "否", "否", "否", "いいえ")                                                          \
  X(kUnknown, "Unknown", "未知", "未知", "未知", "不明")                                              \
  X(kNone, "None", "无", "無", "無", "なし")                                                         \
  /* 启动 / 设备信息 */                                                                              \
  X(kBootStarting, "Starting", "正在启动", "正在啟動", "正在啟動", "起動中")                          \
  X(kInfoTitle, "Device", "设备", "裝置", "裝置", "デバイス")                                         \
  X(kInfoBoard, "Board", "板型", "板型", "板型", "基板")                                             \
  X(kInfoFirmware, "Firmware", "固件", "韌體", "韌體", "ファームウェア")                             \
  X(kInfoProtocol, "Protocol", "协议", "協議", "協議", "プロトコル")                                  \
  X(kInfoLanguage, "Language", "语言", "語言", "語言", "言語")                                       \
  X(kInfoPublicKey, "Public key", "公钥", "公鑰", "公鑰", "公開鍵")                                   \
  X(kInfoHeap, "Free RAM", "空闲内存", "可用記憶體", "可用記憶體", "空きメモリ")                      \
  X(kInfoSecurityNote,                                                                              \
    "Experimental device. Not a tamper-proof chip.",                                                 \
    "实验设备，非防拆安全芯片。", "實驗裝置，非防拆安全晶片。", "實驗裝置，非防拆安全晶片。",            \
    "実験用デバイス。改ざん防止チップではありません。")                                               \
  X(kSecFlashEnc, "Flash Encryption", "Flash 加密", "Flash 加密", "Flash 加密",                      \
    "Flash 暗号化")                                                                                  \
  X(kSecSecureBoot, "Secure Boot", "Secure Boot", "Secure Boot", "Secure Boot",                       \
    "Secure Boot")                                                                                   \
  X(kSecDisabled, "Disabled", "未启用", "未啟用", "未啟用", "無効")                                   \
  /* 锁定与 PIN */                                                                                   \
  X(kLockTitle, "Unlock wallet", "解锁钱包", "解鎖錢包", "解鎖錢包", "ウォレット解除")                  \
  X(kLockUnlock, "Unlock", "解锁", "解鎖", "解鎖", "解除") \
  X(kLockUnlocking, "Unlocking...", "正在解锁中", "正在解鎖中", "正在解鎖中", "解除しています") \
  X(kLockEnterPin, "Enter PIN", "输入密码", "輸入密碼", "輸入密碼", "PINを入力")                      \
  X(kLockSetPin, "Set a new PIN", "设置新密码", "設定新密碼", "設定新密碼", "新しいPINを設定")         \
  X(kLockConfirmPin, "Enter it again", "再次输入", "再次輸入", "再次輸入", "もう一度入力")              \
  X(kLockPinMismatch, "PINs did not match", "两次输入不一致", "兩次輸入不一致", "兩次輸入不一致",      \
    "PINが一致しません")                                                                              \
  X(kLockWrongPin, "Wrong PIN", "密码错误", "密碼錯誤", "密碼錯誤", "PINが違います")                   \
  X(kLockWaitSeconds, "%lu s to retry", "%lu 秒后可重试", "%lu 秒後可重試", "%lu 秒後可重試",           \
    "%lu 秒後に再試行")                                                                              \
  X(kLockDigits, "Digits", "位数", "位數", "位數", "桁数")                                           \
  X(kLockDeleteDigit, "Delete last", "删除上一位", "刪除上一位", "刪除上一位", "直前の桁を削除")         \
  X(kLockCancelInput, "Cancel input", "取消输入", "取消輸入", "取消輸入", "入力を中止")                 \
  X(kLockNoKey, "No wallet key yet", "设备尚无钱包密钥", "裝置尚無錢包密鑰", "裝置尚無錢包密鑰",         \
    "ウォレット鍵が未設定です")                                                                       \
  X(kLockStateLocked, "Locked", "已锁定", "已鎖定", "已鎖定", "ロック中")                            \
  X(kLockStateUnlocked, "Unlocked", "已解锁", "已解鎖", "已解鎖", "解除済み")                        \
  X(kLockStateSession, "Session active", "会话进行中", "會話進行中", "會話進行中", "セッション中")       \
  X(kLockedNotice, "Locked", "已锁定", "已鎖定", "已鎖定", "ロック")                                  \
  X(kLockOldPin, "Current PIN", "当前密码", "目前密碼", "目前密碼", "現在のPIN")                  \
  X(kMenuChangePin, "Change PIN", "更改密码", "變更密碼", "變更密碼", "PINを変更")              \
  /* 主菜单 */                                                                                       \
  X(kMenuTitle, "Menu", "菜单", "選單", "選單", "メニュー")                                           \
  X(kMenuReview, "Review request", "查看待确认请求", "檢視待確認請求", "檢視待確認請求",                \
    "確認待ちの要求")                                                                                \
  X(kMenuGrants, "Session decisions", "会话决定", "會話決定", "會話決定", "セッション決定")             \
  X(kMenuDeviceInfo, "Device info", "设备信息", "裝置資訊", "裝置資訊", "デバイス情報")                 \
  X(kMenuKeyDetail, "Full public key", "完整公钥", "完整公鑰", "完整公鑰", "公開鍵全体")                 \
  X(kMenuImportKey, "Import key", "迁入密钥", "匯入密鑰", "匯入密鑰", "鍵のインポート")                \
  X(kMenuExportKey, "Export key", "迁回密钥", "匯出密鑰", "匯出密鑰", "鍵のエクスポート")              \
  X(kMenuRecoveryBackup, "Recovery backup", "恢复备份", "復原備份", "復原備份", "復旧バックアップ")       \
  X(kMenuErase, "Erase device", "擦除设备", "清除裝置", "清除裝置", "デバイスを消去")                   \
  X(kMenuEmpty, "Nothing to review", "没有待确认请求", "沒有待確認請求", "沒有待確認請求",              \
    "確認待ちはありません")                                                                           \
  /* 阅读页 */                                                                                        \
  X(kReadTitle, "Review details", "审核内容", "審核內容", "審核內容", "確認内容")                        \
  X(kReadChapter, "Chapter %u/%u", "第 %u/%u 章", "第 %u/%u 章", "第 %u/%u 章", "%u/%u 章")           \
  X(kReadHoldFaster, "Hold to scroll faster", "按住可加速滚动", "按住可加速捲動", "按住可加速捲動",     \
    "長押しで高速スクロール")                                                                          \
  X(kReadEnd, "End of text", "文本结束", "文本結束", "文本結束", "本文終わり")                          \
  X(kReadMissingGlyph, "Missing glyph U+%04X", "缺字 U+%04X", "缺字 U+%04X", "缺字 U+%04X",           \
    "文字欠落 U+%04X")                                                                                \
  X(kReadOpenMenu, "Hold B for options", "长按 B 打开菜单", "長按 B 開啟選單", "長按 B 開啟選單",        \
    "B長押しでメニュー")                                                                              \
  /* 对端公钥（设备只展示完整公钥，不识别企业或个人身份） */                                            \
  X(kChannelPeerKey, "Counterparty key", "对端公钥", "對端公鑰", "對端公鑰", "相手の公開鍵")             \
  /* 请求处理菜单 */                                                                                  \
  X(kReqTitle, "How to handle this request?", "如何处理这个请求？", "如何處理這個請求？",              \
    "如何處理這個請求？", "この要求をどう扱いますか？")                                               \
  X(kReqContinueReading, "Continue reading", "继续阅读", "繼續閱讀", "繼續閱讀", "続きを読む")           \
  X(kReqDenyOnce, "Deny this once", "仅本次拒绝", "僅本次拒絕", "僅本次拒絕", "今回のみ拒否")           \
  X(kReqAllowOnce, "Allow this once", "仅本次允许", "僅本次允許", "僅本次允許", "今回のみ許可")         \
  X(kReqAllowSession, "Allow for session", "此会话允许", "此會話允許", "此會話允許", "セッションで許可")   \
  X(kReqDenySession, "Deny for session", "此会话否决", "此會話拒絕", "此會話拒絕", "セッションで拒否")   \
  X(kReqPending, "Queued request", "排队中的请求", "排隊中的請求", "排隊中的請求", "待機中の要求")        \
  /* 摘要与确认 */                                                                                    \
  X(kSumTitle, "Check the details", "核对关键内容", "核對關鍵內容", "核對關鍵內容", "重要項目を確認")      \
  X(kSumOperation, "Operation", "操作", "操作", "操作", "操作")                                       \
  X(kSumObject, "Object", "对象", "對象", "對象", "対象")                                              \
  X(kSumAmount, "Amount", "金额", "金額", "金額", "金額")                                             \
  X(kBitfsQuoteSign, "File quote", "文件报价", "檔案報價", "檔案報價", "ファイル見積もり") \
  X(kBitfsAuthorizeSign, "Purchase authorization", "付款授权", "付款授權", "付款授權", "支払い許可") \
  X(kBitfsDeliverySign, "Content delivery", "内容交付", "內容交付", "內容交付", "コンテンツ配信") \
  X(kBitfsClaimSign, "Arbitration claim", "仲裁申请", "仲裁申請", "仲裁申請", "仲裁申請") \
  X(kBitfsReceiptSign, "Arbitration receipt", "仲裁回执", "仲裁回執", "仲裁回執", "仲裁受領書") \
  X(kBitfsRetrievalSign, "Content retrieval request", "内容取回请求", "內容取回請求", "內容取回請求", "コンテンツ取得要求") \
  X(kBitfsResultSign, "Content retrieval result", "内容取回结果", "內容取回結果", "內容取回結果", "コンテンツ取得結果") \
  X(kOpBitfsWire, "BitFS message signature", "BitFS 消息签名", "BitFS 訊息簽名", "BitFS 訊息簽名", "BitFS メッセージ署名") \
  X(kBitfsKind, "BitFS message kind", "BitFS 消息类型", "BitFS 訊息類型", "BitFS 訊息類型", "BitFS メッセージ種別") \
  X(kBitfsSeed, "Seed hash", "Seed 哈希", "Seed 雜湊", "Seed 雜湊", "Seed ハッシュ") \
  X(kBitfsSeedPrice, "Seed price (sat)", "Seed 价格 (sat)", "Seed 價格 (sat)", "Seed 價格 (sat)", "Seed 価格 (sat)") \
  X(kBitfsBlockPrice, "Block price (sat)", "区块价格 (sat)", "區塊價格 (sat)", "區塊價格 (sat)", "ブロック価格 (sat)") \
  X(kBitfsQuote, "Quote identifier", "报价标识", "報價識別碼", "報價識別碼", "見積もり識別子") \
  X(kBitfsRefund, "Refund transaction ID", "退款交易 ID", "退款交易 ID", "退款交易 ID", "返金取引 ID") \
  X(kBitfsSequence, "Payment sequence", "付款序号", "付款序號", "付款序號", "支払い順序") \
  X(kBitfsAuthorization, "Authorization identifier", "授权标识", "授權識別碼", "授權識別碼", "許可識別子") \
  X(kBitfsClaim, "Claim identifier", "仲裁申请标识", "仲裁申請識別碼", "仲裁申請識別碼", "仲裁申請識別子") \
  X(kBitfsArbiterAmount, "Arbiter amount (sat)", "仲裁金额 (sat)", "仲裁金額 (sat)", "仲裁金額 (sat)", "仲裁金額 (sat)") \
  X(kBitfsResult, "Retrieval result", "取回结果", "取回結果", "取回結果", "取得結果") \
  X(kChannelPeer, "Peer public key", "对方公钥", "對方公鑰", "對方公鑰", "相手の公開鍵") \
  X(kSumScope, "Scope", "授权范围", "授權範圍", "授權範圍", "許可範囲")                                \
  X(kConnectAudience, "Audience", "接收方", "接收方", "接收方", "受信者") \
  X(kConnectRequest, "Request ID", "请求编号", "請求編號", "請求編號", "要求 ID") \
  X(kConnectIssued, "Issued (Unix)", "签发时间 (Unix)", "簽發時間 (Unix)", "簽發時間 (Unix)", "発行時刻 (Unix)") \
  X(kConnectExpires, "Expires (Unix)", "到期时间 (Unix)", "到期時間 (Unix)", "到期時間 (Unix)", "有効期限 (Unix)") \
  X(kConnectClaim, "Identity field", "身份字段", "身分欄位", "身分欄位", "識別情報") \
  X(kConnectContentType, "Content type", "内容类型", "內容類型", "內容類型", "内容の種類") \
  X(kConnectContentLength, "Content bytes", "内容字节数", "內容位元組數", "內容位元組數", "内容のバイト数") \
  X(kConnectContentHash, "Content SHA256", "内容 SHA256", "內容 SHA256", "內容 SHA256", "内容 SHA256") \
  X(kSumLimits, "Limits", "限额", "限額", "限額", "上限")                                             \
  X(kSumRisks, "Warnings", "警告", "警告", "警告", "警告")                                            \
  X(kSumExcludes, "Not included", "不包含", "不包含", "不包含", "含まないもの")                       \
  X(kSumHoldConfirm, "Hold to approve", "长按授权同意", "長按授權同意", "長按授權同意", "長押しで許可") \
  X(kSumHoldDeny, "Hold B to deny", "长按 B 拒绝", "長按 B 拒絕", "長按 B 拒絕", "Bを長押しで拒否")     \
  X(kSumViewScope, "Hold C for full scope", "长按 C 查看完整范围", "長按 C 查看完整範圍",                \
    "長按 C 查看完整範圍", "C長押しで範囲全体")                                                        \
  X(kSumNoMore, "No more requests", "没有更多请求", "沒有更多請求", "沒有更多請求", "これ以上ありません") \
  /* 风险标记 */                                                                                      \
  X(kRiskPaysYou, "Spends your coins", "将花费你的币", "將花費你的幣", "將花費你的幣", "自分のコインを使います") \
  X(kRiskPaysOther, "Pays another address", "支付给其它地址", "支付給其他地址", "支付給其他地址",        \
    "外部アドレスへ送金")                                                                             \
  X(kRiskUnverifiedInputs, "Previous outputs not proven on chain", "前序输出未经链上证明",              \
    "前序輸出未經鏈上證明", "前序輸出未經鏈上證明", "前の出力がオンチェーン未証明")                    \
  X(kRiskFeeHigh, "Fee looks high", "手续费偏高", "手續費偏高", "手續費偏高", "手数料が高め")           \
  X(kRiskUnknownScript, "Unknown script type", "未知脚本类型", "未知腳本類型", "未知腳本類型",          \
    "未知のスクリプト形式")                                                                           \
  X(kRiskPrivateChannel, "Private message content", "私密消息内容", "私密訊息內容", "私密訊息內容",      \
    "プライベートメッセージ")                                                                         \
  /* 会话决定 */                                                                                      \
  X(kGrantsTitle, "Session decisions", "会话决定", "會話決定", "會話決定", "セッション決定")             \
  X(kGrantsEmpty, "No session decisions yet", "暂无会话决定", "暫無會話決定", "暫無會話決定",           \
    "セッション決定はまだありません")                                                                  \
  X(kGrantsUsed, "Used %lu of %lu", "已用 %lu / %lu", "已用 %lu / %lu", "已用 %lu / %lu",            \
    "%lu / %lu 件")                                                                                  \
  X(kGrantsAllowed, "Allowed", "已允许", "已允許", "已允許", "許可")                                   \
  X(kGrantsDenied, "Denied", "已否决", "已拒絕", "已拒絕", "拒否")                                    \
  X(kGrantsCancelOne, "Cancel this decision", "取消该决定", "取消該決定", "取消該決定",                \
    "この決定を取り消す")                                                                             \
  X(kGrantsCancelAll, "Cancel all", "全部取消", "全部取消", "全部取消", "すべて取り消す")               \
  X(kGrantsHoldCancel, "Hold B to cancel", "长按 B 取消", "長按 B 取消", "長按 B 取消", "B長押しで取消")   \
  /* 操作名称 */                                                                                      \
  X(kOpIdentityProve, "Prove identity", "身份证明", "身分證明", "身分證明", "本人確認")                   \
  X(kOpIdentityAuthorize, "Authorize intent", "意图授权", "意圖授權", "意圖授權", "意図の承認")           \
  X(kIdentitySequence, "Identity sequence", "身份序号", "身分序號", "身分序號", "本人記録の順序") \
  X(kOpNoiseProof, "Network handshake identity", "网络握手身份", "網路握手身分", "網絡握手身分", "ネットワーク本人確認") \
  X(kOpPeerRecord, "Network identity record", "网络身份记录", "網路身分記錄", "網絡身分記錄", "ネットワーク本人記録") \
  X(kOpTxSign, "Sign transaction", "签署交易", "簽署交易", "簽署交易", "取引に署名")                     \
  X(kOpChannelPublic, "Channel public message", "Channel 公共消息", "Channel 公共訊息",                 \
    "Channel 公共訊息", "Channel 公開メッセージ")                                                     \
  X(kOpChannelHash, "Channel hash request", "Channel 哈希请求", "Channel 雜湊請求",                     \
    "Channel 雜湊請求", "Channel ハッシュ要求")                                                         \
  X(kOpChannelPrivate, "Channel private message", "Channel 私密消息", "Channel 私密訊息",               \
    "Channel 私密訊息", "Channel プライベートメッセージ")                                               \
  X(kOpChannelSeal, "Channel seal", "Channel 封装", "Channel 封裝", "Channel 封裝",                    \
    "Channel seal")                                                                                  \
  X(kOpChannelOpen, "Channel open", "Channel 解封", "Channel 解封", "Channel 解封",                    \
    "Channel open")                                                                                  \
  X(kOpSecretSeal, "Seal local secret", "封装本地秘密", "封裝本地祕密", "封裝本地祕密",                \
    "ローカル秘密を封印")                                                                             \
  X(kOpSecretOpen, "Open local secret", "解封本地秘密", "解封本地祕密", "解封本地祕密",                \
    "ローカル秘密を開封")                                                                             \
  X(kOpContentAttest, "Attest file digest", "文件摘要声明", "檔案摘要聲明", "檔案摘要聲明",              \
    "ファイルダイジェスト宣言")                                                                       \
  X(kTxPayees, "Recipients", "收款方", "收款方", "收款方", "支払先")                                       \
  X(kTxMorePayees, "more recipients not shown", "还有更多收款方未显示", "還有更多收款方未顯示",              \
    "還有更多收款方未顯示", "別の支払先があります（未表示）")                                            \
  X(kRiskHostEvidence, "Unspent status comes from the host and is not verified here",                     \
    "未花费状态由主机提供，本机未验证", "未花費狀態由主機提供，本機未驗證",                              \
    "未使用状態はホスト提供であり本機は検証していません", "ホスト提供の未使用状態は本機では検証されていません") \
  X(kContentNotTx, "This does not authorise any payment or transaction",                              \
    "本声明不授权任何付款或交易", "本聲明不授權任何付款或交易", "本聲明不授權任何付款或交易",          \
    "この宣言は送金や取引を一切許可しません")                                                          \
  X(kContentDigestLabel, "Statement digest", "声明摘要", "聲明摘要", "聲明摘要", "宣言ダイジェスト")      \
  X(kContentDigestByHost, "Digest computed by the host, not verified here",                           \
    "摘要由主机计算，本机未验证其来源", "摘要由主機計算，本機未驗證其來源",                            \
    "摘要由主機計算，本機未驗證其來源", "摘要由ホスト側で計算されており、本機は出所を検証していません")   \
  X(kOpMigrationImport, "Import key", "迁入密钥", "匯入密鑰", "匯入密鑰", "鍵のインポート")              \
  X(kOpMigrationExport, "Export key", "迁回密钥", "匯出密鑰", "匯出密鑰", "鍵のエクスポート")            \
  /* 范围与权限 */                                                                                    \
  X(kScopeSignMessage, "Sign messages", "签署消息", "簽署訊息", "簽署訊息", "メッセージに署名")           \
  X(kScopePay, "Send payments", "发送付款", "發送付款", "發送付款", "送金")                             \
  X(kScopePrivateRead, "Decrypt private content", "解密私密内容", "解密私密內容", "解密私密內容",        \
    "プライベート内容の復号")                                                                          \
  X(kScopePrivateWrite, "Encrypt private content", "加密私密内容", "加密私密內容", "加密私密內容",        \
    "プライベート内容の暗号化")                                                                        \
  X(kScopeMigrate, "Key migration only", "仅密钥迁移", "僅密鑰遷移", "僅密鑰遷移", "鍵の移行のみ")       \
  /* 数值与单位 */                                                                                     \
  X(kUnitSats, "sats", "聪", "聰", "聰", "サトシ")                                                     \
  X(kUnitNone, "", "", "", "", "")                                                                    \
  X(kAmountSats, "%llu sats", "%llu 聪", "%llu 聰", "%llu 聰", "%llu サトシ")                          \
  X(kCountTimes, "%lu times", "%lu 次", "%lu 次", "%lu 次", "%lu 回")                                  \
  /* 请求状态 */                                                                                       \
  X(kStatusQueued, "Queued", "排队中", "排隊中", "排隊中", "待機中")                                  \
  X(kStatusAwaiting, "Waiting for you", "等待你的确认", "等待你的確認", "等待你的確認",                \
    "確認待ち")                                                                                       \
  X(kStatusExecuted, "Done", "已完成", "已完成", "已完成", "完了")                                      \
  X(kStatusDenied, "Denied", "已拒绝", "已拒絕", "已拒絕", "拒否")                                     \
  X(kStatusCancelled, "Cancelled", "已取消", "已取消", "已取消", "キャンセル")                           \
  X(kStatusExpired, "Expired", "已失效", "已失效", "已失效", "期限切れ")                                \
  X(kStatusUnknown, "Result unknown", "结果未知", "結果不明", "結果不明", "結果不明")                    \
  X(kLockTooManyTries, "Too many attempts", "尝试次数过多", "嘗試次數過多", "嘗試次數過多", "試行回数が多すぎます")                     \
  X(kDenyTitle, "Deny this request?", "拒绝这个请求？", "拒絕這個請求？", "拒絕這個請求？", "この要求を拒否しますか？")                     \
  X(kDenyExplain, "Session denial blocks repeat requests without asking again.", "会话否决会直接拒绝重复请求，不再询问。", "會話拒絕會直接拒絕重複請求，不再詢問。", "會話拒絕會直接拒絕重複請求，不再詢問。", "セッション拒否は再 要求をサイレントに拒否します。")                     \
  X(kLockEnterDigits, "Enter digits", "输入数字", "輸入數字", "輸入數字", "数字を入力")                     \
  /* 错误 */                                                                                          \
  X(kErrTitle, "Cannot continue", "无法继续", "無法繼續", "無法繼續", "続行できません")                  \
  X(kErrLocked, "Device is locked", "设备已锁定", "裝置已鎖定", "裝置已鎖定", "デバイスがロック中")       \
  X(kErrBusy, "Another request is waiting", "有其它请求等待处理", "有其他請求等待處理",                  \
    "有其他請求等待處理", "他の要求が待機中")                                                          \
  X(kErrQueueFull, "Too many queued requests", "排队请求过多", "排隊請求過多", "排隊請求過多",            \
    "待機中の要求が多すぎます")                                                                        \
  X(kErrUnsupported, "Unsupported operation", "不支持的操作", "不支援的操作", "不支援的操作",            \
    "未対応の操作")                                                                                   \
  X(kErrVersionMismatch, "Version mismatch", "版本不匹配", "版本不相符", "版本不相符", "版本の不一致")   \
  X(kErrWrongKey, "Different key on device", "设备上是不同的密钥", "裝置上是不同的密鑰",                  \
    "裝置上是不同的密鑰", "デバイスに別の鍵があります")                                                 \
  X(kErrInvalidRequest, "Invalid request", "请求无效", "請求無效", "請求無效", "無効な要求")             \
  X(kErrRevoked, "Permission was withdrawn", "授权已被撤销", "授權已被撤銷", "授權已被撤銷",              \
    "許可が取り消されました")                                                                          \
  X(kErrDisconnected, "Host disconnected", "主机已断开", "主機已斷開", "主機已斷開", "ホスト切断")        \
  X(kErrTimeout, "Timed out", "已超时", "已逾時", "已逾時", "タイムアウト")                            \
  X(kErrResultUnknown, "Result unknown, do not retry blindly", "结果未知，请勿盲目重试",                 \
    "結果不明，請勿盲目重試", "結果不明，請勿盲目重試", "結果が不明です。不用に再試行しないでください")     \
  X(kErrMigrationConflict, "Another migration in progress", "已有迁移在进行", "已有遷移在進行",            \
    "已有遷移在進行", "別の移行が進行中です")                                                           \
  /* 迁移 */                                                                                          \
  X(kMigTitle, "Import key", "迁入密钥", "匯入密鑰", "匯入密鑰", "鍵のインポート")                      \
  X(kMigEnterPrompt, "Open this menu to accept an import", "打开本菜单以接受迁入",                       \
    "開啟本選單以接受匯入", "開啟本選單以接受匯入", "インポートを受け入れるにはここを開きます")             \
  X(kMigWaiting, "Waiting for key transfer", "等待密钥传输", "等待密鑰傳輸", "等待密鑰傳輸",            \
    "鍵の転送を待っています")                                                                          \
  X(kMigVerifying, "Verifying key", "正在核对密钥", "正在核對密鑰", "正在核對密鑰", "鍵を検証中")         \
  X(kMigSaved, "Key stored on device", "密钥已存入设备", "密鑰已存入裝置", "密鑰已存入裝置",            \
    "鍵をデバイスに保存しました")                                                                      \
  X(kMigNoOldKey, "Old key erased. Connect the browser to finish migration.", "旧私钥已擦除。连接浏览器完成迁移。", "舊私鑰已抹除。連接瀏覽器完成遷移。", "舊私鑰已抹除。連接瀏覽器完成遷移。", "旧鍵は消去済みです。ブラウザーに接続して移行を完了してください。") \
  X(kMigResetWarning, "Confirm browser migration is complete before device reset.", "确认浏览器迁移已完成，再重置设备。", "確認瀏覽器遷移已完成，再重設裝置。", "確認瀏覽器遷移已完成，再重設裝置。", "ブラウザーの移行完了を確認してからデバイスを初期化してください。") \
  X(kMigStatusTitle, "Migration status", "迁移进度", "遷移進度", "遷移進度", "移行状況")                  \
  X(kMigStageHostPrepared, "Host prepared", "主机已准备", "主機已準備", "主機已準備", "ホスト準備完了")   \
  X(kMigStageDeviceStaged, "Staged on device", "设备已暂存", "裝置已暫存", "裝置已暫存",                \
    "デバイスに一時保存")                                                                              \
  X(kMigStageDeviceCommitted, "Committed on device", "设备已提交", "裝置已提交", "裝置已提交",            \
    "デバイスで確定")                                                                                  \
  X(kMigStageHostCommitted, "Committed by host", "主机已提交", "主機已提交", "主機已提交",                \
    "ホストで確定")                                                                                  \
  X(kMigStageCleaned, "Old copy removed", "旧副本已移除", "舊副本已移除", "舊副本已移除",                \
    "旧コピーを削除")                                                                                \
  X(kMigSameKey, "Same key already on device", "设备已是同一密钥", "裝置已是同一密鑰",                    \
    "裝置已是同一密鑰", "同じ鍵がすでにあります")                                                       \
  /* 导出与备份 */                                                                                    \
  X(kExportTitle, "Export private key", "迁回私钥", "匯出私鑰", "匯出私鑰", "秘密鍵のエクスポート")       \
  X(kExportWarning,                                                                                  \
    "The private key leaves this device. Anyone with the host computer can read it. This cannot be "  \
    "undone by re-locking.",                                                                          \
    "私钥将离开本设备。任何拿到这台电脑的人都能读取它，重新锁定也无法收回。",                             \
    "私鑰將離開本裝置。任何拿到這台電腦的人都能讀取它，重新鎖定也無法收回。",                             \
    "私鑰將離開本裝置。任何拿到這部電腦的人都能讀取它，重新鎖定也無法收回。",                             \
    "秘密鍵はデバイスを離れます。この端末を操作できる人は誰でも読み取れ、再ロックしても戻せません。")     \
  X(kExportHold, "Hold B to export once", "长按 B 一次性导出", "長按 B 一次性匯出", "長按 B 一次性匯出",  \
    "B長押しで一度だけエクスポート")                                                                   \
  X(kExportSent, "Export delivered", "导出已交付", "匯出已交付", "匯出已交付", "エクスポート済み")         \
  X(kExportOnceOnly, "One-time export only", "仅一次性导出", "僅一次性匯出", "僅一次性匯出",              \
    "一度きりのみ")                                                                                   \
  X(kBackupTitle, "Recovery backup", "恢复备份", "復原備份", "復原備份", "復旧用バックアップ")            \
  X(kBackupExplain,                                                                                  \
    "Write down the code below and keep it offline. It restores the same key on a new device.",       \
    "请抄写下面的恢复码并离线保存，可在更换设备后恢复同一密钥。",                                         \
    "請抄寫下面的復原碼並離線保存，可在更換裝置後復原同一密鑰。",                                         \
    "請抄寫下面的復原碼並離線保存，可在更換裝置後復原同一密鑰。",                                         \
    "以下の復旧コードを書き写してオフラインで保管すると、新しい端末で同じ鍵を復元できます。")             \
  X(kBackupCode, "Backup code", "恢复码", "復原碼", "復原碼", "復旧コード")                              \
  X(kBackupDone, "Backup created", "恢复备份已生成", "復原備份已產生", "復原備份已產生",                  \
    "バックアップを作成しました")                                                                      \
  /* 擦除 */                                                                                          \
  X(kEraseTitle, "Erase device", "擦除设备", "清除裝置", "清除裝置", "デバイスの消去")                    \
  X(kEraseWarning,                                                                                   \
    "The device key will be destroyed. Host and user backups are not touched.",                        \
    "设备上的密钥将被销毁。主机与用户备份不受影响。",                                                     \
    "裝置上的密鑰將被銷毀。主機與使用者備份不受影響。",                                                 \
    "裝置上的密鑰將被銷毀。主機與使用者備份不受影響。",                                                 \
    "デバイス上の鍵は破棄されます。ホストやユーザーのバックアップは影響を受けません。")                 \
  X(kEraseHold, "Hold C to erase", "长按 C 擦除", "長按 C 清除", "長按 C 清除", "C長押しで消去")         \
  X(kEraseDone, "Device erased", "设备已擦除", "裝置已清除", "裝置已清除", "デバイスを消去しました")     \
  /* 配对 */                                                                                          \
  X(kPairTitle, "Confirm pairing code", "确认配对码", "確認配對碼", "確認配對碼", "ペアリングコードの確認") \
  X(kPairHint, "Check the same 6 digits on the host",                                                \
    "核对电脑上的 6 位数字是否一致", "核對電腦上的 6 位數字是否一致", "核對電腦上的 6 位數字是否一致",     \
    "ホストに表示された6桁と一致するか確認してください")                                                 \
  X(kPairMismatch, "Pairing code mismatch", "配对码不一致", "配對碼不一致", "配對碼不一致",              \
    "コードが一致しません")                                                                             \
  X(kPairOk, "Pairing confirmed", "配对成功", "配對成功", "配對成功", "ペアリング完了")                 \
  X(kHostDisconnected, "Host disconnected", "主机已断开", "主機已斷開", "主機已斷開", "ホスト切断")        \
  /* 底部按钮标签 */                                                                                    \
  X(kBtnUp, "Up", "上", "上", "上", "上")                                                              \
  X(kBtnPrev, "Prev", "上一个", "上一個", "上一個", "前へ") \
  X(kBtnSelect, "Select", "选择", "選擇", "選擇", "選択")                                               \
  X(kBtnOpen, "Open", "打开", "開啟", "開啟", "開く")                                                   \
  X(kBtnBack, "Back", "返回", "返回", "返回", "戻る")                                                   \
  X(kBtnScrollPrev, "Prev", "上翻", "上翻", "上翻", "前へ")                             \
  X(kBtnScrollNext, "Next", "下翻", "下翻", "下翻", "次へ")                             \
  X(kMustReadFirst, "Read the required items first",                              \
    "请先逐项看过关键内容", "請先逐項看過關鍵內容", "請先逐項看過關鍵內容",              \
    "先に必須項目を確認してください")                                                    \
  X(kBtnNext, "Next", "下一个", "下一個", "下一個", "次へ")                                            \
  X(kBtnDown, "Down", "下", "下", "下", "下")                                                          \
  X(kBtnHold, "Hold", "长按", "長按", "長按", "長押し")                                                 \
  X(kBtnHoldConfirm, "Hold to approve", "长按授权同意", "長按授權同意", "長按授權同意", "長押しで許可") \
  X(kBtnHoldDeny, "Hold deny", "长按拒绝", "長按拒絕", "長按拒絕", "長押し拒否")                        \
  X(kBtnDelete, "Delete", "删除", "刪除", "刪除", "削除")                                               \
  X(kBtnMore, "More", "更多", "更多", "更多", "もっと")                                                 \
  X(kBtnExit, "Exit", "退出", "離開", "離開", "終了")                                                   \
  X(kBtnEnter, "Next digit", "下一位", "下一位", "下一位", "次の桁")                                     \
  X(kBtnLess, "Less", "减少", "減少", "減少", "減らす")                                                 \
  X(kBtnMore2, "More", "增加", "增加", "增加", "増やす") \
  ROCKEY_VLP_STRINGS(X)

// 渠道额度固定文案，同一编译语言/字体提取流程。
#define ROCKEY_VLP_STRINGS(X) \
  X(kVlpDecisionOnce, "Once: allow or deny", "本次决定：允许或否决", "本次決定：允許或否決", "本次決定：允許或否決", "今回のみ：許可か拒否") \
  X(kVlpDecisionSession, "This session: allow or deny", "本会话决定：允许或否决", "本會話決定：允許或否決", "本會話決定：允許或否決", "セッション：許可か拒否") \
  X(kVlpDecisionToggle, "Hold to approve", "长按授权同意", "長按授權同意", "長按授權同意", "長押しで許可") \
  X(kVlpGrantsPrevious, "Prev/Hold back", "上项/长按返回", "上項/長按返回", "上項/長按返回", "前/長押し戻る") \
  X(kVlpGrantsCancel, "Cancel/Hold all", "撤销/长按全部", "撤銷/長按全部", "撤銷/長按全部", "取消/長押し全て") \
  X(kVlpReview, "Wallet approval", "钱包确认", "錢包確認", "錢包確認", "ウォレット確認") \
  X(kVlpChannel, "Channel", "渠道", "渠道", "渠道", "チャネル") \
  X(kVlpOwner, "App / plugin", "应用或插件", "應用或插件", "應用或插件", "アプリ") \
  X(kVlpSingleLimit, "Single limit (sats)", "单笔额度（聪）", "單筆額度（聰）", "單筆額度（聰）", "単筆上限") \
  X(kVlpSessionLimit, "Session limit (sats)", "会话额度（聪）", "會話額度（聰）", "會話額度（聰）", "接続上限") \
  X(kVlpUsed, "Used (sats)", "已消费（聪）", "已消費（聰）", "已消費（聰）", "使用済み") \
  X(kVlpFee, "Fee (sats)", "手续费（聪）", "手續費（聰）", "手續費（聰）", "手数料") \
  X(kVlpAmount, "Payment (sats)", "支付金额（聪）", "支付金額（聰）", "支付金額（聰）", "支払金額") \
  X(kVlpChange, "Change", "找零", "找零", "找零", "お釣り") \
  X(kVlpSingleExceeded, "Single exceeded", "单笔超额", "單筆超額", "單筆超額", "単筆超過") \
  X(kVlpSessionExceeded, "Session exceeded", "会话超额", "會話超額", "會話超額", "接続超過") \
  X(kVlpEnabled, "Enabled", "启用", "啟用", "啟用", "有効") \
  X(kVlpKind, "App / plugin", "应用或插件", "應用或插件", "應用或插件", "アプリ") \
  X(kVlpSession, "Session", "会话", "會話", "會話", "接続") \
  X(kVlpPoolFamily, "Fee pool", "费用池", "費用池", "費用池", "費用プール") \
  X(kVlpPoolStage, "Transaction stage", "交易阶段", "交易階段", "交易階段", "取引段階") \
  X(kVlpFunding, "Funding", "资金存入", "資金存入", "資金存入", "資金預入") \
  X(kVlpPoolState, "Cumulative state", "累计状态", "累計狀態", "累計狀態", "累計状態") \
  X(kVlpPoolPaid, "Cumulative paid (sats)", "累计付款（聪）", "累計付款（聰）", "累計付款（聰）", "累計支払額") \
  X(kVlpPoolLocked, "Locked in pool (sats)", "池内锁定（聪）", "池內鎖定（聰）", "池內鎖定（聰）", "プール預入額") \
  X(kVlpRaise, "B: raise this session", "B：提高本会话额度", "B：提高本會話額度", "B：提高本會話額度", "B：接続上限増額") \
  X(kVlpDenyScroll, "A: up / hold deny", "A：上翻／长按拒绝", "A：上翻／長按拒絕", "A：上翻／長按拒絕", "A：上／長押し拒否")

#endif  // ROCKEY_I18N_STRINGS_H
