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
  /* 通用 */                                                                                        \
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
  X(kInfoBattery, "Battery", "电量", "電量", "電量", "バッテリー")                                   \
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
  /* 主菜单 */                                                                                       \
  X(kMenuTitle, "Menu", "菜单", "選單", "選單", "メニュー")                                           \
  X(kMenuReview, "Review request", "查看待确认请求", "檢視待確認請求", "檢視待確認請求",                \
    "確認待ちの要求")                                                                                \
  X(kMenuGrants, "Session decisions", "会话决定", "會話決定", "會話決定", "セッション決定")             \
  X(kMenuLock, "Lock now", "立即锁定", "立即鎖定", "立即鎖定", "今すぐロック")                         \
  X(kMenuDeviceInfo, "Device info", "设备信息", "裝置資訊", "裝置資訊", "デバイス情報")                 \
  X(kMenuKeyDetail, "Full public key", "完整公钥", "完整公鑰", "完整公鑰", "公開鍵全体")                 \
  X(kMenuImportKey, "Import key", "迁入密钥", "匯入密鑰", "匯入密鑰", "鍵のインポート")                \
  X(kMenuExportKey, "Export key", "迁回密钥", "匯出密鑰", "匯出密鑰", "鍵のエクスポート")              \
  X(kMenuRecoveryBackup, "Recovery backup", "恢复备份", "復原備份", "復原備份", "復旧バックアップ")       \
  X(kMenuErase, "Erase device", "擦除设备", "清除裝置", "清除裝置", "デバイスを消去")                   \
  X(kMenuEmpty, "Nothing to review", "没有待确认请求", "沒有待確認請求", "沒有待確認請求",              \
    "確認待ちはありません")                                                                           \
  /* 阅读页 */                                                                                        \
  X(kReadTitle, "Key reputation", "对方可信度", "對方可信度", "對方可信度", "相手の信頼度")             \
  X(kReadChapter, "Chapter %u/%u", "第 %u/%u 章", "第 %u/%u 章", "第 %u/%u 章", "%u/%u 章")           \
  X(kReadJump, "Chapters", "章节", "章節", "章節", "章一覧")                                          \
  X(kReadHoldFaster, "Hold to scroll faster", "按住可加速滚动", "按住可加速捲動", "按住可加速捲動",     \
    "長押しで高速スクロール")                                                                          \
  X(kReadEnd, "End of text", "文本结束", "文本結束", "文本結束", "本文終わり")                         \
  X(kReadMissingGlyph, "Missing glyph U+%04X", "缺字 U+%04X", "缺字 U+%04X", "缺字 U+%04X",           \
    "文字欠落 U+%04X")                                                                                \
  X(kReadStripped, "Some characters were removed", "部分字符已移除", "部分字元已移除",                  \
    "部分字元已移除", "一部の文字を除去しました")                                                     \
  X(kReadTruncated, "Text truncated by device limit", "文本因设备上限被截断",                         \
    "文本因裝置上限被截斷", "文本因裝置上限被截斷", "装置上限により省略されました")                     \
  X(kReadOpenMenu, "Hold B for options", "长按 B 打开菜单", "長按 B 開啟選單", "長按 B 開啟選單",        \
    "B長押しでメニュー")                                                                              \
  /* 可信度证据 */                                                                                    \
  X(kEvidTitle, "Evidence", "证明", "證明", "證明", "証拠")                                          \
  X(kEvidVerified, "Verified on device", "设备已验证", "裝置已驗證", "裝置已驗證", "デバイスで検証済み") \
  X(kEvidHostClaim, "Host claim only", "仅主机声明", "僅主機聲明", "僅主機聲明", "ホストの主張のみ")     \
  X(kEvidNoEvidence, "No evidence", "无证据", "無證據", "無證據", "証拠なし")                        \
  X(kNoEvidenceShort, "no evidence", "无证据", "無證據", "無證據", "証拠なし")                     \
  X(kEvidExpired, "Expired", "已过期", "已過期", "已過期", "期限切れ")                                \
  X(kEvidTimeUnknown, "Time not verifiable", "时间不可核验", "時間不可核驗", "時間不可核驗",           \
    "時刻を検証できません")                                                                           \
  X(kEvidIssuer, "Issuer", "签发机构", "簽發機構", "簽發機構", "発行元")                              \
  X(kEvidNonce, "Nonce", "随机挑战", "隨機挑戰", "隨機挑戰", "ナンス")                                \
  X(kEvidSubject, "Subject key", "对象公钥", "對象公鑰", "對象公鑰", "対象公開鍵")                     \
  X(kEvidBoundRequest, "Bound to request", "已绑定本请求", "已綁定本請求", "已綁定本請求",              \
    "要求に紐づいています")                                                                            \
  X(kEvidNote, "Issuer signature proves origin, not safety.", "机构签名只证明来源，不证明安全。",      \
    "機構簽名只證明來源，不證明安全。", "機構簽名只證明來源，不證明安全。",                           \
    "発行元の署名は出所を示すが安全性を保証しません。")                                               \
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
  X(kSumScope, "Scope", "授权范围", "授權範圍", "授權範圍", "許可範囲")                                \
  X(kSumLimits, "Limits", "限额", "限額", "限額", "上限")                                             \
  X(kSumRisks, "Warnings", "警告", "警告", "警告", "警告")                                            \
  X(kSumExcludes, "Not included", "不包含", "不包含", "不包含", "含まないもの")                       \
  X(kSumHoldConfirm, "Hold B to confirm", "长按 B 确认", "長按 B 確認", "長按 B 確認", "Bを長押しで確定") \
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
  X(kRiskExternalIssuer, "Unrecognised issuer", "未登记的签发机构", "未登記的簽發機構",                  \
    "未登記的簽發機構", "未登録の発行元")                                                              \
  X(kRiskTimeUnverified, "Expiry cannot be checked", "有效期无法核验", "有效期無法核驗",                  \
    "有效期無法核驗", "有効期限を検証できません")                                                       \
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
  X(kOpMigrationImport, "Import key", "迁入密钥", "匯入密鑰", "匯入密鑰", "鍵のインポート")              \
  X(kOpMigrationExport, "Export key", "迁回密钥", "匯出密鑰", "匯出密鑰", "鍵のエクスポート")            \
  /* 范围与权限 */                                                                                    \
  X(kScopeReadOnly, "Read only", "只读", "唯讀", "唯讀", "読み取りのみ")                               \
  X(kScopeSignTx, "Sign own transactions", "签署自己的交易", "簽署自己的交易", "簽署自己的交易",          \
    "自身の取引に署名")                                                                               \
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
  X(kErrInvalidEvidence, "Invalid evidence", "证据无效", "證據無效", "證據無效", "無効な証拠")           \
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
  X(kBtnNext, "Next", "下一个", "下一個", "下一個", "次へ")                                            \
  X(kBtnDown, "Down", "下", "下", "下", "下")                                                          \
  X(kBtnHold, "Hold", "长按", "長按", "長按", "長押し")                                                 \
  X(kBtnHoldConfirm, "Hold confirm", "长按确认", "長按確認", "長按確認", "長押し確定")                  \
  X(kBtnHoldDeny, "Hold deny", "长按拒绝", "長按拒絕", "長按拒絕", "長押し拒否")                        \
  X(kBtnDelete, "Delete", "删除", "刪除", "刪除", "削除")                                               \
  X(kBtnMore, "More", "更多", "更多", "更多", "もっと")                                                 \
  X(kBtnExit, "Exit", "退出", "離開", "離開", "終了")                                                   \
  X(kBtnEnter, "Next digit", "下一位", "下一位", "下一位", "次の桁")                                     \
  X(kBtnLess, "Less", "减少", "減少", "減少", "減らす")                                                 \
  X(kBtnMore2, "More", "增加", "增加", "增加", "増やす") \

#endif  // ROCKEY_I18N_STRINGS_H