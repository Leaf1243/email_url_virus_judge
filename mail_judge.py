import imaplib
import email
from email.header import decode_header
import re
import requests
import base64

# --- 設定項目 ---
GMAIL_USER = "~~~~@gmail.com" # gmailアドレス
GMAIL_PASS = "asdf ghjk 1234 5678"  # Gmailの16桁アプリパスワード
VT_API_KEY = "~~~~~~~~" # 取得したVirusTotalのAPIキー

def check_url_with_virustotal(url):
    """VirusTotal APIを使ってURLを判定し、データがなければその場で新規スキャンする関数"""
    print(f"URLを分析中: {url}")
    
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    
    try:
        # まずは過去のデータがあるか確認
        response = requests.get(api_url, headers=headers)
        
        # 1. 過去にデータがある場合
        if response.status_code == 200:
            return parse_vt_results(response.json())
                
        # 2. 新しいURLでデータがない場合 (404) -> その場で新規スキャンを依頼
        elif response.status_code == 404:
            print("新しいURLです。VirusTotalにリアルタイムスキャンを依頼します")
            
            scan_url = "https://www.virustotal.com/api/v3/urls"
            payload = {"url": url}
            
            # スキャン依頼をPOST
            scan_response = requests.post(scan_url, data=payload, headers=headers)
            
            if scan_response.status_code == 200:
                scan_data = scan_response.json()
                analysis_id = scan_data["data"]["id"]
                
                # 検査が終わるまで少し待つ
                print("セキュリティエンジンが巡回中 15秒ほどお待ちください")
                time.sleep(15)
                
                # 受付番号（analysis_id）を使って結果を取得
                analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                analysis_response = requests.get(analysis_url, headers=headers)
                
                if analysis_response.status_code == 200:
                    return parse_vt_results(analysis_response.json())
                else:
                    return f"❌ スキャン結果の取得に失敗しました (Status: {analysis_response.status_code})"
            else:
                return f"❌ スキャン依頼自体に失敗しました (Status: {scan_response.status_code})"
            
        else:
            return f"❌ APIエラー (Status Code: {response.status_code})"
            
    except Exception as e:
        return f"❌ 接続エラー: {e}"

def parse_vt_results(json_data):
    """VirusTotalのレスポンスから危険数を計算する補助関数"""
    attributes = json_data["data"]["attributes"]
    if "last_analysis_stats" in attributes:
        stats = attributes["last_analysis_stats"]
    else:
        stats = attributes["stats"]
        
    malicious_count = stats.get("malicious", 0)
    suspicious_count = stats.get("suspicious", 0)
    
    if malicious_count > 0 or suspicious_count > 0:
        return f"⚠️ 危険判定！ (悪意あるサイトと判定したベンダー数: {malicious_count})"
    else:
        return "✅ 安全（リアルタイム検査の結果、クリーンなURLです）"

def analyze_email_content(subject, body):
    """受信したメールの本文を分析する関数"""
    print(f"\n==========================================")
    print(f"【分析対象】件名: {subject}")
    print(f"==========================================")
    
    # 1. 本文からURLを抽出（正規表現）
    urls = re.findall(r'https?://[\w/:%#\$&\?\(\)~\.=\+\-]+', body)
    
    if not urls:
        print("-> 本文内にURLは見つかりませんでした。安全な可能性が高いです。")
        return

    print(f"-> 本文内に {len(urls)} 件のURLを発見しました。順次検証します...")
    
    # 2. 見つかったURLを1つずつチェック
    for url in urls:
        # 短縮URLの簡易警告
        if "bit.ly" in url or "t.co" in url:
            print(f"  ⚠️ 警告: 短縮URLが使われています。転送先が隠されている可能性があります。")
            
        # VirusTotalで検証
        result = check_url_with_virustotal(url)
        print(f"  [分析結果] {result}\n")

def get_latest_unread_emails():
    mail = imaplib.IMAP4_SSL("imap.gmail.com")
    try:
        mail.login(GMAIL_USER, GMAIL_PASS)
        mail.select("inbox")
        
        # 今回はテストしやすくするため、直近の「既読・未読問わず最新5件」を取得してみます
        # (本番運用時は "UNSEEN" に戻すと未読だけを処理できます)
        status, response = mail.search(None, "ALL")
        email_ids = response[0].split()
        
        if not email_ids:
            print("メールが見つかりません。")
            return

        # 最新の5件に絞る
        latest_ids = email_ids[-5:]
        print(f"最新の {len(latest_ids)} 件のメールを読み込みました。分析を開始します。")

        for e_id in reversed(latest_ids):
            # BODY.PEEKにし、このスクリプトが読んでも勝手に「既読」にならないようにする
            status, msg_data = mail.fetch(e_id, "(BODY.PEEK[])")
            
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    
                    # 件名の取得
                    subject, encoding = decode_header(msg["Subject"])[0]
                    if isinstance(subject, bytes):
                        subject = subject.decode(encoding or "utf-8")
                    
                    # 本文の抽出
                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            content_type = part.get_content_type()
                            content_disposition = str(part.get("Content-Disposition"))
                            if content_type == "text/plain" and "attachment" not in content_disposition:
                                charset = part.get_content_charset() or "utf-8"
                                body = part.get_payload(decode=True).decode(charset, errors="ignore")
                                break
                    else:
                        charset = msg.get_content_charset() or "utf-8"
                        body = msg.get_payload(decode=True).decode(charset, errors="ignore")
                    
                    # 分析関数を呼び出す
                    analyze_email_content(subject, body)

    except Exception as e:
        print(f"エラーが発生しました: {e}")
    finally:
        mail.logout()

if __name__ == "__main__":
    get_latest_unread_emails()
