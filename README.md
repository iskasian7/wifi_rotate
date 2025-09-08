Wi-Fi Rotation Tool for Windows

Windows 환경에서 파이썬으로 **지정한 SSID/BSSID를 일정 시간마다 순환(로테이션) 접속**하는 스크립트입니다.  
기본적으로 `netsh wlan` 명령을 사용하며, SSID 및 BSSID를 이용해서 접속합니다, BSSID는 보이는 경우 연결을 시도합니다.

---

## 📦 준비물

1. **Windows 10/11 PC**
2. **Python 3.x** (관리자 권한 실행 권장)
3. 무선 네트워크 프로필 (SSID/비밀번호) 사전 등록
   - `netsh wlan show profiles` 로 확인 가능
   - 필요시 XML로 추가:
     ```bat
     netsh wlan add profile filename="C:\path\Office-5G.xml" user=all
     ```

---

## ⚙️ 설정파일 (wifi_rotate.json)

```json
{
  "interface": "Wi-Fi",
  "dwell_seconds": 120,
  "retry_per_target": 5,
  "scan_wait_seconds": 4,
  "targets": [
    {
      "ssid": "Office-5G",
      "profile": "Office-5G",
      "bssid": "AA:BB:CC:DD:EE:01"
    },
    {
      "ssid": "Lab-2G",
      "profile": "Lab-2G"
    }
  ]
}
```
- interface: 무선 어댑터 이름 (netsh wlan show interfaces 로 확인)

- dwell_seconds: 각 타겟에서 머무는 시간(초)

- retry_per_target: 원하는 BSSID로 붙지 못했을 때 재시도 횟수

- scan_wait_seconds: 스캔 대기 시간

- targets: 순환할 네트워크 목록 
    
  - ssid: 네트워크 SSID

  - profile: 저장된 프로필 이름 (netsh wlan show profiles)

  - bssid (선택): 특정 AP BSSID (없으면 SSID 기준 연결)

## ▶ 실행 방법
1. wifi_rotate.py와 wifi_rotate.json을 같은 폴더에 둡니다.

2. 관리자 권한으로 PowerShell 실행

3. 아래 명령어 입력:
```
python wifi_rotate.py
```
4. 순차적으로 타겟 SSID에 연결 → 지정 시간 유지 → 다음 SSID로 이동합니다.

- 중단: Ctrl + C

## 🔍 확인/디버깅
- 현재 연결 상태 확인:

```netsh wlan show interfaces```
- 프로필 확인:

```netsh wlan show profiles```
- 주변 네트워크 스캔:

```netsh wlan show networks mode=bssid```

## ⚠️ 주의사항
- Windows netsh는 BSSID 직접 고정 기능을 공식 지원하지 않음

   → BSSID 지정 시, 스크립트가 재연결을 반복해 원하는 BSSID로 붙도록 유도합니다.
 
   → 하지만 무선 드라이버/환경에 따라 보장되지 않을 수 있습니다.

- SSID/프로필 이름 불일치 시 0x80342002 (연결 요청 실패) 오류가 발생합니다.

   → 반드시 netsh wlan show profiles 에 표시되는 이름을 그대로 사용하세요.
---
## ⏰ 자동 실행 (선택)
Windows 작업 스케줄러를 이용해 로그온 시 자동 실행 가능:

1. 작업 스케줄러 → “기본 작업 만들기”

2. 트리거: 로그온할 때

3. 동작: 프로그램 시작

   - 프로그램/스크립트: python.exe

   - 인수 추가: "C:\경로\wifi_rotate.py"

   - 시작 위치: C:\경로\

4. 가장 높은 권한으로 실행 체크
---
## 📄 라이선스
MIT License

---

