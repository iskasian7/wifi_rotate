import json
import subprocess
import sys
import time
import re
from pathlib import Path

CONFIG_PATH = Path(__file__).with_name("wifi_rotate.json")


def run(cmd, timeout=15):
    # netsh 출력이 CP949/UTF-8 혼재할 수 있어 엄격하지 않게 디코드
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    try:
        out = p.communicate(timeout=timeout)[0]
    except subprocess.TimeoutExpired:
        p.kill()
        out = p.communicate()[0]
    for enc in ("utf-8", "cp949", "euc-kr", "latin-1"):
        try:
            return out.decode(enc, errors="ignore")
        except Exception:
            continue
    return out.decode(errors="ignore")


def current_interface_status():
    """
    현재 연결 상태/SSID/BSSID/인터페이스명 파싱
    """
    text = run("netsh wlan show interfaces")
    # 여러 인터페이스가 있을 수 있으므로 블록 단위로 분해
    blocks = [b.strip() for b in text.split("이름") if b.strip()] if "이름" in text else \
             [b.strip() for b in text.split("Name") if b.strip()]

    infos = []
    for b in blocks:
        # 한글/영문 키 모두 처리
        name_m = re.search(r"(?:^|: )(.+?)\r?\n", b)
        name = name_m.group(1).strip() if name_m else None

        state_m = re.search(r"상태\s*:\s*(.+)|State\s*:\s*(.+)", b)
        state = (state_m.group(1) or state_m.group(2)).strip() if state_m else "unknown"

        ssid_m = re.search(r"SSID\s*:\s*(.+)", b)
        ssid = ssid_m.group(1).strip() if ssid_m else None

        bssid_m = re.search(r"BSSID\s*:\s*([0-9A-Fa-f: -]+)", b)
        bssid = bssid_m.group(1).strip().upper().replace("-", ":") if bssid_m else None

        infos.append({"name": name, "state": state, "ssid": ssid, "bssid": bssid, "raw": b})
    return infos


def scan_networks():
    """
    주변 네트워크(BSSID 포함) 스캔 후 딜레이.
    """
    _ = run("netsh wlan show networks mode=bssid", timeout=20)
    # netsh 스캔 출력은 직전 명령에 즉시 반영 안될 수 있어 약간 대기
    time.sleep(1.5)
    return run("netsh wlan show networks mode=bssid", timeout=20)


def connect_by_profile(interface, profile, ssid=None):
    """
    프로필/SSID로 연결 시도
    """
    if ssid:
        cmd = f'netsh wlan connect name="{profile}" ssid="{ssid}" interface="{interface}"'
    else:
        cmd = f'netsh wlan connect name="{profile}" interface="{interface}"'
    return run(cmd)


def disconnect(interface):
    return run(f'netsh wlan disconnect interface="{interface}"')


def find_interface_block(infos, wanted):
    for info in infos:
        if info["name"] and info["name"].strip('"') == wanted.strip('"'):
            return info
    return None


def normalize_mac(mac):
    return mac.upper().replace("-", ":").strip()


def bssid_present_in_scan(scan_text, ssid, bssid):
    """
    스캔 결과에 특정 SSID/BSSID가 존재하는지 확인
    """
    ssid_blocks = re.split(r"\r?\n\r?\n", scan_text)
    target_bssid = normalize_mac(bssid)
    for block in ssid_blocks:
        if re.search(rf"SSID\s+\d+\s*:\s*{re.escape(ssid)}\s*$", block, re.MULTILINE):
            if re.search(rf"BSSID\s+\d+\s*:\s*{re.escape(target_bssid)}\s*$", block, re.MULTILINE | re.IGNORECASE):
                return True
    return False


def wait_until_connected(interface, ssid, timeout=20):
    """
    지정 SSID로 '연결됨' 상태가 되는지 대기
    """
    t0 = time.time()
    while time.time() - t0 < timeout:
        infos = current_interface_status()
        inf = find_interface_block(infos, interface)
        if not inf:
            time.sleep(1)
            continue
        if inf["state"].lower().startswith(("연결", "connected")) and inf["ssid"] == ssid:
            return True
        time.sleep(1)
    return False


def ensure_bssid(interface, ssid, wanted_bssid, retries=3, scan_wait=3):
    """
    현재 연결된 BSSID가 원하는 것인지 확인하고, 아니면 재시도.
    - netsh에는 BSSID 직접 지정 옵션이 없어, 연결→확인→스캔→재연결을 반복
    - 환경에 따라 보장되지 않을 수 있음
    """
    wanted_bssid = normalize_mac(wanted_bssid)
    for attempt in range(1, retries + 1):
        infos = current_interface_status()
        inf = find_interface_block(infos, interface)
        if inf and inf["ssid"] == ssid and inf["bssid"] == wanted_bssid:
            return True  # 원하는 BSSID에 붙음

        # 스캔해서 대상 BSSID가 보이는지 확인
        scan_text = scan_networks()
        if not bssid_present_in_scan(scan_text, ssid, wanted_bssid):
            # 안 보이면 잠깐 쉬고 재스캔
            time.sleep(scan_wait)
            continue

        # 재연결 시도(연결되어 있더라도 한 번 끊고 붙기)
        disconnect(interface)
        time.sleep(1.5)
        connect_by_profile(interface, ssid, ssid)
        if wait_until_connected(interface, ssid, timeout=20):
            # 다시 상태 확인
            infos = current_interface_status()
            inf = find_interface_block(infos, interface)
            if inf and inf["bssid"] == wanted_bssid:
                return True

        time.sleep(scan_wait)

    return False


def rotate():
    if not CONFIG_PATH.exists():
        print(f"[에러] 설정 파일이 없습니다: {CONFIG_PATH}")
        sys.exit(1)

    cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    iface = cfg.get("interface", "Wi-Fi")
    dwell = int(cfg.get("dwell_seconds", 120))
    retry = int(cfg.get("retry_per_target", 5))
    scan_wait = int(cfg.get("scan_wait_seconds", 4))
    targets = cfg.get("targets", [])

    if not targets:
        print("[에러] targets가 비어 있습니다.")
        sys.exit(1)

    print(f"[정보] 인터페이스: {iface}, 타겟 {len(targets)}개, 체류 {dwell}s, 재시도 {retry}회")

    try:
        while True:
            for t in targets:
                ssid = t["ssid"]
                profile = t.get("profile", ssid)
                bssid = t.get("bssid")

                print(f"\n[타겟] SSID={ssid} (프로필={profile})" + (f", 원하는 BSSID={bssid}" if bssid else ""))

                # 연결 시도
                out = connect_by_profile(iface, profile, ssid)
                print(f"[연결시도]\n{out}")

                if not wait_until_connected(iface, ssid, timeout=25):
                    print("[경고] 연결 대기 시간 초과. 다음 타겟으로 넘어갑니다.")
                    continue

                # BSSID 고급 모드
                if bssid:
                    ok = ensure_bssid(iface, ssid, bssid, retries=retry, scan_wait=scan_wait)
                    if not ok:
                        print(f"[경고] 원하는 BSSID({bssid})로 고정 실패. 현재 BSSID로 체류합니다.")

                # 현재 상태 출력
                infos = current_interface_status()
                inf = find_interface_block(infos, iface)
                if inf:
                    print(f"[상태] 상태={inf['state']}, SSID={inf['ssid']}, BSSID={inf['bssid']}")
                else:
                    print("[경고] 인터페이스 정보를 가져오지 못했습니다.")

                # 체류
                time.sleep(dwell)

    except KeyboardInterrupt:
        print("\n[종료] 사용자 중단")


if __name__ == "__main__":
    rotate()
