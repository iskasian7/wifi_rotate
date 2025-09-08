import json
import subprocess
import sys
import time
import re
from pathlib import Path
from datetime import datetime
import random

# ─────────────────────────────────────────────────────────────
# 경로 유틸
# ─────────────────────────────────────────────────────────────
def resolve_base_path() -> Path:
    if getattr(sys, 'frozen', False):       # PyInstaller onefile
        return Path(sys.executable).parent
    if '__file__' in globals():             # 일반 .py
        return Path(__file__).parent
    return Path.cwd()

def resolve_config_path() -> Path:
    base = resolve_base_path()
    cand = base / "wifi_rotate.json"
    if cand.exists():
        return cand
    return Path.cwd() / "wifi_rotate.json"

BASE_PATH = resolve_base_path()
CONFIG_PATH = resolve_config_path()
LOG_PATH = BASE_PATH / "wifi_test_log.txt"

# ─────────────────────────────────────────────────────────────
# 로깅
# ─────────────────────────────────────────────────────────────
def log(message: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = f"{ts} - {message}"
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(msg + "\n")
    except Exception:
        pass
    print(msg)

# ─────────────────────────────────────────────────────────────
# netsh 실행
# ─────────────────────────────────────────────────────────────
def run(cmd, timeout=15):
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

# ─────────────────────────────────────────────────────────────
# WLAN 유틸
# ─────────────────────────────────────────────────────────────
def current_interface_status():
    text = run("netsh wlan show interfaces")
    blocks = [b.strip() for b in text.split("이름") if b.strip()] if "이름" in text else \
             [b.strip() for b in text.split("Name") if b.strip()]
    infos = []
    for b in blocks:
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
    _ = run("netsh wlan show networks mode=bssid", timeout=20)
    time.sleep(1.2)
    return run("netsh wlan show networks mode=bssid", timeout=20)

def parse_visible_map(scan_text):
    ssid_to_bssids = {}
    ssid_entries = re.split(r"\r?\n\r?\n", scan_text)
    for block in ssid_entries:
        m_ssid = re.search(r"SSID\s+\d+\s*:\s*(.+)\s*$", block, re.MULTILINE)
        if not m_ssid:
            continue
        ssid = m_ssid.group(1).strip()
        bssids = set()
        for bssid_line in re.finditer(r"BSSID\s+\d+\s*:\s*([0-9A-Fa-f: -]+)", block):
            bssid = bssid_line.group(1).upper().replace("-", ":").strip()
            bssids.add(bssid)
        ssid_to_bssids.setdefault(ssid, set()).update(bssids)
    return ssid_to_bssids

def connect_by_profile(interface, profile, ssid=None):
    if ssid:
        cmd = f'netsh wlan connect name="{profile}" ssid="{ssid}" interface="{interface}"'
    else:
        cmd = f'netsh wlan connect name="{profile}" interface="{interface}"'
    return run(cmd)

def disconnect(interface):
    log(f'netsh wlan disconnect interface="{interface}"')
    return run(f'netsh wlan disconnect interface="{interface}"')

def find_interface_block(infos, wanted):
    if not wanted:
        return None
    wanted_clean = wanted.strip('"')
    for info in infos:
        name = (info.get("name") or "").strip('"') if info else ""
        if name == wanted_clean:
            return info
    return None

def wait_until_connected(interface, ssid, timeout=15):
    t0 = time.time()
    while time.time() - t0 < timeout:
        infos = current_interface_status()
        inf = find_interface_block(infos, interface)
        if not inf:
            time.sleep(0.8)
            continue
        if inf["state"].lower().startswith(("연결", "connected")) and inf["ssid"] == ssid:
            return True
        time.sleep(0.8)
    return False

def ensure_bssid(interface, ssid, wanted_bssid, retries=3, scan_wait=3):
    wanted_bssid = wanted_bssid.upper().replace("-", ":").strip()
    for _ in range(max(1, retries)):
        infos = current_interface_status()
        inf = find_interface_block(infos, interface)
        if inf and inf["ssid"] == ssid and inf["bssid"] == wanted_bssid:
            return True
        scan_text = scan_networks()
        visible = parse_visible_map(scan_text)
        if ssid not in visible or wanted_bssid not in visible.get(ssid, set()):
            time.sleep(scan_wait)
            continue
        disconnect(interface)
        time.sleep(1.2)
        connect_by_profile(interface, ssid, ssid)
        if wait_until_connected(interface, ssid, timeout=12):
            infos = current_interface_status()
            inf = find_interface_block(infos, interface)
            if inf and inf["bssid"] == wanted_bssid:
                return True
        time.sleep(scan_wait)
    return False

def harden_profile(profile_name):
    run(f'netsh wlan set profileparameter name="{profile_name}" connectionmode=manual')
    run(f'netsh wlan set profileparameter name="{profile_name}" autoswitch=no')

# ─────────────────────────────────────────────────────────────
# 메인
# ─────────────────────────────────────────────────────────────
def rotate():
    cfg_path = CONFIG_PATH
    if not cfg_path.exists():
        log(f"[에러] 설정 파일이 없습니다: {cfg_path}")
        sys.exit(1)
    try:
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    except Exception as e:
        log(f"[에러] 설정 파일 파싱 실패: {e}")
        sys.exit(1)

    iface = cfg.get("interface", "Wi-Fi")
    dwell = int(cfg.get("dwell_seconds", 120))
    retry = int(cfg.get("retry_per_target", 5))
    scan_wait = int(cfg.get("scan_wait_seconds", 4))
    connect_wait = int(cfg.get("connect_wait_seconds", 15))
    targets = cfg.get("targets", [])
    shuffle_each_round = bool(cfg.get("shuffle_each_round", True))
    min_connect_interval_seconds = int(cfg.get("min_connect_interval_seconds", 4))
    lock_profiles = bool(cfg.get("lock_profiles", False))

    if not targets:
        log("[에러] targets가 비어 있습니다.")
        sys.exit(1)

    if lock_profiles:
        for t in targets:
            profile = t.get("profile") or t.get("ssid")
            if profile:
                harden_profile(profile)

    log(f"[정보] 인터페이스={iface}, 타겟={len(targets)}개, 체류={dwell}s, 재시도(BSSID)={retry}회, "
        f"연결대기={connect_wait}s, 스캔대기={scan_wait}s, shuffle={shuffle_each_round}, "
        f"min_connect_gap={min_connect_interval_seconds}s")

    last_connect_ts = datetime.min

    try:
        while True:
            order = list(range(len(targets)))
            if shuffle_each_round:
                random.shuffle(order)

            for idx in order:
                t = targets[idx]
                ssid = t["ssid"]
                profile = t.get("profile", ssid)
                bssid = (t.get("bssid") or "").upper().replace("-", ":").strip()

                # 연결 간격 스로틀링
                delta = (datetime.now() - last_connect_ts).total_seconds()
                if delta < min_connect_interval_seconds:
                    time.sleep(min_connect_interval_seconds - delta)

                log(f"[타겟] SSID={ssid} (프로필={profile})" + (f", 원하는 BSSID={bssid}" if bssid else ""))

                out = connect_by_profile(iface, profile, ssid)
                log(f"[연결시도] {out.strip()}")
                last_connect_ts = datetime.now()

                if not wait_until_connected(iface, ssid, timeout=connect_wait):
                    log("[경고] 연결 대기 시간 초과. 다음 타겟으로.")
                    time.sleep(0.5)
                    continue

                if bssid:
                    ok = ensure_bssid(iface, ssid, bssid, retries=retry, scan_wait=scan_wait)
                    if not ok:
                        log(f"[경고] 원하는 BSSID({bssid}) 고정 실패. 현재 BSSID로 체류.")

                infos = current_interface_status()
                inf = find_interface_block(infos, iface)
                if inf:
                    log(f"[상태] 상태={inf['state']}, SSID={inf['ssid']}, BSSID={inf['bssid']}")
                else:
                    log("[경고] 인터페이스 정보를 가져오지 못했습니다.")

                time.sleep(dwell)

    except KeyboardInterrupt:
        log("[종료] 사용자 중단")

if __name__ == "__main__":
    rotate()
