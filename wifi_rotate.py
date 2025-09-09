import json
import subprocess
import sys
import time
import re
from pathlib import Path
from datetime import datetime
import random
from typing import Optional

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
# 쉘 실행
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
# IP/GW/Ping 도우미
# ─────────────────────────────────────────────────────────────
def get_ipv4_address(interface_alias: str) -> Optional[str]:
    ps_cmd = (
        f"powershell -NoProfile -Command "
        f"\"(Get-NetIPAddress -InterfaceAlias '{interface_alias}' -AddressFamily IPv4 "
        f"-ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty IPAddress)\""
    )
    out = run(ps_cmd, timeout=10).strip()
    m = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", out)
    if m:
        return m.group(0)

    txt = run("ipconfig", timeout=10)
    blocks = re.split(r"\r?\n\r?\n", txt)
    for bl in blocks:
        if interface_alias in bl:
            m2 = re.search(r"(?:IPv4\s*(?:주소|Address)[^0-9]*)(\d{1,3}(?:\.\d{1,3}){3})", bl)
            if m2:
                return m2.group(1)
    m3 = re.search(r"(?:IPv4\s*(?:주소|Address)[^0-9]*)(\d{1,3}(?:\.\d{1,3}){3})", txt)
    return m3.group(1) if m3 else None

def get_ipv4_gateway(interface_alias: str) -> Optional[str]:
    ps_cmd = (
        f"powershell -NoProfile -Command "
        f"\"$gw=(Get-NetIPConfiguration -InterfaceAlias '{interface_alias}' -ErrorAction SilentlyContinue).IPv4DefaultGateway;"
        f"if($gw){{$gw.NextHop}}\""
    )
    out = run(ps_cmd, timeout=10).strip()
    m = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", out)
    return m.group(0) if m else None

def ping(host: str, timeout_ms: int = 800) -> bool:
    # Windows: -n 1(1회), -w timeout(ms)
    out = run(f'ping -n 1 -w {timeout_ms} {host}', timeout=(timeout_ms // 1000 + 2))
    # 국문/영문 공통으로 'TTL=' 존재 여부로 성공 판단
    return "TTL=" in out.upper()

def is_apipa(ip: Optional[str]) -> bool:
    return bool(ip and ip.startswith("169.254."))

def verify_connectivity(
    iface: str,
    ip_wait_seconds: int = 10,
    require_ip: bool = True,
    require_gateway: bool = True,
    require_ping: bool = False,
    ping_host: Optional[str] = None
):
    """
    연결 후 '실제 사용 가능'한지 검증.
    반환: dict(ok: bool, reason: str, ip: str|None, gw: str|None, ping_ok: bool|None)
    """
    # 1) IP 대기 (APIPA는 실패로 간주)
    ip = None
    t0 = time.time()
    while time.time() - t0 < max(0, ip_wait_seconds):
        ip = get_ipv4_address(iface)
        if ip and not is_apipa(ip):
            break
        time.sleep(1)

    if require_ip:
        if not ip:
            return {"ok": False, "reason": "NO_IP", "ip": ip, "gw": None, "ping_ok": None}
        if is_apipa(ip):
            return {"ok": False, "reason": "APIPA", "ip": ip, "gw": None, "ping_ok": None}

    # 2) 게이트웨이 확인
    gw = get_ipv4_gateway(iface)
    if require_gateway and not gw:
        return {"ok": False, "reason": "NO_GATEWAY", "ip": ip, "gw": gw, "ping_ok": None}

    # 3) 핑(옵션)
    ping_ok = None
    if require_ping:
        target = gw or ping_host or "1.1.1.1"
        ping_ok = ping(target, timeout_ms=800)
        if not ping_ok:
            return {"ok": False, "reason": "PING_FAIL", "ip": ip, "gw": gw, "ping_ok": False}

    return {"ok": True, "reason": "OK", "ip": ip, "gw": gw, "ping_ok": ping_ok}

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

# ─────────────────────────────────────────────────────────────
# BSSID 유도(선택)
# ─────────────────────────────────────────────────────────────
def ensure_bssid(interface, ssid, wanted_bssid, retries=3, scan_wait=3):
    wanted_bssid = (wanted_bssid or "").upper().replace("-", ":").strip()
    if not wanted_bssid:
        return True
    for _ in range(max(1, retries)):
        infos = current_interface_status()
        inf = find_interface_block(infos, interface)
        if inf and inf["ssid"] == ssid and inf["bssid"] == wanted_bssid:
            return True
        # 재연결 유도
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
    connect_wait = int(cfg.get("connect_wait_seconds", 15))
    shuffle_each_round = bool(cfg.get("shuffle_each_round", True))
    min_connect_interval_seconds = int(cfg.get("min_connect_interval_seconds", 4))
    lock_profiles = bool(cfg.get("lock_profiles", False))

    # 새 옵션(검증)
    ip_wait_after_connect = int(cfg.get("post_connect_ip_wait_seconds", 10))
    verify_require_ip = bool(cfg.get("verify_require_ip", True))
    verify_require_gateway = bool(cfg.get("verify_require_gateway", True))
    verify_require_ping = bool(cfg.get("verify_require_ping", False))
    verify_ping_host = cfg.get("verify_ping_host") or None
    disconnect_on_verify_fail = bool(cfg.get("disconnect_on_verify_fail", True))

    targets = cfg.get("targets", [])
    if not targets:
        log("[에러] 타겟이 비어 있습니다.")
        sys.exit(1)

    if lock_profiles:
        for t in targets:
            profile = t.get("profile") or t.get("ssid")
            if profile:
                harden_profile(profile)

    log(f"[정보] 인터페이스={iface}, 타겟={len(targets)}개, 체류={dwell}s, "
        f"연결대기={connect_wait}s, IP대기={ip_wait_after_connect}s, "
        f"검증(ip/gw/ping)={verify_require_ip}/{verify_require_gateway}/{verify_require_ping}, "
        f"최소연결간격={min_connect_interval_seconds}s, 실패시 연결해제={disconnect_on_verify_fail}")

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
                # netsh 출력은 '명령 수락' 수준이므로 성공/실패로 오해 금지
                first_line = out.strip().splitlines()[0] if out.strip() else ""
                log(f"[연결명령] {first_line}")

                last_connect_ts = datetime.now()

                # SSID 연결 상태 대기
                ssid_ok = wait_until_connected(iface, ssid, timeout=connect_wait)
                if not ssid_ok:
                    # SSID 매치 실패여도 실제 네트워크가 살아있을 수 있으니 보조 검증
                    v = verify_connectivity(
                        iface,
                        ip_wait_seconds=max(3, min(10, connect_wait)),  # 너무 오래 끌지 않게
                        require_ip=True,
                        require_gateway=False,  # GW까지 강제하면 성공을 놓칠 수 있음
                        require_ping=bool(cfg.get("verify_require_ping", False)),
                        ping_host=(cfg.get("verify_ping_host") or None)
                    )
                    if v["ok"]:
                        log(f"[참고] SSID 확인에는 실패했지만 네트워크 사용 가능 판정: IP={v['ip']}, GW={v['gw'] or 'N/A'}")
                    else:
                        ip_now = v.get("ip") or get_ipv4_address(iface)
                        log(f"[실패] SSID 연결 확인 실패. 다음 타겟으로. (IP={ip_now or 'N/A'})")
                        time.sleep(0.5)
                        continue

                # (선택) BSSID 유도
                if bssid:
                    if not ensure_bssid(iface, ssid, bssid, retries=retry, scan_wait=2):
                        log(f"[경고] 원하는 BSSID({bssid}) 고정 실패. 현재 BSSID로 진행.")

                # 연결 검증 (IP/GW/Ping)
                v = verify_connectivity(
                    iface,
                    ip_wait_seconds=ip_wait_after_connect,
                    require_ip=verify_require_ip,
                    require_gateway=verify_require_gateway,
                    require_ping=verify_require_ping,
                    ping_host=verify_ping_host
                )

                if not v["ok"]:
                    log(f"[실패] 연결 검증 실패(사유={v['reason']}). IP={v['ip'] or 'N/A'}, GW={v['gw'] or 'N/A'}")
                    if disconnect_on_verify_fail:
                        disconnect(iface)
                    # 실패 시 체류 생략하고 다음 타겟으로
                    continue

                # 성공 로그
                rtt_str = ""
                if verify_require_ping:
                    rtt_str = " (Ping OK)" if v["ping_ok"] else " (Ping N/A)"
                log(f"[성공] 연결/검증 완료. SSID={ssid}, IP={v['ip']}, GW={v['gw']}{rtt_str}")

                # 체류
                time.sleep(dwell)

    except KeyboardInterrupt:
        log("[종료] 사용자 중단")

if __name__ == "__main__":
    rotate()
