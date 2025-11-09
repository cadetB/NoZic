# NoZic.py  
# 작성자: Geunho Baek, Donghyun Kim
# 언어: Python 3.8.5, OS: Windows


import os 
import sys
import struct
import subprocess # 외부 프로세스를 실행하고 관리하기 위한 모듈 (pip, Bandizip CLI)
import importlib
import tempfile   # 임시 파일 및 디렉터리를 생성하기 위한 모듈
import zipfile    # ZIP 파일을 읽고 쓰기 위한 표준 라이브러리 (ZipCrypto 압축 해제용)
import threading
import re
import shutil
import traceback

# GUI 관련 모듈 
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# 윈도우 레지스트리 / win32api (있으면 사용)
try:
    import winreg       # 윈도우 레지스트리에 접근하기 위한 모듈
    import win32api     # 윈도우 API에 접근하기 위한 모듈 (파일 버전, 드라이브 정보)
except Exception:       # 모듈이 없는 경우, 관련 기능을 비활성화하기 위해 None으로 설정
    winreg = None
    win32api = None

# 외부 모듈(pyzipper) 설치/로딩 헬퍼
def setup_dependencies():
    """
    - pywin32 (win32api)와 pyzipper를 자동으로 설치 시도합니다.
    - 설치 후 재시작 알림을 하지 않으며, 설치 결과를 True/False로 반환합니다.
    """
    ok = True
    # pywin32 (win32api) 체크/설치
    try:
        import win32api 
    except Exception:   # 임포트 실패 시 pip를 사용하여 설치 시도
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "pywin32"], stdout=subprocess.DEVNULL)
            # 외부 명령(pip)을 실행하고, 오류 시 예외 발생
            # pywin32 설치 후 모듈 import 시도
            importlib.invalidate_caches()
            try:
                import win32api 
            except Exception:
                ok = False
        except Exception:
            ok = False

    # pyzipper 체크/설치
    try:
        import pyzipper 
    except Exception:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "pyzipper"], stdout=subprocess.DEVNULL)
            importlib.invalidate_caches()
            try:
                import pyzipper  
            except Exception:
                ok = False
        except Exception:
            ok = False

    return ok

# ----------------------------
# 1. 반디집 설치 경로 검색 (레지스트리)
# ----------------------------
def check_bandizip_installation_registry():
    if winreg is None:
        return None     # winreg 모듈이 로드되지 않았으면(None이면) 즉시 None 반환

    bandizip_exe_path = None
    try:        
        keys = [   # 반디집이 설치될 수 있는 가능한 레지스트리 키 목록
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Bandizip"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Bandizip"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Bandizip"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Bandisoft\Bandizip"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Bandisoft\Bandizip"),
        ]
        for hkey, subkey in keys:       # 목록의 키들을 순차적으로 검색
            try:                        # 레지스트리 키 열기 (읽기 전용)
                with winreg.OpenKey(hkey, subkey) as key:
                    install_path, _ = winreg.QueryValueEx(key, "InstallPath")
                    exe_path = os.path.join(install_path, "Bandizip.exe")
                    if os.path.exists(exe_path):
                        bandizip_exe_path = exe_path
                        break
            except FileNotFoundError:
                continue
    except Exception as e:
        print(f"레지스트리 읽기 오류: {e}")
    return bandizip_exe_path

# ----------------------------
# 1-B. 전체 드라이브 검색 (필요 시)
# ----------------------------
def find_bandizip_globally():       # win32api 모듈이 없으면 전체 검색 불가
    if win32api is None:
        return None
    
    print("전체 드라이브 검색 시작...")
    drives = win32api.GetLogicalDriveStrings().split('\x00')[:-1]
    skip_dirs = ("$Recycle.Bin", "System Volume Information", "Windows", "ProgramData")     # 검색에서 제외할 시스템 폴더 (검색 속도 향상 및 오류 방지)
    for drive in drives:
        print(f"{drive} 검색 중...")
        try:    # os.walk: 지정된 경로(drive)부터 시작하여 모든 하위 폴더를 순회
            for root, dirs, files in os.walk(drive):
                dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith('.')]
                for file in files:  # 현재 폴더(root)의 파일 목록(files)을 순회
                    if file.lower() == 'bandizip.exe':  # 파일 이름을 소문자로 변경하여 'bandizip.exe'와 비교
                        found_path = os.path.join(root, file)
                        print(f"발견: {found_path}")
                        return found_path
        except Exception as e:
            print(f"{drive} 검색 중 오류: {e}")
            continue
    print("전체 드라이브 검색 완료. 파일을 찾지 못했습니다.")
    return None

# ----------------------------
# 2. 반디집 버전 확인 (AES256 암호화 지원여부 확인을 위함)
# ----------------------------
def check_bandizip_version(bandizip_exe_path):
    try:
        info = win32api.GetFileVersionInfo(bandizip_exe_path, '\\')
        ms = info['FileVersionMS']
        ls = info['FileVersionLS']
        major = win32api.HIWORD(ms)
        minor = win32api.LOWORD(ms)
        build = win32api.HIWORD(ls)
        rev = win32api.LOWORD(ls)

        # 버전 문자열 포맷팅
        version_str = f"{major}.{minor}.{build}.{rev}"

        if major < 2:
            return None, f"반디집 버전이 너무 낮습니다 ({version_str}). 2.0 이상이 필요합니다."
        return version_str, None
    except Exception as e:
        return None, f"반디집 버전 확인 오류: {e}"

# ----------------------------
# ZIPCrypto 판별
# ----------------------------
def is_zipcrypto_zip(filepath):
    """
    파일이 ZipCrypto로 암호화되었는지 확인합니다.
    AES(compress_type == 99)는 ZipCrypto가 아닙니다.
    """
    # 반디집 전용 포맷(.zipx)은 표준 zipfile 라이브러리가 처리 못하므로 무시
    if filepath.lower().endswith('.zipx'):
        return False
    try:
        with zipfile.ZipFile(filepath, "r") as zf:      # zipfile.ZipFile: zip 파일을 읽기 모드('r')로 열기
            for info in zf.infolist():                  # zf.infolist(): zip 아카이브 내의 모든 파일/폴더 정보 목록 반환
                # flag_bits의 첫 비트(0x1) = 암호화 여부
                if (info.flag_bits & 1) != 0:
                    # 암호화되었더라도, 압축 방식(compress_type)이
                    # 99 (AES)가 아니어야 ZipCrypto입니다.
                    if info.compress_type != 99:
                        return True # 이것이 ZipCrypto입니다.
        
        # 모든 파일을 검사했지만 ZipCrypto를 찾지 못함
        # (AES이거나, 암호화되지 않았거나, 파일이 없는 경우)
        return False
    except zipfile.BadZipFile:
        # zip 파일 형식이 아니거나 손상된 경우
        print(f"[검사 오류] 손상된 ZIP 파일: {filepath}")
        return False
    except Exception as e:
        # 기타 오류 (권한 등)
        print(f"[검사 오류] {filepath}: {e}")
        return False

# ----------------------------
# AES256 알고리즘으로 파일 재압축; pyzipper 우선, 실패 시 Bandizip CLI 폴백
# ----------------------------
def recompress_file_with_aes256(bandizip_path, target_file_path, old_password, new_password, status_callback):
    """
    ZipCrypto → AES-256 재암호화 (기존 파일 덮어쓰기)
    - pyzipper 우선, 실패 시 Bandizip CLI 폴백
    - 한글(cp949) 파일명 인코딩 깨짐 문제 처리
    """
    base_filename = os.path.basename(target_file_path)
    status_callback(f"처리 시작: {base_filename}")
    # --- 1. pyzipper를 사용한 주(Primary) 로직 ---
    try:
        import pyzipper
        status_callback(f"pyzipper 사용: {base_filename} 재압축 시도")

        # tempfile.TemporaryDirectory(): 임시 디렉터리를 생성하고,
        # 'with' 블록이 끝나면 자동으로 삭제됨
        with tempfile.TemporaryDirectory() as tmpdir:
            abs_target = os.path.abspath(target_file_path)
            tmp_zip = os.path.join(tmpdir, "temp_aes.zip") # 임시 AES 파일

            # 1-1. ZipCrypto 파일 해제 (표준 zipfile 사용)
            with zipfile.ZipFile(abs_target, 'r') as zf:
                # 비밀번호를 바이트 문자열로 인코딩 (UTF-8)
                pwd_bytes = old_password.encode('utf-8') if old_password else None
                
                # zf.infolist()로 파일 목록을 순회하며 수동으로 압축 해제
                for info in zf.infolist():
                    filename = info.filename    # zip 헤더에 저장된 파일명
                    
                    # UTF-8 플래그(0x800)가 없는 경우, 한글 인코딩(cp949)으로 강제 변환 시도
                    if not (info.flag_bits & 0x800):
                        try:
                            # zipfile 모듈이 cp437로 잘못 디코딩한 것을 가정하고,
                            # 원본 바이트로 되돌린(encode('cp437')) 후 cp949로 재해석
                            filename_bytes = info.filename.encode('cp437')
                            filename = filename_bytes.decode('cp949')
                        except (UnicodeEncodeError, UnicodeDecodeError):
                            # cp437 -> cp949 변환에 실패하면 원본(깨진) 파일명 사용
                            status_callback(f"인코딩 경고: {info.filename} (변환 실패, 원본 유지)")
                            filename = info.filename 
                    
                    target_path = os.path.join(tmpdir, filename)    # 압축 해제될 파일의 전체 경로
                    abs_tmp_dir = os.path.abspath(tmpdir)           # 임시 디렉터리의 절대 경로
                    
                    # Zip Slip 공격 방지:
                    # 압축 해제 경로(target_path)가 임시 폴더(abs_tmp_dir) 내에 있는지 확인
                    # (예: "../" 같은 경로 조작 방지)
                    if not os.path.abspath(target_path).startswith(abs_tmp_dir):
                        status_callback(f"❌ 보안 오류(Zip Slip) 감지: {info.filename}")
                        raise Exception(f"Zip Slip detected in {info.filename}")

                    if info.is_dir():                           # 디렉터리인 경우
                        os.makedirs(target_path, exist_ok=True) # 폴더 생성
                    else:
                        # 파일 경로의 디렉터리가 없으면 생성
                        if not os.path.exists(os.path.dirname(target_path)):
                             os.makedirs(os.path.dirname(target_path), exist_ok=True)
                        # 파일 추출
                        with zf.open(info, 'r', pwd=pwd_bytes) as source, \
                             open(target_path, 'wb') as target:
                            shutil.copyfileobj(source, target)

            # 1-2. AES-256 재압축 (pyzipper 사용)
            # pyzipper.AESZipFile: AES 암호화를 지원하는 zip 파일 쓰기 모드('w')
            # compression=pyzipper.ZIP_DEFLATED: 표준 Deflate 압축 사용
            with pyzipper.AESZipFile(tmp_zip, 'w', compression=pyzipper.ZIP_DEFLATED) as zout:
                # 새 비밀번호 설정 (바이트) : AES256 알고리즘
                zout.setpassword(new_password.encode('utf-8') if new_password else b'')
                zout.setencryption(pyzipper.WZ_AES, nbits=256)  # 암호화 방식: WZ_AES (WinZip AES), 비트 수: 256
                
                # 임시 폴더(tmpdir)를 순회하며 파일들을 다시 zip에 추가
                for root, _, files in os.walk(tmpdir):
                    for f in files:
                        full_path = os.path.join(root, f)
                        # 방금 생성한 임시 zip 파일(temp_aes.zip) 자신은 추가하지 않도록 방지
                        if full_path == tmp_zip:
                            continue
                        
                        arcname = os.path.relpath(full_path, tmpdir).replace(os.sep, '/')
                        
                        if os.path.isfile(full_path):
                            zout.write(full_path, arcname)
                        elif os.path.isdir(full_path) and not os.listdir(full_path):
                             zout.write(full_path, arcname + '/')


            # 1-3. 기존 파일 덮어쓰기
            # shutil.move: 임시 AES zip 파일(tmp_zip)을 원본 파일(abs_target) 위치로 이동 (덮어쓰기)
            shutil.move(tmp_zip, abs_target)
            status_callback(f"✅ AES 재암호화 완료 (덮어쓰기): {base_filename}")
            return True

    except PermissionError as perm_err:
        # 파일 접근 권한 오류 (예: 파일이 다른 프로그램에서 열려 있음)
        status_callback(f"❌ 권한 오류: {base_filename} 파일에 접근할 수 없습니다. (파일이 다른 곳에 열려있거나, 스크립트를 관리자 권한으로 실행해야 할 수 있습니다.)")
        traceback.print_exc()
        return False

    except Exception as pyerr:
        # pyzipper (또는 표준 zipfile) 실패 시
        status_callback(f"pyzipper 실패: {pyerr}, Bandizip CLI 폴백 시도")
        traceback.print_exc() # pyzipper 오류 상세 출력

    # --- 2. Bandizip CLI를 사용한 폴백(Fallback) 로직 ---
    # (pyzipper가 실패했거나, 임포트되지 않았을 때 이 코드가 실행됨)
    try:        # 반디집 경로가 없거나, 해당 경로에 파일이 없으면 폴백 불가
        if not bandizip_path or not os.path.exists(bandizip_path):
            status_callback("Bandizip CLI 사용 불가 (경로 없음)")
            return False

        with tempfile.TemporaryDirectory() as tmpdir:       # 임시 디렉터리 생성
            abs_target = os.path.abspath(target_file_path)
            
            # 2-1. 압축 풀기
            # -cs:cp949 (charset) 플래그 추가
            # 명령어 리스트 생성: [Bandizip.exe, "x"(추출), "-cs:cp949"(문자셋), "-p:암호", "-o:출력폴더", "대상파일"]
            extract_cmd = [bandizip_path, "x", "-cs:cp949", f"-p:{old_password or ''}", f"-o:{tmpdir}", abs_target]
            # subprocess.run: 명령어 실행
            # check=True: 오류 시 예외 발생
            # capture_output=True: stdout/stderr 캡처
            # encoding='cp949', errors='ignore': 반디집 CLI 출력 인코딩 처리
            subprocess.run(extract_cmd, check=True, capture_output=True, encoding='cp949', errors='ignore')

            # 2-2. 재압축
            tmp_zip = os.path.join(tmpdir, "temp_aes.zip") # 임시 폴더 내에 생성
            
            # 명령어 리스트: [Bandizip.exe, "a"(추가), "-y"(모두예), "-cs:utf-8", "-p:새암호", "-aes256", "결과zip", "대상파일/폴더(.)"]
            # "." : 현재 작업 디렉터리(cwd=tmpdir)의 모든 것
            # -cs:utf-8 플래그 추가하여 새 파일은 UTF-8로 생성
            compress_cmd = [bandizip_path, "a", "-y", "-cs:utf-8", f"-p:{new_password or ''}", "-aes256", tmp_zip, "."]

            # cwd=tmpdir: 명령어의 '현재 작업 디렉터리'를 임시 폴더로 설정
            subprocess.run(compress_cmd, cwd=tmpdir, check=True, capture_output=True, encoding='cp949', errors='ignore')

            # 2-3. 기존 파일 덮어쓰기
            shutil.move(tmp_zip, abs_target)
            status_callback(f"✅ Bandizip CLI 재암호화 완료 (덮어쓰기): {base_filename}")
            return True

    except Exception as e:
        # 반디집 CLI 실행 중 오류 발생 시
        status_callback(f"❌ Bandizip CLI 폴백 실패: {e}")
        traceback.print_exc()
        return False
# ----------------------------
# [제거됨] 검증(반디집 't' 명령어)
# ----------------------------
# verify_aes_conversion 함수가 요청에 따라 제거되었습니다.

# ----------------------------
# 디렉터리 스캐너 (.zip 전용)
# ----------------------------
def find_zipcrypto_files(start_path, bandizip_path, status_callback):
    vulnerable_files = []   # ZipCrypto 파일 목록
    zip_files = []          # 찾은 .zip 파일 전체 목록
    status_callback(f"디렉터리 스캔 중: {start_path}")
    for root, _, files in os.walk(start_path):
        for f in files:
            lf = f.lower()
            if lf.endswith(".zip"):
                zip_files.append(os.path.join(root, f))
            elif lf.endswith(".zipx"):
                # zipx 파일은 무시
                pass

    status_callback(f"총 zip 파일 수: {len(zip_files)} - 검사 시작")
    for i, f in enumerate(zip_files, 1):
        if i % 100 == 0:
            status_callback(f".zip 검사 중... {i}/{len(zip_files)}")
        try:
            if is_zipcrypto_zip(f):     # 암호화 방식 검사 
                vulnerable_files.append(f)
        except Exception as e:
            # 개별 파일 오류는 로그로 남기고 계속 진행
            status_callback(f"[무시된 파일] {f} - {e}")

    status_callback(f"스캔 완료. {len(vulnerable_files)}개의 ZipCrypto 암호화 파일을 찾았습니다.")
    return vulnerable_files

# ----------------------------
# 반디집 AES 기본 설정 
# ----------------------------
def force_aes256_default_setting():
    try:
        if winreg is None:      # winreg 모듈이 없으면 실행 불가
            return False
        reg_path = r"SOFTWARE\Bandizip" # 반디집 설정이 저장되는 레지스트리 경로
        value_name = "comp.zipEnc"      # ZIP 암호화 설정 값 이름 ("comp.zipEnc") 
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path) as key:
            winreg.SetValueEx(key, value_name, 0, winreg.REG_DWORD, 1)    # 1: AES-256 (반디집 설정 기준) 
        return True
    except Exception:
        return False
# ----------------------------
# GUI 클래스 (수정됨)
# ----------------------------
class App(tk.Tk):
    def __init__(self, bandizip_path):
        super().__init__()
        self.bandizip_path = bandizip_path
        self.title("NoZic")
        self.geometry("900x600")

        # 파일(Treeview 아이템 ID)별로 비밀번호를 저장할 딕셔너리
        self.password_map = {}

        top = ttk.Frame(self, padding=8)
        top.pack(fill=tk.X)
        mid = ttk.Frame(self, padding=8)
        mid.pack(fill=tk.BOTH, expand=True)
        bottom = ttk.Frame(self, padding=8)
        bottom.pack(fill=tk.X)

        self.scan_btn = ttk.Button(top, text="폴더 선택 / 스캔 시작", command=self.on_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=5)

        self.convert_btn = ttk.Button(top, text="변환 시작", command=self.on_convert)
        self.convert_btn.pack(side=tk.RIGHT, padx=5)
        
        self.harden_btn = ttk.Button(top, text="AES 설정 변경", command=self.on_harden_defaults)
        self.harden_btn.pack(side=tk.RIGHT, padx=5)


        self.tree = ttk.Treeview(mid, columns=("path", "oldpw", "newpw"), show="headings")
        self.tree.heading("path", text="파일 경로")
        self.tree.heading("oldpw", text="기존 비밀번호")
        self.tree.heading("newpw", text="새 비밀번호")
        self.tree.column("path", width=600)
        self.tree.column("oldpw", width=100, anchor=tk.CENTER)
        self.tree.column("newpw", width=100, anchor=tk.CENTER)
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<Double-1>", self.on_double_click)

        self.status_label = ttk.Label(bottom, text="대기 중...")
        self.status_label.pack(side=tk.LEFT)

        self.files = []

    def disable_all_buttons(self):
        self.scan_btn.config(state=tk.DISABLED)
        self.convert_btn.config(state=tk.DISABLED)
        self.harden_btn.config(state=tk.DISABLED)

    def enable_all_buttons(self):
        self.scan_btn.config(state=tk.NORMAL)
        self.convert_btn.config(state=tk.NORMAL)
        self.harden_btn.config(state=tk.NORMAL)
        # 반디집 경로가 없으면 'AES 설정 변경' 버튼은 활성화하되,
        # winreg 모듈이 없으면 어차피 _harden_thread에서 차단됨.
        # Bandizip.exe 자체는 AES 설정과 무관.

    # GUI 상태 표시줄 업데이트 (스레드에서 호출됨)
    def update_status(self, text):
        self.status_label.config(text=text)
        self.update_idletasks()

    # "스캔 시작" 버튼 클릭 시
    def on_scan(self):
        folder = filedialog.askdirectory()
        if not folder:
            return
        self.tree.delete(*self.tree.get_children())
        self.password_map.clear()

        # 버튼 비활성화 (헬퍼 사용)
        self.disable_all_buttons()

        # 스캔 작업(find_zipcrypto_files)은 오래 걸릴 수 있으므로 별도 스레드에서 실행
        # daemon=True: 메인 프로그램 종료 시 스레드도 강제 종료
        threading.Thread(target=self._scan_thread, args=(folder,), daemon=True).start()

    def _scan_thread(self, folder):     
        self.files = find_zipcrypto_files(folder, self.bandizip_path, self.update_status)
        for p in self.files:        # 스캔 결과를 GUI(Treeview)에 추가
            self.after(0, lambda path=p: self.tree.insert("", "end", values=(path, "", "")))
        
        # 버튼 활성화 (헬퍼 사용)
        self.after(0, self.enable_all_buttons)
        self.update_status(f"스캔 완료. {len(self.files)}개의 파일을 변환해야 합니다.")
    
    # "변환 시작" 버튼 클릭 시
    def on_convert(self):
        items = self.tree.get_children()
        if not items:
            messagebox.showwarning("경고", "변환할 파일이 없습니다.")
            return

        pw_map_for_thread = {}
        for it in items:
            path = self.tree.item(it, "values")[0]
            passwords = self.password_map.get(it)

            # 기존/새 비밀번호가 모두 입력되었는지 확인
            if not passwords or not passwords.get("old") or not passwords.get("new"):
                messagebox.showerror("오류", f"{os.path.basename(path)} 파일의 기존/새 비밀번호를 모두 입력하세요.")
                return
            # 스레드용 맵에 (파일경로, 구비번, 새비번) 저장
            pw_map_for_thread[it] = (path, passwords["old"], passwords["new"])

        # 버튼 비활성화 (헬퍼 사용)
        self.disable_all_buttons()

        # 변환 작업을 별도 스레드에서 실행
        threading.Thread(target=self._convert_thread, args=(pw_map_for_thread,), daemon=True).start()

    def _convert_thread(self, pw_map):
        # 원본 삭제 대신 덮어쓰기 방식이므로, 성공/실패만 태그
        for it, (path, oldpw, newpw) in pw_map.items():
            ok = recompress_file_with_aes256(self.bandizip_path, path, oldpw, newpw, self.update_status)
            tag = "ok" if ok else "fail"
            # 성공 시 목록에서 제거하지 않고, 태그만 함
            self.after(0, lambda iid=it, t=tag: self.tree.item(iid, tags=(t,)))
        
        self.tree.tag_configure("ok", background="lightgreen")
        self.tree.tag_configure("fail", background="lightcoral")
        
        # 버튼 활성화 (헬퍼 사용)
        self.after(0, self.enable_all_buttons)
        self.update_status("모든 변환 작업이 완료되었습니다.")


    # "AES 설정 변경" 버튼 로직 #############################################################
    def on_harden_defaults(self):
        self.update_status("기본 AES 설정 변경 시작...")
        self.disable_all_buttons()
        # 별도 스레드에서 설정 변경 작업 실행
        threading.Thread(target=self._harden_thread, daemon=True).start()

    # 5종 유틸리티 AES 강제화 스레드
    def _harden_thread(self):
        if winreg is None:
            self.after(0, lambda: self.update_status("오류: winreg 모듈이 없어 레지스트리 수정이 불가능합니다."))
            self.after(0, self.enable_all_buttons)
            self.after(0, lambda: messagebox.showerror("오류", "Windows 레지스트리 모듈(winreg)을 찾을 수 없어\nAES 설정을 변경할 수 없습니다."))
            return

        results = [] # 결과 메시지를 저장할 리스트

        # --- 1. 반디집 (Bandizip) ---
        try:
            if force_aes256_default_setting():  # 기존 함수 사용 
                results.append("✅ 반디집: AES-256으로 설정 완료.")
            else:
                results.append("⚠️ 반디집: 설정 실패 (설치되지 않았거나 오류 발생).")
        except Exception as e:
            results.append(f"❌ 반디집: 오류 발생 {e}")

        # --- 2. 7-Zip ---
        # (CSV: HKCU\SOFTWARE\7-Zip\Compression\Options\zip, EncryptionMethod, AES: RegSetValue, Data: AES256) 
        try:
            key_path = r"SOFTWARE\7-Zip\Compression\Options\zip"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                # CSV에서 "Data: AES256" 확인, REG_SZ 타입으로 "AES256" 값 설정
                winreg.SetValueEx(key, "EncryptionMethod", 0, winreg.REG_SZ, "AES256")
                results.append("✅ 7-Zip: AES-256으로 설정 완료.")
        except FileNotFoundError:
            results.append("ℹ️ 7-Zip: 설치되지 않음 (키 없음).")
        except Exception as e:
            results.append(f"❌ 7-Zip: 오류 발생 {e}")

        # --- 3. WinRAR ---
        # (CSV: HKCU\SOFTWARE\WinRAR\Profiles\0, Default=1, ZipLegacyEncrypt=0) 
        try:
            key_path = r"SOFTWARE\WinRAR\Profiles\0"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                # 1. Default(AES) = 1 (DWORD) 
                winreg.SetValueEx(key, "Default", 0, winreg.REG_DWORD, 1)
                # 2. ZipLegacyEncrypt(ZIPC) = 0 (DWORD) 
                winreg.SetValueEx(key, "ZipLegacyEncrypt", 0, winreg.REG_DWORD, 0)
                results.append("✅ WinRAR: AES-256으로 설정 완료 (Default=1, ZipLegacyEncrypt=0).")
        except FileNotFoundError:
            results.append("ℹ️ WinRAR: 설치되지 않음 (키 없음).")
        except Exception as e:
            results.append(f"❌ WinRAR: 오류 발생 {e}")

        # --- 4. WinZip ---
        # (CSV: HKCU\SOFTWARE\Nico Mak Computing\WinZip\WinZip, EncryptionMethod, AES: Type_REG_SZ, Data_4) 
        try:
            key_path = r"SOFTWARE\Nico Mak Computing\WinZip\WinZip"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                # CSV에서 "Type_REG_SZ, Data_4" 확인, REG_SZ 타입으로 "4" 값 설정 
                winreg.SetValueEx(key, "EncryptionMethod", 0, winreg.REG_SZ, "4")
                results.append("✅ WinZip: AES-256으로 설정 완료.")
        except FileNotFoundError:
            results.append("ℹ️ WinZip: 설치되지 않음 (키 없음).")
        except Exception as e:
            results.append(f"❌ WinZip: 오류 발생 {e}")

        # --- 5. PeaZip ---
        # (CSV: ...\AppData\Roaming\PeaZip\conf.txt, [encryption algorithm for ZIP...], AES: 0) 
        try:
            # %APPDATA% 환경 변수를 사용하여 사용자별 경로 동적 생성
            conf_path = os.path.join(os.environ['APPDATA'], 'PeaZip', 'conf.txt')
            if not os.path.exists(conf_path):
                results.append("ℹ️ PeaZip: 설치되지 않음 (conf.txt 없음).")
            else:
                content = ""
                # 설정 파일은 인코딩이 다양할 수 있으므로, utf-8 시도 후 latin-1(cp1252) 폴백
                try:
                    with open(conf_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                except UnicodeDecodeError:
                    with open(conf_path, 'r', encoding='latin-1') as f:
                        content = f.read()
                
                # CSV 키: [encryption algorithm for ZIP 0 AES 1 ZipCrypto (legacy)] 
                # AES 값: 0 
                # 정규식: (키 시작 부분) + (값) -> (키) + (새 값 '0')
                pattern_str = r"(\[encryption algorithm for ZIP[^\]]+\]\s*)\S+"
                pattern = re.compile(pattern_str, re.IGNORECASE) # 대소문자 무시
                
                if pattern.search(content):
                    # 키(group 1)는 유지하고, 뒤의 값만 " 0"으로 변경
                    content = pattern.sub(r"\1 0", content, count=1)
                    
                    with open(conf_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    results.append("✅ PeaZip: AES-256으로 설정 완료.")
                else:
                    results.append("⚠️ PeaZip: conf.txt에서 설정 키를 찾지 못함.")
        except Exception as e:
            results.append(f"❌ PeaZip: 파일 처리 중 오류 발생 {e}")

        # --- 작업 완료 ---
        # 팝업으로 결과 요약 보고
        self.after(0, lambda r="\n".join(results): messagebox.showinfo("AES 설정 완료", r))
        # 버튼 활성화
        self.after(0, self.enable_all_buttons)
        self.after(0, lambda: self.update_status("AES 기본 설정 변경 완료."))


    def ask_password_popup(self, title, prompt_message):        # 비밀번호 입력을 위한 커스텀 팝업창
        win = tk.Toplevel(self)
        win.title(title)
        ttk.Label(win, text=prompt_message).pack(padx=10, pady=(10, 0))
        entry_frame = ttk.Frame(win)
        entry_frame.pack(padx=10, pady=(5, 5), fill=tk.X, expand=True)
        entry = ttk.Entry(entry_frame, show="*")
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        show_pw_var = tk.BooleanVar(value=False)
        def toggle_visibility():
            if show_pw_var.get():
                entry.config(show="")
            else:
                entry.config(show="*")
        toggle_btn = ttk.Checkbutton(entry_frame, text="표시", variable=show_pw_var, command=toggle_visibility)
        toggle_btn.pack(side=tk.LEFT)
        entry.focus_set()
        result = tk.StringVar()
        def apply_pw():
            result.set(entry.get())
            win.destroy()
        ok_button = ttk.Button(win, text="확인", command=apply_pw)
        ok_button.pack(pady=(0, 10))
        win.transient(self)
        win.grab_set()
        self.wait_window(win)
        return result.get() if result.get() else None

    def on_double_click(self, event):       # Treeview 더블 클릭 이벤트 핸들러
        row = self.tree.identify_row(event.y)
        col = self.tree.identify_column(event.x)
        if not row or col not in ("#2", "#3"):
            return
        prompt_title = "기존 비밀번호 입력" if col == "#2" else "새 비밀번호 입력"
        prompt_msg = f"'{os.path.basename(self.tree.item(row, 'values')[0])}' 파일의\n{prompt_title.split(' ')[0] + ' ' + prompt_title.split(' ')[1]}를 입력하세요."
        password = self.ask_password_popup(prompt_title, prompt_msg)
        if password is not None:
            if row not in self.password_map:
                self.password_map[row] = {"old": "", "new": ""}
            if col == "#2":
                self.password_map[row]["old"] = password
            elif col == "#3":
                self.password_map[row]["new"] = password
            display_value = "********" if password else ""
            self.tree.set(row, column=col, value=display_value)

# ----------------------------
# 메인 실행 지점
# ----------------------------
if __name__ == "__main__":
    # pywin32/pyzipper 설치 시도 (선택적)
    deps_ok = setup_dependencies()
    if not deps_ok:
        # 설치에 실패해도 계속 시도: Bandizip만 있으면 동작
        print("의존성 설치에 일부 실패했을 수 있습니다. pyzipper 또는 pywin32가 없으면 Bandizip CLI로 폴백합니다.")
    
    # pyzipper 로드 재시도
    try:
        import pyzipper 
        print("pyzipper 모듈 로드 성공.")
    except ImportError:
        print("pyzipper 모듈 로드 실패. Bandizip CLI 폴백을 사용합니다.")

    # win32api 로드 재시도 (전역 변수 갱신)
    try:
        import winreg
        import win32api
        print("win32api 모듈 로드 성공.")
    except ImportError:
        winreg = None
        win32api = None
        print("win32api 모듈 로드 실패. 일부 자동 검색 기능이 제한됩니다.")


    bandizip_path = None
    config_file = 'bandizip_path.txt'

    # 1. 캐시된 경로 확인
    try:
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                path_from_cache = f.read().strip()
            if os.path.exists(path_from_cache):
                print(f"캐시에서 경로 찾음: {path_from_cache}")
                bandizip_path = path_from_cache
            else:
                try:
                    os.remove(config_file)
                except Exception:
                    pass
    except Exception as e:
        print(f"캐시 파일 읽기 오류: {e}")

    # 2. 레지스트리 확인
    if not bandizip_path:
        print("레지스트리 검색 중...")
        bandizip_path = check_bandizip_installation_registry()

    # 3. PATH 환경 변수 확인
    if not bandizip_path:
        print("PATH 환경 변수 검색 중...")
        bandizip_path = shutil.which('Bandizip.exe')

    # 4. 전체 시스템 검색 (최후의 수단)
    if not bandizip_path and win32api: # win32api가 있어야만 실행
        print("자동 검색 실패. 전체 시스템 검색을 사용자에게 제안합니다.")
        root = tk.Tk()
        root.withdraw()
        if messagebox.askyesno("반디집 자동 검색",
                                "반디집(Bandizip.exe)을 자동으로 찾지 못했습니다.\n\n"
                                "시스템 전체 드라이브에서 'Bandizip.exe'를 검색하시겠습니까?\n"
                                "(이 작업은 몇 분 정도 소요될 수 있습니다.)"):
            messagebox.showinfo("검색 시작", "시스템 전체 검색을 시작합니다. (완료까지 시간이 걸립니다)")
            root.destroy()
            bandizip_path = find_bandizip_globally()
            root_after = tk.Tk()
            root_after.withdraw()
            if bandizip_path:
                messagebox.showinfo("검색 완료", f"반디집을 찾았습니다:\n{bandizip_path}\n\n이 경로를 저장하여 다음 실행부터는 묻지 않습니다.")
                try:
                    with open(config_file, 'w') as f:
                        f.write(bandizip_path)
                except Exception as e:
                    print(f"캐시 파일 쓰기 오류: {e}")
            else:
                messagebox.showwarning("검색 실패", "시스템 전체에서 'Bandizip.exe'를 찾지 못했습니다.")
            root_after.destroy()
        else:
            root.destroy()
    elif not win32api:
        print("win32api 모듈이 없어 전체 시스템 검색을 건너뜁니다.")


    # 5. 최종 경로 유효성 검사 (Bandizip 없더라도 pyzipper가 있으면 계속)
    if not bandizip_path or not os.path.exists(bandizip_path):
        print("Bandizip 경로를 찾지 못했습니다. pyzipper가 설치되어 있으면 Bandizip 없이 동작합니다.")
        # 반디집 경로가 None일 때 pyzipper 폴백을 위해 None 유지
        bandizip_path = None 
    else:
        # 버전 확인 (권장)
        if win32api: # 버전 확인은 win32api 필요
            try:
                version_str, msg = check_bandizip_version(bandizip_path)
                if not version_str:
                    messagebox.showerror("버전 오류", msg)
                    sys.exit(1)
                print(f"반디집 실행: {bandizip_path} (버전: {version_str})")
            except Exception:
                print("반디집 버전 확인 실패 (무시하고 계속)")
                pass
        else:
            print(f"반디집 경로 확인: {bandizip_path} (win32api 없어 버전 확인 불가)")



    # 7. 프로그램 실행
    app = App(bandizip_path)
    
    if not bandizip_path:
        app.update_status("Bandizip 없음. pyzipper로 변환 시도.")
    else:
        app.update_status("대기 중...")

    app.mainloop()