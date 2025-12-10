#!/usr/bin/env python3
"""
Forensics Analyzer - 포렌식 분석기
"""

import re
from datetime import datetime, timedelta
from typing import Dict, List

# 상위 디렉토리의 core 모듈 import
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.registry_parser import RegistryParser


class ForensicsAnalyzer:
    """포렌식 분석기"""
    
    def __init__(self, parser: RegistryParser, hive_type: str):
        self.parser = parser
        self.hive_type = hive_type.upper()
    
    def analyze_shimcache(self) -> List[Dict]:
        """ShimCache (AppCompatCache) 분석 - PROFESSIONAL UPGRADE"""
        results = []
        
        # .exe, .dll 등의 실행 파일 경로 검색
        patterns = ['.exe', '.dll', '.sys', '.scr']
        
        for pattern in patterns:
            offsets = self.parser.search_pattern(pattern)
            
            for offset in offsets:  # Increased from 50 to 100
                # 경로 추출 시도 (improved path extraction)
                path = self._extract_shimcache_path(offset)
                
                if path and ':\\' in path and len(path) > 5:
                    # Extract timestamp (FILETIME, 8-byte QWORD)
                    timestamp = self._extract_shimcache_timestamp(offset)
                    
                    # Extract file size (DWORD, 4-byte)
                    file_size = self._extract_shimcache_filesize(offset)
                    
                    results.append({
                        'path': path,
                        'timestamp': timestamp,
                        'fileSize': file_size,
                        'type': 'ShimCache',
                        'offset': offset
                    })
        
        return self._deduplicate_shimcache_entries(results)
    
    def analyze_userassist(self) -> List[Dict]:
        """UserAssist 분석 (사용자 활동 추적) - PROFESSIONAL UPGRADE"""
        results = []
        
        # ROT13으로 인코딩된 GUID 검색
        userassist_patterns = [
            'HRZR_PGYFRFFVBA',  # ROT13: UEME_CTLSESSION
            'HRZR_EHAPZH',      # ROT13: UEME_RUNPMU
        ]
        
        for pattern in userassist_patterns:
            offsets = self.parser.search_pattern(pattern)
            
            for offset in offsets:  # Increased from 20 to 50
                # 주변 데이터 분석
                context = self._get_context_strings(offset, 200)
                
                for ctx in context:
                    if ctx and len(ctx) > 5:
                        # ROT13 디코딩 시도
                        decoded = self._rot13_decode(ctx)
                        
                        if self._is_valid_path(decoded):
                            # Extract run count (DWORD, 4-byte)
                            run_count = self._extract_userassist_runcount(offset)
                            
                            # Extract focus time (milliseconds)
                            focus_time = self._extract_userassist_focustime(offset)
                            
                            # Extract last executed timestamp
                            last_executed = self._extract_userassist_timestamp(offset)
                            
                            # Remove UEME_ prefix if exists
                            cleaned_program = decoded.replace('UEME_', '')
                            
                            results.append({
                                'program': cleaned_program,
                                'runCount': run_count,
                                'focusTime': focus_time,
                                'lastExecuted': last_executed,
                                'type': 'UserAssist',
                                'offset': offset
                            })
        
        return self._deduplicate_userassist_entries(results)
    
    def analyze_amcache(self) -> List[Dict]:
        """Amcache 분석 (프로그램 설치 및 실행 정보)"""
        results = []
        
        # Amcache.hve 전용
        if 'AMCACHE' not in self.hive_type.upper() and '.HVE' not in self.hive_type.upper():
            return []
        
        # 실행 파일 패턴
        patterns = ['.exe', '.dll', '.sys', '.msi']
        
        for pattern in patterns:
            offsets = self.parser.search_pattern(pattern)
            
            for offset in offsets:  # 최대 100개
                # 경로 추출
                file_path = self._extract_path_at_offset(offset)
                if not file_path:
                    continue
                
                # SHA1 해시 추출 (20바이트)
                sha1 = self._extract_sha1_hash(offset)
                
                # 타임스탬프 추출
                timestamp = self._find_nearby_timestamp(offset)
                
                # 파일 크기 추출
                file_size = self._extract_file_size(offset)
                
                # Publisher 추출
                publisher = self._extract_publisher(offset)
                
                # Version 추출
                version = self._extract_version(offset)
                
                program_name = file_path.split('\\')[-1] if '\\' in file_path else file_path
                
                results.append({
                    'programName': program_name,
                    'filePath': file_path,
                    'sha1': sha1,
                    'timestamp': timestamp,
                    'fileSize': file_size,
                    'publisher': publisher,
                    'version': version,
                    'type': 'Amcache',
                    'offset': offset
                })
        
        # 프로그램 정보 필드로도 검색
        program_patterns = ['ProgramName', 'Publisher', 'InstallDate']
        for pattern in program_patterns:
            offsets = self.parser.search_pattern(pattern)
            
            for offset in offsets:
                program_name = self.parser.read_unicode_string(offset + 20, 100)
                if program_name and len(program_name) > 2:
                    file_path = self._extract_path_at_offset(offset)
                    
                    results.append({
                        'programName': program_name,
                        'filePath': file_path or '',
                        'sha1': self._extract_sha1_hash(offset),
                        'timestamp': self._find_nearby_timestamp(offset),
                        'fileSize': self._extract_file_size(offset),
                        'publisher': self._extract_publisher(offset),
                        'version': self._extract_version(offset),
                        'type': 'Amcache',
                        'offset': offset
                    })
        
        # 중복 제거 (더 많은 정보를 가진 엔트리 우선)
        return self._deduplicate_amcache_entries(results)
    
    def analyze_bam_dam(self) -> List[Dict]:
        """BAM/DAM (Background Activity Moderator) 분석 - PROFESSIONAL UPGRADE"""
        results = []
        
        # BAM/DAM 관련 패턴
        patterns = ['\\Device\\HarddiskVolume', 'SystemRoot']
        
        for pattern in patterns:
            offsets = self.parser.search_pattern(pattern)
            
            for offset in offsets:  # Increased from 30 to 50
                path = self._extract_path_at_offset(offset)
                
                if path and '\\' in path:
                    # Convert device path to drive letter (e.g., C:\)
                    converted_path = self._convert_device_path_to_drive(path)
                    
                    # Extract timestamp (Windows 10/11 uses FILETIME)
                    timestamp = self._find_nearby_timestamp(offset)
                    
                    # Filter by timestamp (BAM/DAM introduced in Windows 10, 2015+)
                    if timestamp and '201' in timestamp[:4]:  # 2015+
                        year = int(timestamp[:4])
                        if year < 2015:
                            continue
                    
                    # Extract user SID
                    user_sid = self._extract_user_sid(offset)
                    
                    results.append({
                        'path': converted_path,
                        'timestamp': timestamp,
                        'userSID': user_sid,
                        'type': 'BAM/DAM',
                        'offset': offset
                    })
        
        return self._deduplicate_bamdam_entries(results)
    
    def analyze_usb_devices(self) -> List[Dict]:
        """USB 장치 분석 (타임스탬프 추가)"""
        results = []
        
        # USB 관련 패턴
        usb_patterns = ['VID_', 'PID_', 'USBSTOR', '\\??\\USB#']
        
        for pattern in usb_patterns:
            offsets = self.parser.search_pattern(pattern)
            
            for offset in offsets:
                context = self.parser.read_string(offset, 200)
                
                # VID/PID 추출
                vid_match = re.search(r'VID_([0-9A-F]{4})', context)
                pid_match = re.search(r'PID_([0-9A-F]{4})', context)
                
                if vid_match or pid_match:
                    # 시리얼 넘버 추출 시도
                    serial_match = re.search(r'\\([0-9A-F&]{8,})', context)
                    
                    # 타임스탬프 추출 시도
                    timestamp = self._find_nearby_timestamp(offset)
                    
                    # 장치 이름 추출 시도 (USBSTOR\Disk&... 패턴)
                    device_name = None
                    name_match = re.search(r'Disk&[^\\]+\\([^\\]+)', context)
                    if name_match:
                        device_name = name_match.group(1)
                    
                    results.append({
                        'device': context,
                        'vid': vid_match.group(1) if vid_match else None,
                        'pid': pid_match.group(1) if pid_match else None,
                        'serial': serial_match.group(1) if serial_match else None,
                        'deviceName': device_name,
                        'timestamp': timestamp,
                        'type': 'USB Device',
                        'offset': offset
                    })
        
        return results
    
    def analyze_recent_docs(self) -> List[Dict]:
        """최근 문서 분석 (개선된 버전)"""
        results = []
        
        # NTUSER.DAT 하이브에서만 정확한 분석 가능
        if self.hive_type in ['NTUSER.DAT', 'UsrClass.dat']:
            # RecentDocs 키 패턴 검색
            recentdocs_patterns = [
                b'RecentDocs',
                b'\\Explorer\\RecentDocs',
                b'OpenSavePidlMRU'
            ]
            
            for pattern in recentdocs_patterns:
                found = False
                offset = 0
                while offset < self.parser.size:
                    pos = self.parser.data.find(pattern, offset)
                    if pos == -1:
                        break
                    found = True
                    
                    # RecentDocs 근처에서 파일 경로 추출 시도
                    for back in range(0, 500, 2):
                        test_offset = pos + back
                        if test_offset >= self.parser.size:
                            break
                        
                        # Unicode 파일명 추출
                        filename = self.parser.read_unicode_string(test_offset, 520)
                        
                        # 유효한 문서 확장자 체크
                        if filename and any(ext in filename.lower() for ext in ['.doc', '.pdf', '.xls', '.txt', '.jpg', '.png', '.ppt', '.zip']):
                            # 타임스탬프 추출 시도
                            timestamp = self._find_nearby_timestamp(pos)
                            
                            results.append({
                                'document': filename,
                                'timestamp': timestamp,
                                'type': 'RecentDocs (NTUSER.DAT)',
                                'offset': pos
                            })
                    
                    offset = pos + 1
                    if len(results) > 100:  # 너무 많으면 중단
                        break
        
        # 다른 하이브에서는 기본 패턴 검색 (덜 정확)
        else:
            doc_patterns = ['.doc', '.pdf', '.xls', '.txt', '.jpg', '.png', '.ppt', '.zip']
            
            for pattern in doc_patterns:
                offsets = self.parser.search_pattern(pattern)
                
                for offset in offsets:
                    path = self._extract_path_at_offset(offset)
                    
                    if path and ('\\' in path or '/' in path) and len(path) > 5:
                        # 타임스탬프 추출 시도
                        timestamp = self._find_nearby_timestamp(offset)
                        
                        results.append({
                            'document': path,
                            'timestamp': timestamp,
                            'type': 'Document Path',
                            'offset': offset
                        })
        
        return self._deduplicate_by_path(results)
    
    def analyze_run_keys(self) -> List[Dict]:
        """Run/RunOnce 키 분석 (자동 시작 프로그램)"""
        results = []
        
        # Run 키 패턴
        run_patterns = ['Run', 'RunOnce', 'RunServices']
        
        for pattern in run_patterns:
            offsets = self.parser.search_pattern(pattern)
            
            for offset in offsets:
                # 주변에서 실행 경로 찾기
                for i in range(-200, 200, 2):
                    test_offset = offset + i
                    if test_offset < 0:
                        continue
                    
                    path = self.parser.read_unicode_string(test_offset, 500)
                    
                    if self._is_valid_executable_path(path):
                        results.append({
                            'name': pattern,
                            'command': path[:200],
                            'type': 'Auto-Start',
                            'offset': offset
                        })
                        break
        
        return self._deduplicate_by_command(results)
    
    def analyze_sam_users(self) -> List[Dict]:
        """SAM 사용자 계정 분석 (타임스탬프 추가)"""
        if self.hive_type != 'SAM':
            return []
        
        results = []
        
        # SID 패턴 (S-1-5-21-...)
        sid_pattern = 'S-1-5-21'
        offsets = self.parser.search_pattern(sid_pattern)
        
        for offset in offsets:
            sid = self.parser.read_string(offset, 100)
            
            # 사용자명 찾기 (SID 주변)
            username = self._find_username_near_sid(offset)
            
            if username:
                # 마지막 로그인 시간 추출 시도
                last_login = self._find_nearby_timestamp(offset)
                
                # 계정 생성 시간 추출 시도 (다른 위치에서)
                created_time = None
                for back in range(100, 500, 8):
                    test_offset = offset - back
                    if test_offset < 0:
                        break
                    filetime = self.parser.read_qword(test_offset)
                    dt = self.parser.filetime_to_datetime(filetime)
                    if dt and 1995 < dt.year < 2030:
                        created_time = dt.strftime('%Y-%m-%d %H:%M:%S')
                        break
                
                results.append({
                    'username': username,
                    'sid': sid,
                    'lastLogin': last_login,
                    'created': created_time,
                    'type': 'User Account',
                    'offset': offset
                })
        
        # Administrator, Guest 등 기본 계정 검색
        default_users = ['Administrator', 'Guest', 'DefaultAccount']
        for user in default_users:
            offsets = self.parser.search_pattern(user)
            if offsets:
                timestamp = self._find_nearby_timestamp(offsets[0])
                results.append({
                    'username': user,
                    'sid': 'Unknown',
                    'lastLogin': timestamp,
                    'created': None,
                    'type': 'User Account',
                    'offset': offsets[0]
                })
        
        return self._deduplicate_by_username(results)
    
    def analyze_network_profiles(self) -> List[Dict]:
        """네트워크 프로필 분석"""
        results = []
        
        network_patterns = ['ProfileName', 'Description', 'SSID']
        
        for pattern in network_patterns:
            offsets = self.parser.search_pattern(pattern)
            
            for offset in offsets[:10]:
                name = self.parser.read_unicode_string(offset + 20, 100)
                
                if name and len(name) > 2:
                    results.append({
                        'network': name,
                        'type': 'Network Profile',
                        'offset': offset
                    })
        
        return results
    
    # Helper methods
    def _extract_path_at_offset(self, offset: int) -> str:
        """오프셋에서 경로 추출 (improved with printable filter)"""
        # ASCII 시도
        for back in range(0, 500, 1):
            test_offset = offset - back
            if test_offset < 0:
                break
            
            path = self.parser.read_string(test_offset, 500)
            if ':\\' in path and len(path) > 5:
                # 드라이브 문자부터 추출
                drive_idx = path.find(':\\')
                if drive_idx > 0:
                    path = path[drive_idx-1:]
                    # Keep only printable ASCII
                    path = ''.join(c for c in path if 32 <= ord(c) <= 126)
                    # Remove registry signatures
                    import re
                    path = re.sub(r'(vk|nk|lh|sk)(?![a-z]).*$', '', path, flags=re.IGNORECASE)
                    if ';' in path:
                        path = path[:path.index(';')]
                    return path.strip()
        
        # Unicode 시도
        for back in range(0, 500, 2):
            test_offset = offset - back
            if test_offset < 0:
                break
            
            path = self.parser.read_unicode_string(test_offset, 500)
            if ':\\' in path and len(path) > 5:
                drive_idx = path.find(':\\')
                if drive_idx > 0:
                    clean_path = path[drive_idx-1:]
                    # Keep only printable ASCII
                    clean_path = ''.join(c for c in clean_path if c.isprintable() and ord(c) < 127)
                    # Remove registry signatures
                    import re
                    clean_path = re.sub(r'(vk|nk|lh|sk)(?![a-z]).*$', '', clean_path, flags=re.IGNORECASE)
                    if ';' in clean_path:
                        clean_path = clean_path[:clean_path.index(';')]
                    return clean_path.strip()
        
        return ""
    
    def _get_context_strings(self, offset: int, range_size: int) -> List[str]:
        """오프셋 주변 문자열 추출"""
        strings = []
        start = max(0, offset - range_size)
        end = min(self.parser.size, offset + range_size)
        
        # ASCII
        current = ""
        for i in range(start, end):
            byte = self.parser.data[i]
            if 32 <= byte <= 126:
                current += chr(byte)
            else:
                if len(current) >= 4:
                    strings.append(current)
                current = ""
        
        return strings
    
    def _find_nearby_timestamp(self, offset: int) -> str:
        """주변에서 타임스탬프 찾기"""
        # 8바이트 FILETIME 검색
        for i in range(offset - 100, offset + 100, 8):
            if i < 0 or i + 8 > self.parser.size:
                continue
            
            filetime = self.parser.read_qword(i)
            dt = self.parser.filetime_to_datetime(filetime)
            
            if dt and 1990 < dt.year < 2100:
                return dt.strftime('%Y-%m-%d %H:%M:%S')
        
        return None
    
    def _extract_shimcache_path(self, offset: int) -> str:
        """ShimCache 경로 추출 (improved 500-byte backward search)"""
        best_path = ""
        
        # Unicode path search (primary method)
        for back in range(0, 500, 2):
            test_offset = offset - back
            if test_offset < 0:
                break
            
            path = self.parser.read_unicode_string(test_offset, 520)  # 260 chars * 2
            if ':\\' in path and ('.' in path or '\\' in path):
                # Extract from drive letter
                drive_idx = path.find(':\\')
                if drive_idx > 0:
                    clean_path = path[drive_idx-1:]
                    # Keep only printable ASCII characters
                    clean_path = ''.join(c for c in clean_path if c.isprintable() and ord(c) < 127)
                    # Remove registry signatures at end (vk, nk, lh, sk not followed by letter)
                    import re
                    clean_path = re.sub(r'(vk|nk|lh|sk)(?![a-z]).*$', '', clean_path, flags=re.IGNORECASE)
                    # Also remove anything after semicolon
                    if ';' in clean_path:
                        clean_path = clean_path[:clean_path.index(';')]
                    clean_path = clean_path.strip()
                    if len(clean_path) > 5 and clean_path.count('\\') >= 1:
                        if len(best_path) == 0 or len(clean_path) < len(best_path):
                            best_path = clean_path
        
        if best_path:
            return best_path
        
        # Fallback to ASCII
        for back in range(0, 500, 1):
            test_offset = offset - back
            if test_offset < 0:
                break
            
            path = self.parser.read_string(test_offset, 500)
            if ':\\' in path and len(path) > 5:
                drive_idx = path.find(':\\')
                if drive_idx > 0:
                    path = path[drive_idx-1:]
                    # Keep only ASCII printable
                    path = ''.join(c for c in path if 32 <= ord(c) <= 126)
                    # Remove registry signatures
                    import re
                    path = re.sub(r'(vk|nk|lh|sk)(?![a-z]).*$', '', path, flags=re.IGNORECASE)
                    if ';' in path:
                        path = path[:path.index(';')]
                    return path.strip()
        
        return ""
    
    def _extract_shimcache_timestamp(self, offset: int) -> str:
        """ShimCache 타임스탬프 추출 (FILETIME, 8-byte QWORD)"""
        # Search within 200 bytes range
        for i in range(offset - 100, offset + 100, 8):
            if i < 0 or i + 8 > self.parser.size:
                continue
            
            filetime = self.parser.read_qword(i)
            dt = self.parser.filetime_to_datetime(filetime)
            
            # Filter valid timestamps (1995-2030 for ShimCache)
            if dt and 1995 < dt.year < 2030:
                return dt.strftime('%Y-%m-%d %H:%M:%S')
        
        return None
    
    def _extract_shimcache_filesize(self, offset: int) -> int:
        """ShimCache 파일 크기 추출 (DWORD, 4-byte)"""
        try:
            # Search within 100 bytes range
            for i in range(offset - 50, offset + 50, 4):
                if i < 0:
                    continue
                
                size = self.parser.read_dword(i)
                
                # Filter valid file sizes (100 bytes ~ 500MB)
                if 100 < size < 524288000:  # 500MB limit
                    return size
        except:
            pass
        
        return None
    
    def _deduplicate_shimcache_entries(self, entries: List[Dict]) -> List[Dict]:
        """ShimCache 엔트리 중복 제거 (타임스탬프 우선순위)"""
        seen = {}
        
        for entry in entries:
            path_key = entry.get('path', '').lower()
            
            if path_key not in seen:
                seen[path_key] = entry
            else:
                # Prefer entry with timestamp
                if entry.get('timestamp') and not seen[path_key].get('timestamp'):
                    seen[path_key] = entry
                # Prefer entry with file size
                elif entry.get('fileSize') and not seen[path_key].get('fileSize'):
                    seen[path_key] = entry
        
        # Sort by path
        return sorted(seen.values(), key=lambda x: x.get('path', ''))
    
    def _extract_sha1_hash(self, offset: int) -> str:
        """SHA1 해시 추출 (20바이트 = 40자 hex)"""
        try:
            for i in range(offset - 100, offset + 100):
                if i < 0 or i + 20 > self.parser.size:
                    continue
                
                hash_bytes = self.parser.data[i:i+20]
                hex_str = hash_bytes.hex().upper()
                
                # 유효한 SHA1 (모두 0이 아님)
                if len(hex_str) == 40 and hex_str != '0' * 40:
                    # 최소한의 엔트로피 확인
                    if len(set(hex_str)) > 4:  # 4가지 이상의 다른 문자
                        return hex_str
        except:
            pass
        
        return None
    
    def _extract_file_size(self, offset: int) -> int:
        """파일 크기 추출 (DWORD, 4바이트)"""
        try:
            for i in range(offset - 50, offset + 50, 4):
                if i < 0:
                    continue
                
                size = self.parser.read_dword(i)
                
                # 합리적인 파일 크기 (0 ~ 2GB)
                if 0 < size < 2147483648:
                    return size
        except:
            pass
        
        return None
    
    def _extract_publisher(self, offset: int) -> str:
        """게시자/회사명 추출"""
        try:
            patterns = ['Publisher', 'Company', 'Vendor', 'Manufacturer']
            
            for pattern in patterns:
                for i in range(offset - 500, offset + 500):
                    if i < 0:
                        continue
                    
                    text = self.parser.read_unicode_string(i, 200)
                    if pattern in text:
                        # 패턴 다음의 문자열 추출
                        after_pattern = text[text.index(pattern) + len(pattern):]
                        # 출력 가능한 ASCII만 남기기
                        cleaned = ''.join(c for c in after_pattern if 32 <= ord(c) <= 126)
                        cleaned = cleaned.strip()
                        if 0 < len(cleaned) < 100:
                            return cleaned
        except:
            pass
        
        return None
    
    def _extract_version(self, offset: int) -> str:
        """버전 정보 추출"""
        try:
            for i in range(offset - 200, offset + 200):
                if i < 0:
                    continue
                
                text = self.parser.read_unicode_string(i, 50)
                # 버전 패턴 매칭 (예: 1.0.0, 10.0.19041.1)
                version_match = re.search(r'\d+\.\d+(\.\d+)?(\.\d+)?', text)
                if version_match:
                    return version_match.group(0)
        except:
            pass
        
        return None
    
    def _deduplicate_amcache_entries(self, entries: List[Dict]) -> List[Dict]:
        """Amcache 엔트리 중복 제거 (더 많은 정보를 가진 것 우선)"""
        seen = {}
        
        for entry in entries:
            key = (entry.get('filePath') or entry.get('programName', '')).lower()
            
            if key not in seen:
                seen[key] = entry
            else:
                # 정보 점수 계산
                old_score = sum([
                    1 if seen[key].get('sha1') else 0,
                    1 if seen[key].get('publisher') else 0,
                    1 if seen[key].get('version') else 0,
                    1 if seen[key].get('fileSize') else 0
                ])
                new_score = sum([
                    1 if entry.get('sha1') else 0,
                    1 if entry.get('publisher') else 0,
                    1 if entry.get('version') else 0,
                    1 if entry.get('fileSize') else 0
                ])
                
                # 더 많은 정보를 가진 엔트리로 교체
                if new_score > old_score:
                    seen[key] = entry
        
        return sorted(seen.values(), key=lambda x: x.get('programName', ''))
    
    def _find_username_near_sid(self, offset: int) -> str:
        """SID 주변에서 사용자명 찾기"""
        # 앞뒤로 검색
        for i in range(offset - 200, offset + 200, 2):
            if i < 0:
                continue
            
            name = self.parser.read_unicode_string(i, 100)
            
            # 유효한 사용자명 패턴
            if name and 3 <= len(name) <= 20:
                if re.match(r'^[a-zA-Z0-9_\-\.]+$', name):
                    return name
        
        return None
    
    def _rot13_decode(self, text: str) -> str:
        """ROT13 디코딩"""
        result = ""
        for char in text:
            if 'a' <= char <= 'z':
                result += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
            elif 'A' <= char <= 'Z':
                result += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
            else:
                result += char
        return result
    
    def _extract_userassist_runcount(self, offset: int) -> int:
        """UserAssist Run Count 추출 (DWORD, 4-byte)"""
        try:
            # Search within 100 bytes range
            for i in range(offset - 50, offset + 50, 4):
                if i < 0:
                    continue
                
                count = self.parser.read_dword(i)
                
                # Filter valid run counts (1 ~ 10000)
                if 1 <= count <= 10000:
                    return count
        except:
            pass
        
        return None
    
    def _extract_userassist_focustime(self, offset: int) -> int:
        """UserAssist Focus Time 추출 (milliseconds)"""
        try:
            # Search within 100 bytes range
            for i in range(offset - 50, offset + 50, 4):
                if i < 0:
                    continue
                
                focus_ms = self.parser.read_dword(i)
                
                # Filter valid focus time (1ms ~ 24 hours in milliseconds)
                if 1 <= focus_ms <= 86400000:  # 24 hours = 86400000 ms
                    return focus_ms
        except:
            pass
        
        return None
    
    def _extract_userassist_timestamp(self, offset: int) -> str:
        """UserAssist Last Executed Timestamp 추출 (FILETIME)"""
        try:
            # Search within 200 bytes range for FILETIME (8-byte)
            for i in range(offset - 100, offset + 100, 8):
                if i < 0:
                    continue
                
                timestamp = self.parser.read_qword(i)
                
                # Valid FILETIME range (1601-01-01 ~ 2100-12-31)
                if 116444736000000000 <= timestamp <= 211845350400000000:
                    try:
                        # Convert FILETIME to datetime
                        dt = datetime(1601, 1, 1) + timedelta(microseconds=timestamp // 10)
                        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
                    except:
                        pass
        except:
            pass
        
        return None
    
    def _deduplicate_userassist_entries(self, entries: List[Dict]) -> List[Dict]:
        """UserAssist 엔트리 중복 제거 (run count 우선순위)"""
        seen = {}
        
        for entry in entries:
            prog_key = entry.get('program', '').lower()
            
            if prog_key not in seen:
                seen[prog_key] = entry
            else:
                # Prefer entry with higher run count
                old_count = seen[prog_key].get('runCount') or 0
                new_count = entry.get('runCount') or 0
                
                if new_count > old_count:
                    seen[prog_key] = entry
                # Prefer entry with focus time
                elif entry.get('focusTime') and not seen[prog_key].get('focusTime'):
                    seen[prog_key] = entry
        
        # Sort by program name
        return sorted(seen.values(), key=lambda x: x.get('program', ''))
    
    def _convert_device_path_to_drive(self, device_path: str) -> str:
        """Device path를 드라이브 문자로 변환 (e.g., \\Device\\HarddiskVolume2 -> C:\\)"""
        import re
        
        # Match \\Device\\HarddiskVolumeN pattern
        volume_match = re.search(r'\\Device\\HarddiskVolume(\d+)', device_path)
        
        if volume_match:
            volume_number = int(volume_match.group(1))
            # Simple mapping: Volume1=C:, Volume2=D:, etc.
            # Note: This is a simplified mapping, actual mapping requires registry lookup
            drive_letter = chr(67 + volume_number - 1)  # 67 = ASCII 'C'
            
            # Replace device path with drive letter
            converted = device_path.replace(volume_match.group(0), f"{drive_letter}:")
            return converted
        
        return device_path
    
    def _extract_user_sid(self, offset: int) -> str:
        """사용자 SID 추출 (S-1-5-21-... 패턴)"""
        try:
            # Search within 200 bytes range
            for i in range(offset - 100, offset + 100):
                if i < 0:
                    continue
                
                # Try ASCII string
                text = self.parser.read_string(i, 100)
                
                # Match SID pattern: S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX-XXXX
                import re
                sid_match = re.search(r'S-1-5-21-\d+-\d+-\d+-\d+', text)
                
                if sid_match:
                    return sid_match.group(0)
        except:
            pass
        
        return None
    
    def _deduplicate_bamdam_entries(self, entries: List[Dict]) -> List[Dict]:
        """BAM/DAM 엔트리 중복 제거 (타임스탬프 우선순위)"""
        seen = {}
        
        for entry in entries:
            path_key = entry.get('path', '').lower()
            
            if path_key not in seen:
                seen[path_key] = entry
            else:
                # Prefer entry with newer timestamp
                old_ts = seen[path_key].get('timestamp') or ''
                new_ts = entry.get('timestamp') or ''
                
                if new_ts > old_ts:
                    seen[path_key] = entry
                # Prefer entry with SID
                elif entry.get('userSID') and not seen[path_key].get('userSID'):
                    seen[path_key] = entry
        
        # Sort by timestamp (descending), handle None values
        return sorted(seen.values(), key=lambda x: x.get('timestamp') or '', reverse=True)
    
    def _is_valid_path(self, path: str) -> bool:
        """유효한 경로인지 확인"""
        return ':\\' in path or '\\' in path and len(path) > 5
    
    def _is_valid_executable_path(self, path: str) -> bool:
        """유효한 실행 파일 경로인지 확인"""
        if not path or len(path) < 5:
            return False
        return any(ext in path.lower() for ext in ['.exe', '.dll', '.bat', '.cmd', '.com'])
    
    # Deduplication methods
    def _deduplicate_by_path(self, items: List[Dict]) -> List[Dict]:
        seen = set()
        result = []
        for item in items:
            key = item.get('path', '').lower()
            if key and key not in seen:
                seen.add(key)
                result.append(item)
        return result
    
    def _deduplicate_by_program(self, items: List[Dict]) -> List[Dict]:
        seen = set()
        result = []
        for item in items:
            key = item.get('program', '').lower()
            if key and key not in seen:
                seen.add(key)
                result.append(item)
        return result
    
    def _deduplicate_by_command(self, items: List[Dict]) -> List[Dict]:
        seen = set()
        result = []
        for item in items:
            key = item.get('command', '').lower()
            if key and key not in seen:
                seen.add(key)
                result.append(item)
        return result
    
    def _deduplicate_by_username(self, items: List[Dict]) -> List[Dict]:
        seen = set()
        result = []
        for item in items:
            key = item.get('username', '').lower()
            if key and key not in seen:
                seen.add(key)
                result.append(item)
        return result
    
    def analyze_shellbags(self) -> List[Dict]:
        """ShellBags 분석 (탐색기 폴더 접근 이력)"""
        results = []
        
        # NTUSER.DAT 또는 UsrClass.dat에만 적용
        if 'NTUSER' not in self.hive_type.upper() and 'USRCLASS' not in self.hive_type.upper():
            return []
        
        # BagMRU 패턴 검색
        bagmru_offsets = self.parser.search_pattern('BagMRU')
        
        for offset in bagmru_offsets[:50]:
            context = self._get_context_strings(offset, 300)
            
            for ctx in context:
                if '\\' in ctx and len(ctx) > 10:
                    # 폴더 경로인지 확인 (파일 확장자 없음)
                    if not any(ext in ctx.lower() for ext in ['.exe', '.dll', '.txt', '.doc', '.pdf']):
                        timestamp = self._extract_filetime_near_offset(offset)
                        
                        results.append({
                            'path': ctx,
                            'type': 'folder',
                            'timestamp': timestamp,
                            'source': 'BagMRU',
                            'offset': offset
                        })
        
        # 일반 폴더 경로 패턴
        folder_patterns = ['\\Desktop', '\\Documents', '\\Downloads', '\\Pictures', '\\Videos']
        
        for pattern in folder_patterns:
            offsets = self.parser.search_pattern(pattern)[:20]
            
            for offset in offsets:
                path = self._extract_path_at_offset(offset)
                if path and len(path) > 10:
                    timestamp = self._extract_filetime_near_offset(offset)
                    
                    results.append({
                        'path': path,
                        'type': pattern.replace('\\', ''),
                        'timestamp': timestamp,
                        'source': 'Pattern'
                    })
        
        return self._deduplicate_by_path(results)[:100]
    
    def analyze_prefetch(self) -> List[Dict]:
        """Prefetch 분석 (프로그램 실행 최적화 정보)"""
        results = []
        
        # SYSTEM 하이브에 Prefetch 정보 저장
        if 'SYSTEM' not in self.hive_type.upper():
            return []
        
        # Prefetch 패턴 검색
        prefetch_patterns = ['.pf', 'Prefetch', 'SCCA']
        
        for pattern in prefetch_patterns:
            offsets = self.parser.search_pattern(pattern)
            
            for offset in offsets[:50]:
                # 실행 파일명 추출
                context = self._get_context_strings(offset, 200)
                
                for ctx in context:
                    if '.exe' in ctx.lower() or '.pf' in ctx.lower():
                        # 실행 횟수 추출 (DWORD)
                        run_count = None
                        for i in range(offset - 20, offset + 20, 4):
                            if i < 0:
                                continue
                            count = self.parser.read_dword(i)
                            if count and 1 <= count <= 10000:
                                run_count = count
                                break
                        
                        # 마지막 실행 시간
                        timestamp = self._extract_filetime_near_offset(offset)
                        
                        results.append({
                            'program': ctx,
                            'runCount': run_count,
                            'timestamp': timestamp,
                            'type': 'Prefetch',
                            'offset': offset
                        })
        
        return self._deduplicate_by_program(results)[:100]
    
    def analyze_lnk_files(self) -> List[Dict]:
        """LNK 파일 분석 (바로가기 파일 이력)"""
        results = []
        
        # NTUSER.DAT에서 최근 사용한 LNK 파일 검색
        if 'NTUSER' not in self.hive_type.upper():
            return []
        
        # .lnk 패턴 검색
        lnk_offsets = self.parser.search_pattern('.lnk')
        
        for offset in lnk_offsets[:100]:
            # LNK 파일 경로 추출
            lnk_path = self._extract_path_at_offset(offset)
            
            if lnk_path and '.lnk' in lnk_path.lower():
                # 타겟 경로 추출 (LNK가 가리키는 실제 파일)
                target_path = None
                context = self._get_context_strings(offset, 300)
                for ctx in context:
                    if ':\\' in ctx and ctx != lnk_path:
                        target_path = ctx
                        break
                
                # 타임스탬프 추출
                timestamp = self._extract_filetime_near_offset(offset)
                
                results.append({
                    'lnkPath': lnk_path,
                    'targetPath': target_path,
                    'timestamp': timestamp,
                    'type': 'LNK',
                    'offset': offset
                })
        
        return self._deduplicate_by_path(results)[:100]
    
    def analyze_security_detailed(self) -> List[Dict]:
        """SECURITY 하이브 상세 분석 (보안 정책, 권한, 감사)"""
        results = []
        
        # SECURITY 하이브에만 적용
        if 'SECURITY' not in self.hive_type.upper():
            return []
        
        # 보안 정책 키 검색
        security_keys = [
            'Policy\\Accounts',  # 계정 정책
            'Policy\\Audit',     # 감사 정책
            'Policy\\PolAdtEv',  # 감사 이벤트
            'Policy\\Secrets',   # LSA Secrets
            'SAM\\Domains',      # 도메인 정보
        ]
        
        for key in security_keys:
            offsets = self.parser.search_pattern(key)
            
            for offset in offsets[:30]:
                # 정책 값 추출
                context = self._get_context_strings(offset, 200)
                
                for ctx in context:
                    if len(ctx) > 5:
                        # DWORD 값 추출 (정책 설정 값)
                        policy_value = None
                        for i in range(offset - 20, offset + 20, 4):
                            if i < 0:
                                continue
                            val = self.parser.read_dword(i)
                            if val is not None:
                                policy_value = val
                                break
                        
                        results.append({
                            'policyKey': key,
                            'policyName': ctx,
                            'value': policy_value,
                            'type': 'SecurityPolicy',
                            'offset': offset
                        })
        
        # SID (보안 식별자) 패턴 검색
        sid_offsets = self.parser.search_pattern('S-1-5-')
        
        for offset in sid_offsets[:50]:
            sid = self.parser.read_ascii_string(offset, 100)
            if sid and sid.startswith('S-1-5-'):
                # SID 타입 확인
                sid_type = self._determine_sid_type(sid)
                
                results.append({
                    'sid': sid,
                    'sidType': sid_type,
                    'type': 'SID',
                    'offset': offset
                })
        
        return results[:100]
    
    def _determine_sid_type(self, sid: str) -> str:
        """SID 타입 결정"""
        if 'S-1-5-18' in sid:
            return 'SYSTEM (LocalSystem)'
        elif 'S-1-5-19' in sid:
            return 'LOCAL SERVICE'
        elif 'S-1-5-20' in sid:
            return 'NETWORK SERVICE'
        elif 'S-1-5-21' in sid:
            return 'Domain User/Group'
        elif 'S-1-5-32' in sid:
            return 'Built-in Group'
        else:
            return 'Unknown'
    
    def analyze_muicache(self) -> List[Dict]:
        """MuiCache 분석 (응용 프로그램 UI 캐시) - v3.0"""
        results = []
        
        # MuiCache는 NTUSER.DAT 또는 UsrClass.dat에 존재
        if 'NTUSER' not in self.hive_type.upper() and 'USRCLASS' not in self.hive_type.upper():
            return []
        
        # MuiCache 키 패턴 검색
        muicache_patterns = ['MuiCache', 'ApplicationCompany', 'FriendlyAppName']
        
        for pattern in muicache_patterns:
            offsets = self.parser.search_pattern(pattern)
            
            for offset in offsets[:100]:
                # 주변에서 실행 파일 경로 추출
                context = self._get_context_strings(offset, 300)
                
                for ctx in context:
                    # .exe 파일 경로 확인
                    if '.exe' in ctx.lower() and ':\\' in ctx:
                        # 응용 프로그램 이름 추출
                        app_name = None
                        for app_ctx in context:
                            if app_ctx != ctx and len(app_ctx) > 3 and '.exe' not in app_ctx:
                                app_name = app_ctx
                                break
                        
                        # 타임스탬프 추출
                        timestamp = self._extract_filetime_near_offset(offset)
                        
                        results.append({
                            'path': ctx,
                            'appName': app_name,
                            'timestamp': timestamp,
                            'source': 'MuiCache',
                            'type': 'MuiCache',
                            'offset': offset
                        })
        
        return self._deduplicate_by_path(results)[:100]
    
    def analyze_installed_software_detailed(self) -> List[Dict]:
        """설치된 소프트웨어 상세 분석 - v3.0"""
        results = []
        
        # SOFTWARE 하이브에서만 작동
        if 'SOFTWARE' not in self.hive_type.upper():
            return []
        
        # Uninstall 키 패턴 검색
        uninstall_patterns = [
            'Microsoft\\Windows\\CurrentVersion\\Uninstall',
            'Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
        ]
        
        for pattern in uninstall_patterns:
            offsets = self.parser.search_pattern(pattern)
            
            for offset in offsets[:200]:
                # 프로그램 정보 추출
                context = self._get_context_strings(offset, 500)
                
                # DisplayName, Publisher, Version, InstallDate 추출
                display_name = None
                publisher = None
                version = None
                install_date = None
                install_location = None
                uninstall_string = None
                
                for i, ctx in enumerate(context):
                    if 'DisplayName' in ctx and i + 1 < len(context):
                        display_name = context[i + 1]
                    elif 'Publisher' in ctx and i + 1 < len(context):
                        publisher = context[i + 1]
                    elif 'DisplayVersion' in ctx and i + 1 < len(context):
                        version = context[i + 1]
                    elif 'InstallDate' in ctx and i + 1 < len(context):
                        install_date = context[i + 1]
                    elif 'InstallLocation' in ctx and i + 1 < len(context):
                        install_location = context[i + 1]
                    elif 'UninstallString' in ctx and i + 1 < len(context):
                        uninstall_string = context[i + 1]
                
                # 최소한 DisplayName이 있어야 유효한 항목
                if display_name and len(display_name) > 2:
                    # 설치 크기 추출 (DWORD)
                    install_size = None
                    for i in range(offset - 50, offset + 50, 4):
                        if i < 0:
                            continue
                        size = self.parser.read_dword(i)
                        if size and size < 10000000000:  # 10GB 이하
                            install_size = size
                            break
                    
                    results.append({
                        'displayName': display_name,
                        'publisher': publisher,
                        'version': version,
                        'installDate': install_date,
                        'installLocation': install_location,
                        'uninstallString': uninstall_string,
                        'estimatedSize': install_size,
                        'type': 'InstalledSoftware',
                        'offset': offset
                    })
        
        # 중복 제거 (DisplayName 기준)
        seen = set()
        unique_results = []
        for item in results:
            name = item.get('displayName', '')
            if name and name not in seen:
                seen.add(name)
                unique_results.append(item)
        
        return unique_results[:150]
    
    def analyze_typed_paths(self) -> List[Dict]:
        """TypedPaths 분석 (탐색기 주소창 입력 이력) - v3.1"""
        results = []
        
        # NTUSER.DAT에만 적용
        if 'NTUSER' not in self.hive_type.upper():
            return []
        
        # TypedPaths 패턴 검색
        typed_patterns = ['TypedPaths', 'url']
        
        for pattern in typed_patterns:
            offsets = self.parser.search_pattern(pattern)
            
            for offset in offsets[:100]:
                context = self._get_context_strings(offset, 200)
                
                for ctx in context:
                    # 경로나 URL 형식인지 확인
                    if (':\\' in ctx or '\\\\' in ctx or 'http' in ctx.lower()) and len(ctx) > 5:
                        # MRU 순서 추출
                        mru_order = None
                        for i in range(offset - 20, offset + 20, 4):
                            if i < 0:
                                continue
                            order = self.parser.read_dword(i)
                            if order and order < 100:
                                mru_order = order
                                break
                        
                        results.append({
                            'path': ctx,
                            'mruOrder': mru_order,
                            'type': 'TypedPath',
                            'offset': offset
                        })
        
        return self._deduplicate_by_path(results)[:50]
    
    def analyze_recent_apps(self) -> List[Dict]:
        """RecentApps 분석 (Windows 10+ 최근 앱) - v3.1"""
        results = []
        
        # NTUSER.DAT에만 적용
        if 'NTUSER' not in self.hive_type.upper():
            return []
        
        # RecentApps 패턴 검색
        recentapps_patterns = ['RecentApps', 'AppId', 'AppPath']
        
        for pattern in recentapps_patterns:
            offsets = self.parser.search_pattern(pattern)
            
            for offset in offsets[:100]:
                context = self._get_context_strings(offset, 300)
                
                for ctx in context:
                    if '.exe' in ctx.lower() and ':\\' in ctx:
                        # 실행 횟수 추출
                        launch_count = None
                        for i in range(offset - 30, offset + 30, 4):
                            if i < 0:
                                continue
                            count = self.parser.read_dword(i)
                            if count and count > 0 and count < 10000:
                                launch_count = count
                                break
                        
                        # 마지막 실행 시간
                        last_access = self._extract_filetime_near_offset(offset)
                        
                        results.append({
                            'appPath': ctx,
                            'launchCount': launch_count,
                            'lastAccess': last_access,
                            'type': 'RecentApp',
                            'offset': offset
                        })
        
        return self._deduplicate_by_path(results)[:100]
    
    def analyze_services_detailed(self) -> List[Dict]:
        """Services 상세 분석 (시스템 서비스) - v3.1"""
        results = []
        
        # SYSTEM 하이브에만 적용
        if 'SYSTEM' not in self.hive_type.upper():
            return []
        
        # Services 패턴 검색
        service_patterns = ['Services\\', 'ImagePath', 'DisplayName']
        
        for pattern in service_patterns:
            offsets = self.parser.search_pattern(pattern)
            
            for offset in offsets[:150]:
                context = self._get_context_strings(offset, 400)
                
                service_name = None
                image_path = None
                display_name = None
                start_type = None
                
                for i, ctx in enumerate(context):
                    if '.exe' in ctx.lower() or '.dll' in ctx.lower() or '.sys' in ctx.lower():
                        image_path = ctx
                    elif len(ctx) > 3 and ctx.replace(' ', '').isalnum() and not '.exe' in ctx:
                        if not display_name:
                            display_name = ctx
                        elif not service_name:
                            service_name = ctx
                
                # Start Type 추출 (DWORD: 2=auto, 3=manual, 4=disabled)
                for i in range(offset - 50, offset + 50, 4):
                    if i < 0:
                        continue
                    st = self.parser.read_dword(i)
                    if st in [0, 1, 2, 3, 4]:
                        start_type = {0: 'Boot', 1: 'System', 2: 'Auto', 3: 'Manual', 4: 'Disabled'}.get(st)
                        break
                
                if image_path or display_name:
                    results.append({
                        'serviceName': service_name,
                        'displayName': display_name,
                        'imagePath': image_path,
                        'startType': start_type,
                        'type': 'Service',
                        'offset': offset
                    })
        
        # 중복 제거
        seen = set()
        unique_results = []
        for item in results:
            key = (item.get('imagePath'), item.get('displayName'))
            if key not in seen and any(key):
                seen.add(key)
                unique_results.append(item)
        
        return unique_results[:100]
    
    def analyze_wlan_profiles(self) -> List[Dict]:
        """WLAN Profiles 분석 (Wi-Fi 프로필) - v3.1"""
        results = []
        
        # SOFTWARE 하이브에만 적용
        if 'SOFTWARE' not in self.hive_type.upper():
            return []
        
        # WLAN 패턴 검색
        wlan_patterns = ['ProfileName', 'Profiles\\', 'SSID']
        
        for pattern in wlan_patterns:
            offsets = self.parser.search_pattern(pattern)
            
            for offset in offsets[:100]:
                context = self._get_context_strings(offset, 200)
                
                for ctx in context:
                    # SSID나 프로필 이름으로 보이는 문자열
                    if len(ctx) > 2 and len(ctx) < 64 and not '\\' in ctx:
                        # 연결 타입 추출
                        conn_type = None
                        for i in range(offset - 30, offset + 30, 4):
                            if i < 0:
                                continue
                            ct = self.parser.read_dword(i)
                            if ct in [1, 2]:
                                conn_type = 'Infrastructure' if ct == 1 else 'AdHoc'
                                break
                        
                        # 마지막 연결 시간
                        last_connected = self._extract_filetime_near_offset(offset)
                        
                        results.append({
                            'profileName': ctx,
                            'connectionType': conn_type,
                            'lastConnected': last_connected,
                            'type': 'WLAN',
                            'offset': offset
                        })
        
        # 중복 제거
        seen = set()
        unique_results = []
        for item in results:
            name = item.get('profileName', '')
            if name and name not in seen:
                seen.add(name)
                unique_results.append(item)
        
        return unique_results[:50]
    
    def analyze_timezone(self) -> List[Dict]:
        """Time Zone 분석 (시간대 정보) - v3.1"""
        results = []
        
        # SYSTEM 하이브에만 적용
        if 'SYSTEM' not in self.hive_type.upper():
            return []
        
        # TimeZone 패턴 검색
        tz_patterns = ['TimeZoneInformation', 'StandardName', 'DaylightName']
        
        for pattern in tz_patterns:
            offsets = self.parser.search_pattern(pattern)
            
            for offset in offsets[:30]:
                context = self._get_context_strings(offset, 200)
                
                standard_name = None
                daylight_name = None
                bias = None
                
                for ctx in context:
                    if 'Standard' in ctx and len(ctx) > 10:
                        standard_name = ctx
                    elif 'Daylight' in ctx and len(ctx) > 10:
                        daylight_name = ctx
                
                # Bias 값 추출 (분 단위)
                for i in range(offset - 20, offset + 20, 4):
                    if i < 0:
                        continue
                    b = self.parser.read_dword(i)
                    if b and b < 1000:  # 합리적인 범위
                        bias = b
                        break
                
                if standard_name or daylight_name:
                    results.append({
                        'standardName': standard_name,
                        'daylightName': daylight_name,
                        'bias': bias,
                        'type': 'TimeZone',
                        'offset': offset
                    })
        
        return results[:10]
    
    def _extract_filetime_near_offset(self, offset: int, search_range: int = 100) -> str:
        """오프셋 근처에서 FILETIME 추출"""
        for i in range(offset - search_range, offset + search_range, 8):
            if i < 0:
                continue
            
            timestamp_val = self.parser.read_qword(i)
            if timestamp_val:
                timestamp_str = self.parser.filetime_to_datetime(timestamp_val)
                if timestamp_str:
                    return timestamp_str
        
        return None

