#!/usr/bin/env python3
"""
Registry Parser - 레지스트리 바이너리 파서
"""

import os
import struct
import re
from datetime import datetime
from typing import List


class RegistryParser:
    """레지스트리 바이너리 파서"""
    
    def __init__(self, data: bytes, file_path: str = None):
        self.data = data
        self.size = len(data)
        self.file_path = file_path
    
    def validate_hive(self) -> bool:
        """레지스트리 하이브 검증"""
        if len(self.data) < 4:
            return False
        signature = self.data[0:4].decode('ascii', errors='ignore')
        return signature == 'regf'
    
    def detect_hive_type(self) -> str:
        """하이브 타입 자동 감지 (1차: 파일명, 2차: 바이너리 패턴)"""
        try:
            # 1차: 파일명 기반 감지 (가장 정확하고 빠름)
            if self.file_path:
                filename = os.path.basename(self.file_path).upper()
                
                # 표준 레지스트리 파일명 매칭
                if 'NTUSER.DAT' in filename or filename == 'NTUSER':
                    return 'NTUSER.DAT'
                elif 'USRCLASS.DAT' in filename or 'USRCLASS' in filename:
                    return 'UsrClass.dat'
                elif filename == 'SYSTEM':
                    return 'SYSTEM'
                elif filename == 'SOFTWARE':
                    return 'SOFTWARE'
                elif filename == 'SAM':
                    return 'SAM'
                elif filename == 'SECURITY':
                    return 'SECURITY'
                elif 'AMCACHE.HVE' in filename or 'AMCACHE' in filename:
                    return 'Amcache.hve'
            
            # 2차: 바이너리 패턴 기반 감지 (파일명으로 판별 실패 시)
            search_size = min(len(self.data), 2 * 1024 * 1024)  # 2MB까지 검색
            data_chunk = self.data[:search_size]
            
            # UTF-16 LE 패턴 (레지스트리는 주로 UTF-16 사용)
            patterns_utf16 = {
                'SAM': ['SAM'.encode('utf-16-le'), 'Users'.encode('utf-16-le')],
                'SYSTEM': ['ControlSet'.encode('utf-16-le'), 'Services'.encode('utf-16-le')],
                'SOFTWARE': ['SOFTWARE'.encode('utf-16-le'), 'Classes'.encode('utf-16-le')],
                'SECURITY': ['SECURITY'.encode('utf-16-le'), 'Policy'.encode('utf-16-le')],
                'Amcache.hve': ['Amcache'.encode('utf-16-le'), 'InventoryApplicationFile'.encode('utf-16-le')],
                'UsrClass.dat': ['Local Settings'.encode('utf-16-le'), 'Shell'.encode('utf-16-le')],
                'NTUSER.DAT': ['Software'.encode('utf-16-le'), 'Explorer'.encode('utf-16-le'), 'Desktop'.encode('utf-16-le')],
            }
            
            # 각 하이브 타입별 점수 계산
            scores = {}
            for hive_type, patterns in patterns_utf16.items():
                score = sum(1 for pattern in patterns if pattern in data_chunk)
                if score > 0:
                    scores[hive_type] = score
            
            # 가장 높은 점수의 하이브 타입 반환
            if scores:
                # SYSTEM vs SOFTWARE 구분 개선 (최우선)
                if 'SYSTEM' in scores and 'SOFTWARE' in scores:
                    # SYSTEM 특징: CurrentControlSet (시스템 구성)
                    if 'CurrentControlSet'.encode('utf-16-le') in data_chunk or \
                       'ControlSet001'.encode('utf-16-le') in data_chunk:
                        return 'SYSTEM'
                    # SOFTWARE 특징: Uninstall (프로그램 제거 정보)
                    elif 'Uninstall'.encode('utf-16-le') in data_chunk:
                        return 'SOFTWARE'
                
                # SOFTWARE vs NTUSER.DAT 구분
                if 'SOFTWARE' in scores and 'NTUSER.DAT' in scores:
                    # SOFTWARE 특징: Uninstall (프로그램 제거 정보)
                    if 'Uninstall'.encode('utf-16-le') in data_chunk:
                        return 'SOFTWARE'
                    # NTUSER.DAT 특징: Control Panel, Keyboard Layout
                    elif 'Control Panel'.encode('utf-16-le') in data_chunk and \
                         'Keyboard'.encode('utf-16-le') in data_chunk:
                        return 'NTUSER.DAT'
                    # Classes가 있으면 SOFTWARE
                    elif 'Classes'.encode('utf-16-le') in data_chunk:
                        return 'SOFTWARE'
                    else:
                        return 'NTUSER.DAT'
                
                # 가장 높은 점수 반환
                return max(scores, key=scores.get)
            
            # ASCII 패턴 fallback (일부 하이브는 ASCII 사용)
            if b'ControlSet' in data_chunk:
                return 'SYSTEM'
            elif b'AppCompatCache' in data_chunk or b'ShimCache' in data_chunk:
                return 'SOFTWARE'
            elif b'SAM' in data_chunk and b'Domains' in data_chunk:
                return 'SAM'
            
            return 'UNKNOWN'
        except:
            return 'UNKNOWN'
    
    def read_dword(self, offset: int) -> int:
        """DWORD 읽기 (Little Endian)"""
        if offset + 4 > self.size:
            return 0
        return struct.unpack('<I', self.data[offset:offset+4])[0]
    
    def read_qword(self, offset: int) -> int:
        """QWORD 읽기 (Little Endian)"""
        if offset + 8 > self.size:
            return 0
        return struct.unpack('<Q', self.data[offset:offset+8])[0]
    
    def read_string(self, offset: int, length: int) -> str:
        """ASCII 문자열 읽기"""
        if offset + length > self.size:
            return ""
        try:
            data = self.data[offset:offset+length]
            return data.split(b'\x00')[0].decode('ascii', errors='ignore')
        except:
            return ""
    
    def read_unicode_string(self, offset: int, length: int) -> str:
        """UTF-16 LE 문자열 읽기 (강화된 필터링)"""
        if offset + length > self.size:
            return ""
        try:
            data = self.data[offset:offset+length]
            # Decode UTF-16 LE
            decoded = data.decode('utf-16-le', errors='ignore')
            # Stop at first null terminator
            null_pos = decoded.find('\x00')
            if null_pos != -1:
                decoded = decoded[:null_pos]
            
            # Enhanced filtering: Remove control characters and high Unicode planes
            # Keep only printable ASCII + common European chars (< 0x0300)
            decoded = ''.join(c for c in decoded if (
                (c.isprintable() or c in '\n\r\t') and 
                ord(c) < 0x0300  # Filter out combining diacritics and high Unicode
            ))
            
            # Remove any remaining null bytes and control characters
            decoded = re.sub(r'[\x00-\x1f\x7f-\x9f]+', '', decoded)
            
            return decoded.strip()
        except:
            return ""
    
    def filetime_to_datetime(self, filetime: int):
        """Windows FILETIME을 datetime으로 변환"""
        try:
            # FILETIME: 1601-01-01부터의 100나노초 단위
            EPOCH_DIFF = 11644473600  # 1601-01-01과 1970-01-01의 차이 (초)
            timestamp = (filetime / 10000000.0) - EPOCH_DIFF
            return datetime.fromtimestamp(timestamp)
        except:
            return None
    
    def extract_strings(self, min_length: int = 4, max_strings: int = 100) -> List[str]:
        """문자열 추출"""
        strings = []
        current = ""
        max_size = min(self.size, 500 * 1024)  # 최대 500KB만 스캔
        
        # ASCII 문자열
        for i in range(max_size):
            byte = self.data[i]
            if 32 <= byte <= 126:  # 출력 가능한 ASCII
                current += chr(byte)
            else:
                if len(current) >= min_length:
                    strings.append(current)
                    if len(strings) >= max_strings:
                        break
                current = ""
        
        # 중복 제거 및 필터링
        unique_strings = list(set(strings))
        filtered = [s for s in unique_strings if min_length <= len(s) < 100]
        return filtered[:max_strings]
    
    def search_pattern(self, pattern: str) -> List[int]:
        """패턴 검색"""
        offsets = []
        pattern_bytes = pattern.encode('ascii', errors='ignore')
        offset = 0
        
        while offset < self.size:
            pos = self.data.find(pattern_bytes, offset)
            if pos == -1:
                break
            offsets.append(pos)
            offset = pos + 1
        
        return offsets
    
    def read_ascii_string(self, offset: int, length: int) -> str:
        """ASCII 문자열 읽기 (별칭)"""
        return self.read_string(offset, length)
