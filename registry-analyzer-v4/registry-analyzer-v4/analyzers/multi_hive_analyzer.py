"""
Multi-Hive Analyzer for Windows Registry Forensics
다중 레지스트리 하이브 통합 분석 모듈

Author: Registry Forensic Analyzer Team
Version: 4.0
"""

from typing import Dict, List, Optional, Tuple
from datetime import datetime
from core.registry_parser import RegistryParser
from analyzers.forensics_analyzer import ForensicsAnalyzer


class MultiHiveAnalyzer:
    """
    여러 레지스트리 하이브를 동시에 분석하여 상관관계 발견
    
    주요 기능:
    1. Cross-hive correlation detection
    2. Unified timeline generation
    3. User activity pattern analysis
    4. System-wide artifact correlation
    """
    
    def __init__(self):
        """초기화"""
        self.hives: Dict[str, Dict] = {}  # hive_type -> {'parser': ..., 'analyzer': ..., 'findings': ...}
        self.correlations: List[Dict] = []
        self.timeline: List[Dict] = []
    
    def add_hive(self, file_path: str, hive_type: str) -> bool:
        """
        하이브 파일 추가
        
        Args:
            file_path: 레지스트리 파일 경로
            hive_type: SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER, USRCLASS, AMCACHE
        
        Returns:
            성공 여부
        """
        try:
            # 파일 읽기
            with open(file_path, 'rb') as f:
                data = f.read()
            
            parser = RegistryParser(data, file_path)
            analyzer = ForensicsAnalyzer(parser, hive_type)
            
            # 모든 분석 실행
            findings = self._analyze_all(analyzer)
            
            self.hives[hive_type] = {
                'file_path': file_path,
                'parser': parser,
                'analyzer': analyzer,
                'findings': findings
            }
            
            return True
        except Exception as e:
            import traceback
            print(f"Failed to add hive {hive_type}: {e}")
            traceback.print_exc()
            return False
    
    def _analyze_all(self, analyzer: ForensicsAnalyzer) -> Dict:
        """모든 분석 모듈 실행"""
        return {
            'shimcache': analyzer.analyze_shimcache(),
            'amcache': analyzer.analyze_amcache(),
            'userassist': analyzer.analyze_userassist(),
            'bam_dam': analyzer.analyze_bam_dam(),
            'usb_devices': analyzer.analyze_usb_devices(),
            'recent_docs': analyzer.analyze_recent_docs(),
            'run_keys': analyzer.analyze_run_keys(),
            'sam_users': analyzer.analyze_sam_users(),
            'network_profiles': analyzer.analyze_network_profiles(),
            'shellbags': analyzer.analyze_shellbags(),
            'muicache': analyzer.analyze_muicache(),
            'prefetch': analyzer.analyze_prefetch(),
            'lnk_files': analyzer.analyze_lnk_files(),
            'installed_software': analyzer.analyze_installed_software_detailed(),
            'security_detailed': analyzer.analyze_security_detailed(),
            # v3.1 추가
            'typed_paths': analyzer.analyze_typed_paths(),
            'recent_apps': analyzer.analyze_recent_apps(),
            'services_detailed': analyzer.analyze_services_detailed(),
            'wlan_profiles': analyzer.analyze_wlan_profiles(),
            'timezone': analyzer.analyze_timezone()
        }
    
    def find_correlations(self) -> List[Dict]:
        """
        하이브 간 상관관계 발견
        
        Returns:
            상관관계 목록
        """
        self.correlations = []
        
        # 1. ShimCache + Amcache 통합 (프로그램 실행 증거 강화)
        self._correlate_shimcache_amcache()
        
        # 2. UserAssist + Prefetch + BAM/DAM (사용자 활동 패턴)
        self._correlate_user_activity()
        
        # 3. USB Devices + User Files (외부 저장장치 사용 증거)
        self._correlate_usb_usage()
        
        # 4. Network Profiles + WLAN + User Activity (네트워크 활동)
        self._correlate_network_activity()
        
        # 5. Run Keys + Installed Software (자동 실행 프로그램)
        self._correlate_autorun_software()
        
        # 6. Services + Installed Software (시스템 서비스 연관)
        self._correlate_services_software()
        
        # 7. TimeZone + Timeline (시간대 보정)
        self._correlate_timezone_timeline()
        
        return self.correlations
    
    def _correlate_shimcache_amcache(self):
        """ShimCache와 Amcache를 교차 분석하여 프로그램 실행 증거 강화"""
        system_findings = self.hives.get('SYSTEM', {}).get('findings', {})
        software_findings = self.hives.get('SOFTWARE', {}).get('findings', {})
        
        shimcache = system_findings.get('shimcache', [])
        amcache = software_findings.get('amcache', [])
        
        if not shimcache or not amcache:
            return
        
        # ShimCache 경로를 키로 하는 맵 생성
        shimcache_map = {item['path'].lower(): item for item in shimcache}
        
        # Amcache와 매칭
        for am_item in amcache:
            program_name = am_item.get('programName', '').lower()
            
            # ShimCache에서 일치하는 항목 찾기
            for sc_path, sc_item in shimcache_map.items():
                if program_name in sc_path or program_name.replace('.exe', '') in sc_path:
                    correlation = {
                        'type': 'ShimCache-Amcache Match',
                        'confidence': 'HIGH',
                        'program': am_item.get('programName'),
                        'path': sc_item['path'],
                        'shimcache_timestamp': sc_item.get('timestamp'),
                        'amcache_timestamp': am_item.get('timestamp'),
                        'sha1': am_item.get('sha1'),
                        'publisher': am_item.get('publisher'),
                        'version': am_item.get('version'),
                        'significance': 'Program execution confirmed by multiple sources'
                    }
                    self.correlations.append(correlation)
    
    def _correlate_user_activity(self):
        """UserAssist, Prefetch, BAM/DAM을 통합하여 사용자 활동 패턴 분석"""
        ntuser_findings = self.hives.get('NTUSER', {}).get('findings', {})
        system_findings = self.hives.get('SYSTEM', {}).get('findings', {})
        software_findings = self.hives.get('SOFTWARE', {}).get('findings', {})
        
        userassist = ntuser_findings.get('userassist', [])
        prefetch = software_findings.get('prefetch', [])
        bam_dam = system_findings.get('bam_dam', [])
        recent_apps = ntuser_findings.get('recent_apps', [])
        
        # 프로그램별로 그룹화
        program_activity = {}
        
        # UserAssist 데이터 추가
        for item in userassist:
            program = item.get('program', '').lower()
            if program not in program_activity:
                program_activity[program] = {
                    'program': item.get('program'),
                    'sources': [],
                    'timestamps': [],
                    'run_count': 0
                }
            program_activity[program]['sources'].append('UserAssist')
            if item.get('lastExecuted'):
                program_activity[program]['timestamps'].append(item['lastExecuted'])
            if item.get('runCount'):
                program_activity[program]['run_count'] += item['runCount']
        
        # Prefetch 데이터 추가
        for item in prefetch:
            program = item.get('program', '').lower()
            if program not in program_activity:
                program_activity[program] = {
                    'program': item.get('program'),
                    'sources': [],
                    'timestamps': [],
                    'run_count': 0
                }
            program_activity[program]['sources'].append('Prefetch')
            if item.get('timestamp'):
                program_activity[program]['timestamps'].append(item['timestamp'])
            if item.get('runCount'):
                program_activity[program]['run_count'] += item['runCount']
        
        # BAM/DAM 데이터 추가
        for item in bam_dam:
            path = item.get('path', '').lower()
            program = path.split('\\')[-1] if '\\' in path else path
            if program not in program_activity:
                program_activity[program] = {
                    'program': program,
                    'sources': [],
                    'timestamps': [],
                    'run_count': 0
                }
            program_activity[program]['sources'].append('BAM/DAM')
            if item.get('timestamp'):
                program_activity[program]['timestamps'].append(item['timestamp'])
        
        # RecentApps 데이터 추가
        for item in recent_apps:
            app_name = item.get('appName', '').lower()
            if app_name not in program_activity:
                program_activity[app_name] = {
                    'program': item.get('appName'),
                    'sources': [],
                    'timestamps': [],
                    'run_count': 0
                }
            program_activity[app_name]['sources'].append('RecentApps')
            if item.get('lastAccessTime'):
                program_activity[app_name]['timestamps'].append(item['lastAccessTime'])
            if item.get('launchCount'):
                program_activity[app_name]['run_count'] += item['launchCount']
        
        # 2개 이상 소스에서 발견된 프로그램을 상관관계로 추가
        for program, data in program_activity.items():
            if len(data['sources']) >= 2:
                correlation = {
                    'type': 'User Activity Pattern',
                    'confidence': 'HIGH' if len(data['sources']) >= 3 else 'MEDIUM',
                    'program': data['program'],
                    'sources': list(set(data['sources'])),
                    'source_count': len(set(data['sources'])),
                    'timestamps': sorted(data['timestamps'])[:5],  # 최근 5개
                    'total_run_count': data['run_count'],
                    'significance': f'Program activity confirmed by {len(set(data["sources"]))} different sources'
                }
                self.correlations.append(correlation)
    
    def _correlate_usb_usage(self):
        """USB 장치 연결과 사용자 파일 접근 상관관계"""
        system_findings = self.hives.get('SYSTEM', {}).get('findings', {})
        ntuser_findings = self.hives.get('NTUSER', {}).get('findings', {})
        
        usb_devices = system_findings.get('usb_devices', [])
        recent_docs = ntuser_findings.get('recent_docs', [])
        shellbags = ntuser_findings.get('shellbags', [])
        
        if not usb_devices:
            return
        
        # USB 드라이브 레터 추출
        usb_drives = []
        for usb in usb_devices:
            if usb.get('driveLetter'):
                usb_drives.append(usb['driveLetter'].upper())
        
        if not usb_drives:
            return
        
        # Recent Docs에서 USB 경로 찾기
        usb_files = []
        for doc in recent_docs:
            path = doc.get('path', '')
            for drive in usb_drives:
                if path.upper().startswith(drive + ':\\'):
                    usb_files.append({
                        'path': path,
                        'timestamp': doc.get('timestamp'),
                        'drive': drive
                    })
        
        # ShellBags에서 USB 경로 찾기
        for bag in shellbags:
            path = bag.get('path', '')
            for drive in usb_drives:
                if path.upper().startswith(drive + ':\\'):
                    usb_files.append({
                        'path': path,
                        'timestamp': bag.get('timestamp'),
                        'drive': drive
                    })
        
        # 상관관계 추가
        if usb_files:
            correlation = {
                'type': 'USB Device Usage',
                'confidence': 'HIGH',
                'usb_devices': [{'serial': usb.get('serialNumber'), 'drive': usb.get('driveLetter')} 
                               for usb in usb_devices],
                'accessed_files': usb_files[:20],  # 최대 20개
                'total_file_count': len(usb_files),
                'significance': f'Found {len(usb_files)} files accessed from USB devices'
            }
            self.correlations.append(correlation)
    
    def _correlate_network_activity(self):
        """네트워크 프로필과 WLAN, 사용자 활동 연관"""
        software_findings = self.hives.get('SOFTWARE', {}).get('findings', {})
        
        network_profiles = software_findings.get('network_profiles', [])
        wlan_profiles = software_findings.get('wlan_profiles', [])
        
        if network_profiles or wlan_profiles:
            correlation = {
                'type': 'Network Activity',
                'confidence': 'MEDIUM',
                'network_profiles': len(network_profiles),
                'wlan_profiles': len(wlan_profiles),
                'networks': [{'name': p.get('profileName'), 'type': 'Wired'} 
                            for p in network_profiles[:5]],
                'wifi_networks': [{'ssid': w.get('profileName'), 'type': w.get('connectionType')} 
                                 for w in wlan_profiles[:5]],
                'significance': f'User connected to {len(network_profiles) + len(wlan_profiles)} networks'
            }
            self.correlations.append(correlation)
    
    def _correlate_autorun_software(self):
        """자동 실행 프로그램과 설치된 소프트웨어 연관"""
        software_findings = self.hives.get('SOFTWARE', {}).get('findings', {})
        ntuser_findings = self.hives.get('NTUSER', {}).get('findings', {})
        
        run_keys_sw = software_findings.get('run_keys', [])
        run_keys_nu = ntuser_findings.get('run_keys', [])
        installed_software = software_findings.get('installed_software', [])
        
        all_run_keys = run_keys_sw + run_keys_nu
        
        if not all_run_keys or not installed_software:
            return
        
        # 설치된 소프트웨어 맵 생성
        software_map = {sw.get('displayName', '').lower(): sw 
                       for sw in installed_software}
        
        # Run Key와 매칭
        autorun_matched = []
        for run_key in all_run_keys:
            program = run_key.get('program', '').lower()
            path = run_key.get('path', '').lower()
            
            for sw_name, sw_data in software_map.items():
                if sw_name in program or sw_name in path:
                    autorun_matched.append({
                        'autorun_program': run_key.get('program'),
                        'autorun_path': run_key.get('path'),
                        'installed_software': sw_data.get('displayName'),
                        'publisher': sw_data.get('publisher'),
                        'install_date': sw_data.get('installDate')
                    })
        
        if autorun_matched:
            correlation = {
                'type': 'Autorun Software Correlation',
                'confidence': 'HIGH',
                'matched_count': len(autorun_matched),
                'matches': autorun_matched[:10],  # 최대 10개
                'significance': f'Found {len(autorun_matched)} autorun programs with matching installed software'
            }
            self.correlations.append(correlation)
    
    def _correlate_services_software(self):
        """시스템 서비스와 설치된 소프트웨어 연관"""
        system_findings = self.hives.get('SYSTEM', {}).get('findings', {})
        software_findings = self.hives.get('SOFTWARE', {}).get('findings', {})
        
        services = system_findings.get('services_detailed', [])
        installed_software = software_findings.get('installed_software', [])
        
        if not services or not installed_software:
            return
        
        # 소프트웨어별 서비스 매칭
        software_services = []
        
        for service in services:
            image_path = service.get('imagePath', '').lower()
            
            for software in installed_software:
                sw_name = software.get('displayName', '').lower()
                install_loc = software.get('installLocation', '').lower()
                
                if sw_name and sw_name in image_path:
                    software_services.append({
                        'service_name': service.get('serviceName'),
                        'service_type': service.get('startType'),
                        'image_path': service.get('imagePath'),
                        'software': software.get('displayName'),
                        'publisher': software.get('publisher')
                    })
                elif install_loc and install_loc in image_path:
                    software_services.append({
                        'service_name': service.get('serviceName'),
                        'service_type': service.get('startType'),
                        'image_path': service.get('imagePath'),
                        'software': software.get('displayName'),
                        'publisher': software.get('publisher')
                    })
        
        if software_services:
            correlation = {
                'type': 'Services-Software Correlation',
                'confidence': 'MEDIUM',
                'matched_count': len(software_services),
                'matches': software_services[:10],
                'significance': f'Found {len(software_services)} services associated with installed software'
            }
            self.correlations.append(correlation)
    
    def _correlate_timezone_timeline(self):
        """시간대 정보를 타임라인에 적용"""
        system_findings = self.hives.get('SYSTEM', {}).get('findings', {})
        timezone_info = system_findings.get('timezone', [])
        
        if timezone_info and len(timezone_info) > 0:
            tz = timezone_info[0]
            bias = tz.get('bias')
            
            if bias is not None:
                hours_offset = -(bias // 60)
                correlation = {
                    'type': 'Timezone Information',
                    'confidence': 'HIGH',
                    'timezone': tz.get('standardName'),
                    'utc_offset': f'UTC{hours_offset:+d}:00',
                    'bias_minutes': bias,
                    'significance': f'All timestamps should be interpreted in {tz.get("standardName")} timezone'
                }
                self.correlations.append(correlation)
    
    def build_timeline(self) -> List[Dict]:
        """
        모든 하이브의 타임스탬프를 통합하여 타임라인 생성
        
        Returns:
            시간순 정렬된 이벤트 목록
        """
        self.timeline = []
        
        for hive_type, hive_data in self.hives.items():
            findings = hive_data.get('findings', {})
            
            # 각 아티팩트에서 타임스탬프 추출
            for artifact_type, artifacts in findings.items():
                if not artifacts:
                    continue
                
                for artifact in artifacts:
                    # 다양한 타임스탬프 필드명 처리
                    timestamp = None
                    ts_field = None
                    
                    for field in ['timestamp', 'lastExecuted', 'lastWriteTime', 
                                 'lastAccessTime', 'installDate', 'lastConnectedTime']:
                        if artifact.get(field):
                            timestamp = artifact[field]
                            ts_field = field
                            break
                    
                    if timestamp and timestamp != 'N/A':
                        event = {
                            'timestamp': timestamp,
                            'timestamp_field': ts_field,
                            'hive': hive_type,
                            'artifact_type': artifact_type,
                            'artifact_data': artifact,
                            'description': self._generate_event_description(artifact_type, artifact)
                        }
                        self.timeline.append(event)
        
        # 시간순 정렬 (안전하게 문자열 처리)
        def safe_timestamp_key(event):
            ts = event['timestamp']
            if isinstance(ts, str):
                return ts
            return str(ts)
        
        self.timeline.sort(key=safe_timestamp_key)
        
        return self.timeline
    
    def _generate_event_description(self, artifact_type: str, artifact: Dict) -> str:
        """이벤트 설명 생성"""
        if artifact_type == 'shimcache':
            return f"Program executed: {artifact.get('path')}"
        elif artifact_type == 'amcache':
            return f"Program installed/modified: {artifact.get('programName')}"
        elif artifact_type == 'userassist':
            return f"User launched: {artifact.get('program')}"
        elif artifact_type == 'bam_dam':
            return f"Background activity: {artifact.get('path')}"
        elif artifact_type == 'usb_devices':
            return f"USB device connected: {artifact.get('serialNumber')}"
        elif artifact_type == 'recent_docs':
            return f"Document accessed: {artifact.get('path')}"
        elif artifact_type == 'run_keys':
            return f"Autorun configured: {artifact.get('program')}"
        elif artifact_type == 'network_profiles':
            return f"Network connected: {artifact.get('profileName')}"
        elif artifact_type == 'shellbags':
            return f"Folder accessed: {artifact.get('path')}"
        elif artifact_type == 'muicache':
            return f"Application UI accessed: {artifact.get('path')}"
        elif artifact_type == 'prefetch':
            return f"Program prefetched: {artifact.get('program')}"
        elif artifact_type == 'lnk_files':
            return f"Shortcut accessed: {artifact.get('lnkPath')}"
        elif artifact_type == 'installed_software':
            return f"Software installed: {artifact.get('displayName')}"
        elif artifact_type == 'typed_paths':
            return f"Path typed in Explorer: {artifact.get('path')}"
        elif artifact_type == 'recent_apps':
            return f"Recent app launched: {artifact.get('appName')}"
        elif artifact_type == 'wlan_profiles':
            return f"WiFi connected: {artifact.get('profileName')}"
        else:
            return f"{artifact_type}: {str(artifact)[:100]}"
    
    def get_summary(self) -> Dict:
        """분석 요약 생성"""
        return {
            'loaded_hives': list(self.hives.keys()),
            'hive_count': len(self.hives),
            'total_artifacts': sum(
                sum(1 for artifacts in hive['findings'].values() if artifacts)
                for hive in self.hives.values()
            ),
            'correlation_count': len(self.correlations),
            'timeline_events': len(self.timeline),
            'high_confidence_correlations': len([c for c in self.correlations 
                                                 if c.get('confidence') == 'HIGH'])
        }
