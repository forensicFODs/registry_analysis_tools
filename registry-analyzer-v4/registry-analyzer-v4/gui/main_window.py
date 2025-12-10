#!/usr/bin/env python3
"""
Main Window - Tkinter GUI
"""

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Any
import re

# 상위 디렉토리 모듈 import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.registry_parser import RegistryParser
from analyzers.forensics_analyzer import ForensicsAnalyzer
from analyzers.ai_analyzer import AIAnalyzer
from analyzers.multi_hive_analyzer import MultiHiveAnalyzer


class RegistryForensicGUI:
    """GUI 메인 클래스"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Windows Registry Forensic Analyzer v4.0")
        
        # 화면 크기 자동 감지 및 최적화
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        # 화면의 85% 크기로 설정 (여백 확보)
        window_width = int(screen_width * 0.85)
        window_height = int(screen_height * 0.85)
        
        # 최소/최대 크기 제한
        window_width = max(1000, min(window_width, 1920))  # 최소 1000, 최대 1920
        window_height = max(700, min(window_height, 1080))  # 최소 700, 최대 1080
        
        # 창을 화면 중앙에 배치
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        
        self.root.geometry(f"{window_width}x{window_height}+{x}+{y}")
        self.root.configure(bg='#1a1a1a')
        
        # 최소 크기 설정 (너무 작아지는 것 방지)
        self.root.minsize(1000, 700)
        
        # 창 크기 조절 가능
        self.root.resizable(True, True)
        
        # 스타일 설정
        self.setup_styles()
        
        # 변수
        self.file_path = tk.StringVar()
        self.api_provider = tk.StringVar(value='gemini')
        self.api_key = tk.StringVar()
        self.hive_type = tk.StringVar(value='AUTO (Detect)')
        self.analysis_results = None
        self.selected_files = []  # 선택된 파일 목록 (다중 선택 가능)
        
        # UI 구성
        self.create_widgets()
    
    def setup_styles(self):
        """스타일 설정"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # 다크 테마
        style.configure('TFrame', background='#1a1a1a')
        style.configure('TLabel', background='#1a1a1a', foreground='#e0e0e0', font=('Segoe UI', 10))
        style.configure('Title.TLabel', font=('Segoe UI', 16, 'bold'), foreground='#FFD700')
        style.configure('TButton', font=('Segoe UI', 10))
        style.configure('TRadiobutton', background='#1a1a1a', foreground='#e0e0e0', font=('Segoe UI', 10))
        style.configure('TCombobox', fieldbackground='#2a2a2a', background='#2a2a2a', foreground='#e0e0e0')
    
    def create_widgets(self):
        """위젯 생성"""
        # 헤더
        header = ttk.Frame(self.root)
        header.pack(fill=tk.X, padx=20, pady=20)
        
        ttk.Label(header, text="🛡️ 윈도우 레지스트리 포렌식 분석기", style='Title.TLabel').pack()
        ttk.Label(header, text="완전한 레지스트리 분석 도구", foreground='#00ff00').pack()
        
        # 메인 컨테이너 (PanedWindow 사용 - 크기 조절 가능)
        main_container = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, 
                                        sashrelief=tk.RAISED, sashwidth=5,
                                        bg='#1a1a1a')
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # 왼쪽 패널 (설정) - 최소 너비 300, 최대 너비 500
        left_panel = ttk.Frame(main_container)
        main_container.add(left_panel, minsize=300, width=380)
        
        self.create_config_panel(left_panel)
        
        # 오른쪽 패널 (결과) - 자동 확장
        right_panel = ttk.Frame(main_container)
        main_container.add(right_panel, minsize=500)
        
        self.create_results_panel(right_panel)
    
    def create_config_panel(self, parent):
        """설정 패널 생성"""
        # AI 설정
        ai_frame = ttk.LabelFrame(parent, text="⚙️ AI 설정", padding=15)
        ai_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(ai_frame, text="제공자:").pack(anchor=tk.W)
        provider_frame = ttk.Frame(ai_frame)
        provider_frame.pack(fill=tk.X, pady=5)
        
        ttk.Radiobutton(provider_frame, text="Gemini (무료)", variable=self.api_provider, value='gemini').pack(anchor=tk.W)
        ttk.Radiobutton(provider_frame, text="OpenAI (유료)", variable=self.api_provider, value='openai').pack(anchor=tk.W)
        
        ttk.Label(ai_frame, text="API 키:").pack(anchor=tk.W, pady=(10, 0))
        api_entry = ttk.Entry(ai_frame, textvariable=self.api_key, show='*', width=40)
        api_entry.pack(fill=tk.X, pady=5)
        
        # Hive Type은 항상 AUTO (자동 감지)
        # UI에서 제거하고 내부적으로만 AUTO 사용
        
        # 파일 선택 (다중 선택 가능) - 접기/펼치기 가능 (v4.0)
        self.file_frame = ttk.LabelFrame(parent, text="📁 레지스트리 파일", padding=15)
        self.file_frame.pack(fill=tk.X, pady=5)
        
        # 파일 선택 버튼 + 토글 버튼
        file_btn_frame = ttk.Frame(self.file_frame)
        file_btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(file_btn_frame, text="📂 파일 선택 (다중 가능)", 
                  command=self.select_files).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        # 접기/펼치기 토글 버튼
        self.file_list_visible = tk.BooleanVar(value=True)
        self.toggle_btn = tk.Button(file_btn_frame, text="▲ 접기", 
                                    command=self.toggle_file_list,
                                    bg='#2d2d2d', fg='#ffffff', width=8,
                                    cursor='hand2', relief=tk.RAISED, bd=2)
        self.toggle_btn.pack(side=tk.LEFT)
        
        # 선택된 파일 목록 표시 (접기/펼치기 가능)
        self.file_list_container = ttk.Frame(self.file_frame)
        self.file_list_container.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.file_list_frame = ttk.Frame(self.file_list_container)
        self.file_list_frame.pack(fill=tk.BOTH, expand=True)
        
        # 파일 목록 라벨 (동적 업데이트)
        self.file_count_label = ttk.Label(self.file_frame, text="선택된 파일: 0개", foreground='#FFD700')
        self.file_count_label.pack(anchor=tk.W, pady=5)
        
        # 분석 버튼
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, pady=20)
        
        analyze_btn = tk.Button(btn_frame, text="🔍 분석 시작", command=self.start_analysis,
                               bg='#FFD700', fg='#000000', font=('Segoe UI', 12, 'bold'),
                               cursor='hand2', relief=tk.RAISED, bd=3)
        analyze_btn.pack(fill=tk.X, pady=5)
        
        # Multi-Hive 분석 버튼 (v3.1)
        multi_hive_btn = tk.Button(btn_frame, text="🔗 Multi-Hive 분석", command=self.start_multi_hive_analysis,
                                   bg='#00BFFF', fg='#000000', font=('Segoe UI', 11, 'bold'),
                                   cursor='hand2', relief=tk.RAISED, bd=3)
        multi_hive_btn.pack(fill=tk.X, pady=5)
        
        clear_btn = tk.Button(btn_frame, text="🔄 전체 지우기", command=self.clear_all,
                             bg='#444444', fg='#ffffff', font=('Segoe UI', 10),
                             cursor='hand2', relief=tk.RAISED, bd=2)
        clear_btn.pack(fill=tk.X, pady=5)
        
        # 내보내기 버튼
        export_frame = ttk.Frame(parent)
        export_frame.pack(fill=tk.X, pady=5)
        
        self.export_json_btn = tk.Button(export_frame, text="💾 JSON 내보내기", command=self.export_json,
                                         bg='#00ff00', fg='#000000', font=('Segoe UI', 9),
                                         cursor='hand2', state=tk.DISABLED)
        self.export_json_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        self.export_csv_btn = tk.Button(export_frame, text="📄 CSV 내보내기", command=self.export_csv,
                                        bg='#00ff00', fg='#000000', font=('Segoe UI', 9),
                                        cursor='hand2', state=tk.DISABLED)
        self.export_csv_btn.pack(side=tk.LEFT, fill=tk.X, expand=True)
    
    def create_results_panel(self, parent):
        """결과 패널 생성"""
        results_frame = ttk.LabelFrame(parent, text="📊 분석 결과", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        # 검색 프레임 (v3.0)
        search_frame = tk.Frame(results_frame, bg='#1a1a1a')
        search_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(search_frame, text="🔍 검색:").pack(side=tk.LEFT, padx=(0, 5))
        
        self.search_query = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_query, width=40)
        search_entry.pack(side=tk.LEFT, padx=(0, 5))
        
        tk.Button(search_frame, text="검색", command=self.search_results,
                 bg='#0066ff', fg='#ffffff', font=('Segoe UI', 9),
                 cursor='hand2').pack(side=tk.LEFT, padx=(0, 5))
        
        tk.Button(search_frame, text="초기화", command=self.clear_search,
                 bg='#666666', fg='#ffffff', font=('Segoe UI', 9),
                 cursor='hand2').pack(side=tk.LEFT, padx=(0, 5))
        
        # 검색 옵션
        self.case_sensitive = tk.BooleanVar(value=False)
        ttk.Checkbutton(search_frame, text="대소문자 구분", 
                       variable=self.case_sensitive).pack(side=tk.LEFT, padx=(10, 0))
        
        self.regex_mode = tk.BooleanVar(value=False)
        ttk.Checkbutton(search_frame, text="정규표현식", 
                       variable=self.regex_mode).pack(side=tk.LEFT, padx=(10, 0))
        
        # 결과 카운트 레이블
        self.search_count_label = tk.Label(search_frame, text="", bg='#1a1a1a', fg='#00ff00')
        self.search_count_label.pack(side=tk.RIGHT, padx=(10, 0))
        
        # 폰트 크기 조절 프레임
        font_frame = tk.Frame(results_frame, bg='#1a1a1a')
        font_frame.pack(fill=tk.X, pady=(5, 5))
        
        ttk.Label(font_frame, text="🔤 폰트 크기:").pack(side=tk.LEFT, padx=(0, 5))
        
        self.font_size = tk.IntVar(value=10)
        
        tk.Button(font_frame, text="-", command=self.decrease_font,
                 bg='#444444', fg='#ffffff', font=('Segoe UI', 10, 'bold'),
                 width=3, cursor='hand2').pack(side=tk.LEFT, padx=2)
        
        tk.Label(font_frame, textvariable=self.font_size, 
                bg='#1a1a1a', fg='#00ff00', font=('Segoe UI', 10),
                width=3).pack(side=tk.LEFT, padx=2)
        
        tk.Button(font_frame, text="+", command=self.increase_font,
                 bg='#444444', fg='#ffffff', font=('Segoe UI', 10, 'bold'),
                 width=3, cursor='hand2').pack(side=tk.LEFT, padx=2)
        
        tk.Button(font_frame, text="기본", command=self.reset_font,
                 bg='#666666', fg='#ffffff', font=('Segoe UI', 9),
                 cursor='hand2').pack(side=tk.LEFT, padx=(10, 0))
        
        # 결과 텍스트 영역
        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD,
                                                       bg='#0a0a0a', fg='#00ff00',
                                                       font=('Consolas', 10),
                                                       insertbackground='#00ff00')
        self.results_text.pack(fill=tk.BOTH, expand=True)
        
        # 검색 하이라이트 태그 설정
        self.results_text.tag_config("highlight", background="#ffff00", foreground="#000000")
        
        # 초기 메시지
        self.results_text.insert('1.0', """
╔══════════════════════════════════════════════════════════════╗
║  Windows Registry Forensic Analyzer v4.0                    ║
║  Object-Oriented Architecture + Enhanced Analysis            ║
╚══════════════════════════════════════════════════════════════╝

Instructions:
1. Select AI provider and enter API key
2. Choose hive type (SYSTEM, SOFTWARE, SAM, etc.)
3. Select registry file
4. Click 'Start Analysis'

Supported Analysis:
✓ ShimCache (Executed Programs)
✓ UserAssist (User Activity)
✓ BAM/DAM (Background Activity)
✓ USB Devices
✓ Recent Documents
✓ Run/RunOnce (Auto-start)
✓ SAM User Accounts
✓ Network Profiles
✓ ShellBags (Folder Access History)
✓ Prefetch (Program Execution Cache)
✓ LNK Files (Shortcuts)
✓ Security Policies & SIDs
✓ AI-powered forensic analysis
✓ Search & Filter Results
        """)
        self.results_text.config(state=tk.DISABLED)
    
    def select_files(self):
        """파일 선택 (다중 선택 가능)"""
        filenames = filedialog.askopenfilenames(
            title="레지스트리 파일 선택 (다중 선택 가능)",
            filetypes=[
                ("Registry Files", "SYSTEM;SOFTWARE;SAM;SECURITY;NTUSER.DAT;UsrClass.dat;Amcache.hve;*.dat;*.hve"),
                ("All Files", "*.*")
            ]
        )
        
        if filenames:
            self.selected_files = list(filenames)
            self.update_file_list_display()
    
    def update_file_list_display(self):
        """선택된 파일 목록 표시 업데이트"""
        # 기존 위젯 제거
        for widget in self.file_list_frame.winfo_children():
            widget.destroy()
        
        # 파일 개수 업데이트
        count = len(self.selected_files)
        self.file_count_label.config(text=f"선택된 파일: {count}개")
        
        if count == 0:
            ttk.Label(self.file_list_frame, text="선택된 파일이 없습니다.", 
                     foreground='#888888').pack(anchor=tk.W)
            return
        
        # 스크롤 가능한 프레임 생성 (동적 높이)
        # 파일 개수에 따라 높이 조정 (최소 100, 최대 300)
        dynamic_height = min(300, max(100, count * 25))
        canvas = tk.Canvas(self.file_list_frame, bg='#1a1a1a', 
                          height=dynamic_height, 
                          highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.file_list_frame, orient="vertical", 
                                 command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # 파일 목록 표시
        for i, filepath in enumerate(self.selected_files, 1):
            filename = os.path.basename(filepath)
            
            # 하이브 타입 자동 감지
            try:
                with open(filepath, 'rb') as f:
                    data = f.read(512)  # 헤더만 읽기
                    parser = RegistryParser(data, filepath)
                    hive_type = parser.detect_hive_type()
            except:
                hive_type = "Unknown"
            
            file_label = ttk.Label(scrollable_frame, 
                                  text=f"{i}. {filename} ({hive_type})",
                                  foreground='#00ff00')
            file_label.pack(anchor=tk.W, pady=2)
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 파일이 선택되면 자동으로 접기 (v4.0)
        if count > 0 and self.file_list_visible.get():
            self.root.after(500, self.toggle_file_list)  # 0.5초 후 자동 접기
    
    def show_file_selection_dialog(self):
        """파일 선택 다이얼로그 표시 (Listbox 사용)"""
        # 다이얼로그 생성
        dialog = tk.Toplevel(self.root)
        dialog.title("분석할 파일 선택")
        dialog.geometry("600x400")
        dialog.configure(bg='#1a1a1a')
        dialog.transient(self.root)
        dialog.grab_set()
        
        # 제목
        title_label = tk.Label(dialog, text="🔍 단일 파일 분석", 
                              font=('Segoe UI', 14, 'bold'),
                              bg='#1a1a1a', fg='#FFD700')
        title_label.pack(pady=10)
        
        info_label = tk.Label(dialog, 
                            text="분석할 파일을 선택하세요 (1개만 선택 가능)",
                            font=('Segoe UI', 10),
                            bg='#1a1a1a', fg='#e0e0e0')
        info_label.pack(pady=5)
        
        # 파일 목록 프레임
        list_frame = tk.Frame(dialog, bg='#1a1a1a')
        list_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Listbox + Scrollbar
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        listbox = tk.Listbox(list_frame, 
                            yscrollcommand=scrollbar.set,
                            font=('Consolas', 10),
                            bg='#2a2a2a', fg='#00ff00',
                            selectmode=tk.SINGLE,
                            height=15)
        listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=listbox.yview)
        
        # 파일 목록 추가
        for i, filepath in enumerate(self.selected_files):
            filename = os.path.basename(filepath)
            
            # 하이브 타입 감지
            try:
                with open(filepath, 'rb') as f:
                    data = f.read(512)
                    parser = RegistryParser(data, filepath)
                    hive_type = parser.detect_hive_type()
            except:
                hive_type = "Unknown"
            
            listbox.insert(tk.END, f"{i+1}. {filename} ({hive_type})")
        
        # 선택된 파일 변수
        selected_file = [None]
        
        def on_select():
            selection = listbox.curselection()
            if selection:
                index = selection[0]
                selected_file[0] = self.selected_files[index]
                dialog.destroy()
            else:
                messagebox.showwarning("경고", "파일을 선택하세요", parent=dialog)
        
        def on_cancel():
            dialog.destroy()
        
        # 버튼 프레임
        button_frame = tk.Frame(dialog, bg='#1a1a1a')
        button_frame.pack(pady=10)
        
        select_btn = tk.Button(button_frame, text="✅ 선택", command=on_select,
                              bg='#00ff00', fg='#000000', font=('Segoe UI', 11, 'bold'),
                              width=15, cursor='hand2')
        select_btn.pack(side=tk.LEFT, padx=5)
        
        cancel_btn = tk.Button(button_frame, text="❌ 취소", command=on_cancel,
                              bg='#ff0000', fg='#ffffff', font=('Segoe UI', 11, 'bold'),
                              width=15, cursor='hand2')
        cancel_btn.pack(side=tk.LEFT, padx=5)
        
        # 다이얼로그 대기
        self.root.wait_window(dialog)
        
        return selected_file[0]
    
    def start_analysis(self):
        """분석 시작 - 선택된 파일 목록에서 1개 선택"""
        # 파일 선택 확인
        if not self.selected_files:
            messagebox.showerror("오류", "먼저 파일을 선택하세요 (📂 파일 선택 버튼)")
            return
        
        # 파일이 1개만 있으면 바로 분석
        if len(self.selected_files) == 1:
            selected_file = self.selected_files[0]
        else:
            # 여러 개 있으면 선택 창 표시
            selected_file = self.show_file_selection_dialog()
            if not selected_file:
                return
        
        # API 키 확인 (선택사항)
        if not self.api_key.get():
            response = messagebox.askyesno(
                "AI 분석",
                "API 키가 입력되지 않았습니다.\n\n"
                "바이너리 분석만 진행하고 AI 분석은 건너뛰시겠습니까?\n\n"
                "(AI 분석을 원하시면 '아니오'를 선택하고 API 키를 먼저 입력해주세요)"
            )
            if not response:
                return
        
        # 결과 초기화
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete('1.0', tk.END)
        self.results_text.insert('1.0', "🔍 분석 진행 중...\n\n")
        self.results_text.config(state=tk.DISABLED)
        self.root.update()
        
        try:
            # 파일 읽기
            self.results_text.config(state=tk.NORMAL)
            self.results_text.insert(tk.END, "📂 파일 읽는 중...\n")
            self.results_text.config(state=tk.DISABLED)
            self.root.update()
            
            # selected_file 사용
            with open(selected_file, 'rb') as f:
                data = f.read()
            
            # 파서 생성 (파일 경로 전달)
            parser = RegistryParser(data, selected_file)
            
            self.results_text.config(state=tk.NORMAL)
            self.results_text.insert(tk.END, f"📂 파일: {os.path.basename(selected_file)}\n")
            self.results_text.config(state=tk.DISABLED)
            self.root.update()
            
            if not parser.validate_hive():
                messagebox.showwarning("경고", "유효한 레지스트리 하이브 파일이 아닐 수 있습니다 (missing 'regf' signature)")
            
            # 하이브 타입 자동 감지
            detected_type = parser.detect_hive_type()
            self.results_text.config(state=tk.NORMAL)
            self.results_text.insert(tk.END, f"🔍 Detected hive type: {detected_type}\n")
            self.results_text.config(state=tk.DISABLED)
            self.root.update()
            
            # 사용자가 선택한 타입이 있으면 우선, 없으면 자동 감지 사용
            selected_type = self.hive_type.get()
            if selected_type == 'AUTO (Detect)' or not selected_type:
                hive_type = detected_type
            else:
                hive_type = selected_type
            
            # 포렌식 분석
            self.results_text.config(state=tk.NORMAL)
            self.results_text.insert(tk.END, f"🔬 Running forensic analysis on {hive_type} hive...\n")
            self.results_text.config(state=tk.DISABLED)
            self.root.update()
            
            analyzer = ForensicsAnalyzer(parser, hive_type)
            
            raw_findings = {
                'shimcache': analyzer.analyze_shimcache(),
                'amcache': analyzer.analyze_amcache(),
                'userassist': analyzer.analyze_userassist(),
                'bam_dam': analyzer.analyze_bam_dam(),
                'usb_devices': analyzer.analyze_usb_devices(),
                'recent_docs': analyzer.analyze_recent_docs(),
                'run_keys': analyzer.analyze_run_keys(),
                'sam_users': analyzer.analyze_sam_users(),
                'network_profiles': analyzer.analyze_network_profiles(),
                # v3.0 새로운 분석 모듈
                'shellbags': analyzer.analyze_shellbags(),
                'muicache': analyzer.analyze_muicache(),
                'prefetch': analyzer.analyze_prefetch(),
                'lnk_files': analyzer.analyze_lnk_files(),
                'installed_software': analyzer.analyze_installed_software_detailed(),
                'security_detailed': analyzer.analyze_security_detailed(),
                # v3.1 추가 모듈 (5개)
                'typed_paths': analyzer.analyze_typed_paths(),
                'recent_apps': analyzer.analyze_recent_apps(),
                'services_detailed': analyzer.analyze_services_detailed(),
                'wlan_profiles': analyzer.analyze_wlan_profiles(),
                'timezone': analyzer.analyze_timezone()
            }
            
            # 문자열 추출 (개선: 50 → 1000개)
            # 우선순위 기반: 아티팩트에서 추출한 데이터 우선
            strings = parser.extract_strings(min_length=4, max_strings=1000)
            
            # AI 분석
            self.results_text.config(state=tk.NORMAL)
            self.results_text.insert(tk.END, "🤖 AI 분석 실행 중...\n")
            self.results_text.config(state=tk.DISABLED)
            self.root.update()
            
            if self.api_provider.get() == 'gemini':
                ai_results = AIAnalyzer.analyze_with_gemini(
                    self.api_key.get(),
                    self.hive_type.get(),
                    strings,
                    raw_findings
                )
            else:
                ai_results = AIAnalyzer.analyze_with_openai(
                    self.api_key.get(),
                    self.hive_type.get(),
                    strings,
                    raw_findings
                )
            
            # 결과 저장
            self.analysis_results = {
                'file_name': os.path.basename(self.file_path.get()),
                'file_size': len(data),
                'hive_type': self.hive_type.get(),
                'analysis_date': datetime.now().isoformat(),
                'raw_findings': raw_findings,
                'ai_analysis': ai_results
            }
            
            # 결과 표시
            self.display_results(self.analysis_results)
            
            # 내보내기 버튼 활성화
            self.export_json_btn.config(state=tk.NORMAL)
            self.export_csv_btn.config(state=tk.NORMAL)
            
            messagebox.showinfo("Success", "Analysis completed successfully!")
            
        except Exception as e:
            self.results_text.config(state=tk.NORMAL)
            self.results_text.insert(tk.END, f"\n❌ Error: {str(e)}\n")
            self.results_text.config(state=tk.DISABLED)
            messagebox.showerror("Error", f"Analysis failed: {str(e)}")
    
    def display_results(self, results):
        """결과 표시"""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete('1.0', tk.END)
        
        # 헤더
        self.results_text.insert(tk.END, "╔" + "═"*78 + "╗\n")
        self.results_text.insert(tk.END, f"║  Analysis Results - {results['file_name']:<60} ║\n")
        self.results_text.insert(tk.END, "╚" + "═"*78 + "╝\n\n")
        
        # 기본 정보
        self.results_text.insert(tk.END, f"File: {results['file_name']}\n")
        self.results_text.insert(tk.END, f"Size: {results['file_size']:,} bytes\n")
        self.results_text.insert(tk.END, f"Type: {results['hive_type']}\n")
        self.results_text.insert(tk.END, f"Date: {results['analysis_date']}\n\n")
        
        # Raw Findings
        self.results_text.insert(tk.END, "═" * 80 + "\n")
        self.results_text.insert(tk.END, "📋 포렌식 발견사항\n")
        self.results_text.insert(tk.END, "═" * 80 + "\n\n")
        
        raw = results['raw_findings']
        
        # ShimCache
        if raw['shimcache']:
            self.results_text.insert(tk.END, f"🚀 ShimCache (Executed Programs): {len(raw['shimcache'])} items\n")
            for i, item in enumerate(raw['shimcache'], 1):
                ts_info = f" [{item.get('timestamp', 'N/A')}]" if item.get('timestamp') else ""
                size_info = f" ({item.get('fileSize', 0):,} bytes)" if item.get('fileSize') else ""
                self.results_text.insert(tk.END, f"   {i}. {item['path']}{ts_info}{size_info}\n")
            self.results_text.insert(tk.END, "\n")
        
        # Amcache
        if raw['amcache']:
            self.results_text.insert(tk.END, f"📦 Amcache (Program Information): {len(raw['amcache'])} items\n")
            for i, item in enumerate(raw['amcache'], 1):
                sha1_info = f" [SHA1:{item.get('sha1', 'N/A')[:16]}...]" if item.get('sha1') else ""
                pub_info = f" ({item.get('publisher', 'Unknown')})" if item.get('publisher') else ""
                ver_info = f" v{item.get('version')}" if item.get('version') else ""
                size_info = f" [{item.get('fileSize', 0):,} bytes]" if item.get('fileSize') else ""
                ts_info = f" [{item.get('timestamp', 'N/A')}]" if item.get('timestamp') else ""
                self.results_text.insert(tk.END, f"   {i}. {item['programName']}{pub_info}{ver_info}{ts_info}\n")
                if sha1_info or size_info:
                    self.results_text.insert(tk.END, f"       {sha1_info}{size_info}\n")
            self.results_text.insert(tk.END, "\n")
        
        # UserAssist
        if raw['userassist']:
            self.results_text.insert(tk.END, f"👤 UserAssist (User Activity): {len(raw['userassist'])} items\n")
            for i, item in enumerate(raw['userassist'], 1):
                run_info = f" [Runs: {item.get('runCount')}]" if item.get('runCount') else ""
                focus_ms = item.get('focusTime')
                focus_info = ""
                if focus_ms:
                    focus_sec = focus_ms / 1000
                    if focus_sec < 60:
                        focus_info = f" [Focus: {focus_sec:.1f}s]"
                    else:
                        focus_min = focus_sec / 60
                        focus_info = f" [Focus: {focus_min:.1f}m]"
                ts_info = f" [{item.get('lastExecuted', 'N/A')}]" if item.get('lastExecuted') else ""
                self.results_text.insert(tk.END, f"   {i}. {item['program']}{run_info}{focus_info}{ts_info}\n")
            self.results_text.insert(tk.END, "\n")
        
        # BAM/DAM
        if raw['bam_dam']:
            self.results_text.insert(tk.END, f"⚡ BAM/DAM (Background Activity): {len(raw['bam_dam'])} items\n")
            for i, item in enumerate(raw['bam_dam'], 1):
                ts = f" [{item['timestamp']}]" if item.get('timestamp') else ""
                sid_info = f" [User: {item['userSID'][-8:]}...]" if item.get('userSID') else ""
                self.results_text.insert(tk.END, f"   {i}. {item['path']}{ts}{sid_info}\n")
            self.results_text.insert(tk.END, "\n")
        
        # USB Devices
        if raw['usb_devices']:
            self.results_text.insert(tk.END, f"💾 USB Devices: {len(raw['usb_devices'])} items\n")
            for i, item in enumerate(raw['usb_devices'], 1):
                vid_pid = f" (VID:{item.get('vid', 'N/A')} PID:{item.get('pid', 'N/A')})" if item.get('vid') else ""
                ts_info = f" [{item.get('timestamp', 'N/A')}]" if item.get('timestamp') else ""
                serial_info = f" [S/N: {item.get('serialNumber', 'N/A')}]" if item.get('serialNumber') else ""
                self.results_text.insert(tk.END, f"   {i}. {item['device']}{vid_pid}{ts_info}{serial_info}\n")
            self.results_text.insert(tk.END, "\n")
        
        # Recent Documents
        if raw['recent_docs']:
            self.results_text.insert(tk.END, f"📄 Recent Documents: {len(raw['recent_docs'])} items\n")
            for i, item in enumerate(raw['recent_docs'], 1):
                ts_info = f" [{item.get('timestamp', 'N/A')}]" if item.get('timestamp') else ""
                path_info = f" ({item.get('path', '')}" if item.get('path') else ""
                self.results_text.insert(tk.END, f"   {i}. {item['document']}{ts_info}{path_info}\n")
            self.results_text.insert(tk.END, "\n")
        
        # Run Keys
        if raw['run_keys']:
            self.results_text.insert(tk.END, f"🔑 Auto-Start Programs: {len(raw['run_keys'])} items\n")
            for i, item in enumerate(raw['run_keys'], 1):
                self.results_text.insert(tk.END, f"   {i}. {item['name']}: {item['command'][:80]}\n")
            self.results_text.insert(tk.END, "\n")
        
        # SAM Users
        if raw['sam_users']:
            self.results_text.insert(tk.END, f"👥 User Accounts: {len(raw['sam_users'])} items\n")
            for i, item in enumerate(raw['sam_users'], 1):
                last_login = f" [Last Login: {item.get('lastLogin', 'N/A')}]" if item.get('lastLogin') else ""
                created = f" [Created: {item.get('created', 'N/A')}]" if item.get('created') else ""
                self.results_text.insert(tk.END, f"   {i}. {item['username']} (SID: {item['sid']}){last_login}{created}\n")
            self.results_text.insert(tk.END, "\n")
        
        # Network Profiles
        if raw['network_profiles']:
            self.results_text.insert(tk.END, f"🌐 Network Profiles: {len(raw['network_profiles'])} items\n")
            for i, item in enumerate(raw['network_profiles'], 1):
                ts_info = f" [{item.get('timestamp', 'N/A')}]" if item.get('timestamp') else ""
                type_info = f" ({item.get('type', 'Unknown')})" if item.get('type') else ""
                self.results_text.insert(tk.END, f"   {i}. {item['network']}{type_info}{ts_info}\n")
            self.results_text.insert(tk.END, "\n")
        
        # ShellBags (v3.0)
        if raw.get('shellbags'):
            self.results_text.insert(tk.END, f"📁 ShellBags (Folder Access History): {len(raw['shellbags'])} items\n")
            for i, item in enumerate(raw['shellbags'], 1):
                ts_info = f" [{item.get('timestamp', 'N/A')}]" if item.get('timestamp') else ""
                type_info = f" [{item.get('type', 'folder')}]" if item.get('type') else ""
                self.results_text.insert(tk.END, f"   {i}. {item['path']}{type_info}{ts_info}\n")
            self.results_text.insert(tk.END, "\n")
        
        # MuiCache (v3.0)
        if raw.get('muicache'):
            self.results_text.insert(tk.END, f"🎨 MuiCache (Application UI Cache): {len(raw['muicache'])} items\n")
            for i, item in enumerate(raw['muicache'], 1):
                app_info = f" ({item.get('appName')})" if item.get('appName') else ""
                ts_info = f" [{item.get('timestamp', 'N/A')}]" if item.get('timestamp') else ""
                self.results_text.insert(tk.END, f"   {i}. {item['path']}{app_info}{ts_info}\n")
            self.results_text.insert(tk.END, "\n")
        
        # Prefetch (v3.0)
        if raw.get('prefetch'):
            self.results_text.insert(tk.END, f"⚡ Prefetch (Program Execution Cache): {len(raw['prefetch'])} items\n")
            for i, item in enumerate(raw['prefetch'], 1):
                run_info = f" [Runs: {item.get('runCount')}]" if item.get('runCount') else ""
                ts_info = f" [{item.get('timestamp', 'N/A')}]" if item.get('timestamp') else ""
                self.results_text.insert(tk.END, f"   {i}. {item['program']}{run_info}{ts_info}\n")
            self.results_text.insert(tk.END, "\n")
        
        # LNK Files (v3.0)
        if raw.get('lnk_files'):
            self.results_text.insert(tk.END, f"🔗 LNK Files (Shortcuts): {len(raw['lnk_files'])} items\n")
            for i, item in enumerate(raw['lnk_files'], 1):
                target_info = f" → {item.get('targetPath', 'N/A')}" if item.get('targetPath') else ""
                ts_info = f" [{item.get('timestamp', 'N/A')}]" if item.get('timestamp') else ""
                self.results_text.insert(tk.END, f"   {i}. {item['lnkPath']}{target_info}{ts_info}\n")
            self.results_text.insert(tk.END, "\n")
        
        # Installed Software Detailed (v3.0)
        if raw.get('installed_software'):
            self.results_text.insert(tk.END, f"💿 Installed Software (Detailed): {len(raw['installed_software'])} items\n")
            for i, item in enumerate(raw['installed_software'], 1):
                pub_info = f" by {item.get('publisher')}" if item.get('publisher') else ""
                ver_info = f" v{item.get('version')}" if item.get('version') else ""
                date_info = f" [Installed: {item.get('installDate')}]" if item.get('installDate') else ""
                self.results_text.insert(tk.END, f"   {i}. {item['displayName']}{pub_info}{ver_info}{date_info}\n")
                if item.get('installLocation'):
                    self.results_text.insert(tk.END, f"       Location: {item.get('installLocation')}\n")
            self.results_text.insert(tk.END, "\n")
        
        # Security Detailed (v3.0)
        if raw.get('security_detailed'):
            self.results_text.insert(tk.END, f"🔐 Security Policies & SIDs: {len(raw['security_detailed'])} items\n")
            for i, item in enumerate(raw['security_detailed'], 1):
                if item.get('type') == 'SecurityPolicy':
                    val_info = f" = {item.get('value')}" if item.get('value') is not None else ""
                    self.results_text.insert(tk.END, f"   {i}. [{item.get('policyKey')}] {item.get('policyName', 'N/A')}{val_info}\n")
                elif item.get('type') == 'SID':
                    type_info = f" ({item.get('sidType', 'Unknown')})" if item.get('sidType') else ""
                    self.results_text.insert(tk.END, f"   {i}. {item.get('sid')}{type_info}\n")
            self.results_text.insert(tk.END, "\n")
        
        # TypedPaths (v3.1)
        if raw.get('typed_paths'):
            self.results_text.insert(tk.END, f"📍 TypedPaths (Address Bar History): {len(raw['typed_paths'])} items\n")
            for i, item in enumerate(raw['typed_paths'], 1):
                mru_info = f" [MRU: {item.get('mruOrder')}]" if item.get('mruOrder') is not None else ""
                type_info = f" ({item.get('type')})" if item.get('type') else ""
                self.results_text.insert(tk.END, f"   {i}. {item['path']}{mru_info}{type_info}\n")
            self.results_text.insert(tk.END, "\n")
        
        # RecentApps (v3.1)
        if raw.get('recent_apps'):
            self.results_text.insert(tk.END, f"📱 RecentApps (Windows 10+ Recent Apps): {len(raw['recent_apps'])} items\n")
            for i, item in enumerate(raw['recent_apps'], 1):
                app_info = item.get('appName', 'Unknown')
                path_info = f" [{item.get('appPath', 'N/A')}]" if item.get('appPath') else ""
                count_info = f" (Launches: {item.get('launchCount')})" if item.get('launchCount') else ""
                ts_info = f" [Last: {item.get('lastAccessTime', 'N/A')}]" if item.get('lastAccessTime') else ""
                self.results_text.insert(tk.END, f"   {i}. {app_info}{count_info}{ts_info}\n")
                if path_info:
                    self.results_text.insert(tk.END, f"       Path: {item.get('appPath', 'N/A')}\n")
            self.results_text.insert(tk.END, "\n")
        
        # Services Detailed (v3.1)
        if raw.get('services_detailed'):
            self.results_text.insert(tk.END, f"⚙️  Services (System Services): {len(raw['services_detailed'])} items\n")
            for i, item in enumerate(raw['services_detailed'], 1):
                name = item.get('serviceName', 'Unknown')
                start_type = item.get('startType', 'Unknown')
                img_path = item.get('imagePath', 'N/A')
                display = item.get('displayName', '')
                
                # startType에 따른 이모지 추가
                start_emoji = {
                    'Boot': '🚀', 'System': '⚡', 'Auto': '✅', 
                    'Manual': '⏸️', 'Disabled': '❌'
                }.get(start_type, '❓')
                
                self.results_text.insert(tk.END, f"   {i}. {start_emoji} {name} [{start_type}]\n")
                if display and display != name:
                    self.results_text.insert(tk.END, f"       Display: {display}\n")
                self.results_text.insert(tk.END, f"       Image: {img_path}\n")
            self.results_text.insert(tk.END, "\n")
        
        # WLAN Profiles (v3.1)
        if raw.get('wlan_profiles'):
            self.results_text.insert(tk.END, f"📶 WLAN Profiles (Wi-Fi Networks): {len(raw['wlan_profiles'])} items\n")
            for i, item in enumerate(raw['wlan_profiles'], 1):
                profile_name = item.get('profileName', 'Unknown')
                conn_type = item.get('connectionType', 'Unknown')
                ts_info = f" [Connected: {item.get('lastConnectedTime')}]" if item.get('lastConnectedTime') else ""
                conn_emoji = '🏢' if conn_type == 'Infrastructure' else '📡' if conn_type == 'AdHoc' else '❓'
                self.results_text.insert(tk.END, f"   {i}. {conn_emoji} {profile_name} ({conn_type}){ts_info}\n")
            self.results_text.insert(tk.END, "\n")
        
        # TimeZone (v3.1)
        if raw.get('timezone'):
            self.results_text.insert(tk.END, f"🌍 Time Zone Information: {len(raw['timezone'])} items\n")
            for i, item in enumerate(raw['timezone'], 1):
                std_name = item.get('standardName', 'Unknown')
                bias = item.get('bias')
                bias_info = ""
                if bias is not None:
                    hours = -(bias // 60)  # Bias는 음수로 저장됨
                    bias_info = f" (UTC{hours:+d}:00)"
                daylight = f" / Daylight: {item.get('daylightName')}" if item.get('daylightName') else ""
                self.results_text.insert(tk.END, f"   {i}. {std_name}{bias_info}{daylight}\n")
            self.results_text.insert(tk.END, "\n")
        
        # AI Analysis
        ai = results['ai_analysis']
        if 'error' not in ai:
            self.results_text.insert(tk.END, "═" * 80 + "\n")
            self.results_text.insert(tk.END, "🤖 AI 포렌식 분석\n")
            self.results_text.insert(tk.END, "═" * 80 + "\n\n")
            
            if 'summary' in ai:
                self.results_text.insert(tk.END, f"Summary:\n{ai['summary']}\n\n")
            
            if 'suspiciousActivities' in ai and ai['suspiciousActivities']:
                self.results_text.insert(tk.END, "⚠️  의심스러운 활동:\n")
                for i, item in enumerate(ai['suspiciousActivities'], 1):
                    self.results_text.insert(tk.END, f"   {i}. {item}\n")
                self.results_text.insert(tk.END, "\n")
            
            if 'timeline' in ai and ai['timeline']:
                self.results_text.insert(tk.END, "📅 타임라인:\n")
                for i, item in enumerate(ai['timeline'], 1):
                    ts = item.get('timestamp', 'Unknown')
                    event = item.get('event', item if isinstance(item, str) else '')
                    self.results_text.insert(tk.END, f"   {i}. [{ts}] {event}\n")
                self.results_text.insert(tk.END, "\n")
            
            if 'recommendations' in ai and ai['recommendations']:
                self.results_text.insert(tk.END, "💡 권장사항:\n")
                for i, item in enumerate(ai['recommendations'], 1):
                    self.results_text.insert(tk.END, f"   {i}. {item}\n")
        else:
            self.results_text.insert(tk.END, f"\n❌ AI Analysis Error: {ai['error']}\n")
        
        self.results_text.config(state=tk.DISABLED)
    
    def export_json(self):
        """JSON 내보내기"""
        if not self.analysis_results:
            messagebox.showerror("Error", "No results to export")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(self.analysis_results, f, indent=2, ensure_ascii=False, default=str)
                messagebox.showinfo("Success", f"Exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {str(e)}")
    
    def export_csv(self):
        """CSV 내보내기"""
        if not self.analysis_results:
            messagebox.showerror("Error", "No results to export")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8-sig') as f:
                    # 헤더
                    f.write("Category,Item,Timestamp,Details\n")
                    
                    raw = self.analysis_results['raw_findings']
                    
                    # ShimCache (with timestamp and file size)
                    for item in raw['shimcache']:
                        ts = item.get('timestamp', '')
                        size = item.get('fileSize', '')
                        details = f"Size: {size} bytes" if size else ""
                        f.write(f"ShimCache,{item['path']},{ts},{details}\n")
                    
                    # Amcache (with SHA1, publisher, version, etc.)
                    for item in raw.get('amcache', []):
                        ts = item.get('timestamp', '')
                        sha1 = item.get('sha1', 'N/A')
                        pub = item.get('publisher', 'Unknown')
                        ver = item.get('version', '')
                        size = item.get('fileSize', '')
                        details = f"SHA1:{sha1[:16]}... Publisher:{pub} Version:{ver} Size:{size}"
                        f.write(f"Amcache,{item['programName']},{ts},{details}\n")
                    
                    # UserAssist (with run count and focus time)
                    for item in raw['userassist']:
                        runs = item.get('runCount', '')
                        focus = item.get('focusTime', '')
                        details = f"Runs:{runs} FocusTime:{focus}ms" if runs or focus else ""
                        f.write(f"UserAssist,{item['program']},,{details}\n")
                    
                    # BAM/DAM (with user SID)
                    for item in raw['bam_dam']:
                        ts = item.get('timestamp', '')
                        sid = item.get('userSID', '')
                        details = f"UserSID:{sid}" if sid else ""
                        f.write(f"BAM/DAM,{item['path']},{ts},{details}\n")
                    
                    # USB
                    for item in raw['usb_devices']:
                        vid = item.get('vid', '')
                        pid = item.get('pid', '')
                        f.write(f"USB Device,{item['device']},,VID:{vid} PID:{pid}\n")
                    
                    # Recent Docs
                    for item in raw['recent_docs']:
                        f.write(f"Recent Document,{item['document']},,\n")
                    
                    # Run Keys
                    for item in raw['run_keys']:
                        f.write(f"Auto-Start,{item['name']},,{item['command']}\n")
                    
                    # SAM Users
                    for item in raw['sam_users']:
                        f.write(f"User Account,{item['username']},,{item['sid']}\n")
                    
                    # Network
                    for item in raw['network_profiles']:
                        f.write(f"Network Profile,{item['network']},,\n")
                
                messagebox.showinfo("Success", f"Exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {str(e)}")
    
    def clear_all(self):
        """모두 지우기"""
        self.file_path.set("")
        self.selected_files = []  # 선택된 파일 목록 초기화
        self.update_file_list_display()  # UI 업데이트
        self.analysis_results = None
        
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete('1.0', tk.END)
        self.results_text.insert('1.0', """
╔══════════════════════════════════════════════════════════════╗
║  Windows Registry Forensic Analyzer v4.0                    ║
║  Object-Oriented Architecture + Enhanced Analysis            ║
╚══════════════════════════════════════════════════════════════╝

Instructions:
1. Select AI provider and enter API key
2. Choose hive type
3. Select registry file
4. Click 'Start Analysis'
        """)
        self.results_text.config(state=tk.DISABLED)
        
        self.export_json_btn.config(state=tk.DISABLED)
        self.export_csv_btn.config(state=tk.DISABLED)
    
    def search_results(self):
        """분석 결과 검색 (v3.0)"""
        if not self.analysis_results:
            messagebox.showwarning("경고", "검색할 분석 결과가 없습니다.")
            return
        
        query = self.search_query.get().strip()
        if not query:
            messagebox.showwarning("경고", "검색어를 입력하세요.")
            return
        
        # 기존 하이라이트 제거
        self.results_text.tag_remove("highlight", "1.0", tk.END)
        
        # 검색 수행
        case_sensitive = self.case_sensitive.get()
        regex_mode = self.regex_mode.get()
        
        match_count = 0
        
        if regex_mode:
            # 정규표현식 검색
            try:
                import re
                pattern = re.compile(query, 0 if case_sensitive else re.IGNORECASE)
            except re.error as e:
                messagebox.showerror("오류", f"잘못된 정규표현식: {e}")
                return
            
            # 텍스트에서 패턴 검색
            content = self.results_text.get("1.0", tk.END)
            for match in pattern.finditer(content):
                start_idx = f"1.0+{match.start()}c"
                end_idx = f"1.0+{match.end()}c"
                self.results_text.tag_add("highlight", start_idx, end_idx)
                match_count += 1
        
        else:
            # 일반 문자열 검색
            search_str = query if case_sensitive else query.lower()
            start_pos = "1.0"
            
            while True:
                pos = self.results_text.search(search_str, start_pos, tk.END, 
                                              nocase=not case_sensitive)
                if not pos:
                    break
                
                end_pos = f"{pos}+{len(query)}c"
                self.results_text.tag_add("highlight", pos, end_pos)
                match_count += 1
                start_pos = end_pos
        
        # 결과 카운트 표시
        if match_count > 0:
            self.search_count_label.config(text=f"찾음: {match_count}개")
            # 첫 번째 매치로 스크롤
            first_match = self.results_text.tag_ranges("highlight")
            if first_match:
                self.results_text.see(first_match[0])
        else:
            self.search_count_label.config(text="결과 없음")
            messagebox.showinfo("검색", f"'{query}'에 대한 결과를 찾을 수 없습니다.")
    
    def clear_search(self):
        """검색 초기화 (v3.0)"""
        self.search_query.set("")
        self.search_count_label.config(text="")
        self.results_text.tag_remove("highlight", "1.0", tk.END)
    
    def decrease_font(self):
        """폰트 크기 감소 (v4.0)"""
        current = self.font_size.get()
        if current > 6:  # 최소 크기 제한
            new_size = current - 1
            self.font_size.set(new_size)
            self.results_text.config(font=("Consolas", new_size))
    
    def increase_font(self):
        """폰트 크기 증가 (v4.0)"""
        current = self.font_size.get()
        if current < 20:  # 최대 크기 제한
            new_size = current + 1
            self.font_size.set(new_size)
            self.results_text.config(font=("Consolas", new_size))
    
    def reset_font(self):
        """폰트 크기 기본값으로 리셋 (v4.0)"""
        self.font_size.set(10)
        self.results_text.config(font=("Consolas", 10))
    
    def toggle_file_list(self):
        """파일 목록 표시 토글 (v4.0)"""
        if self.file_list_visible.get():
            # 접기
            self.file_list_container.pack_forget()
            self.file_list_visible.set(False)
            self.toggle_btn.config(text="▼ 펼치기")
        else:
            # 펼치기
            self.file_list_container.pack(fill=tk.BOTH, expand=True, pady=5)
            self.file_list_visible.set(True)
            self.toggle_btn.config(text="▲ 접기")
    
    def start_multi_hive_analysis(self):
        """Multi-hive 분석 시작 - 이미 선택된 파일 사용 (v4.0)"""
        # 이미 선택된 파일 확인
        if not self.selected_files:
            messagebox.showerror("오류", 
                               "먼저 파일을 선택하세요!\n\n"
                               "1. '📂 파일 선택' 버튼으로 여러 파일 선택\n"
                               "2. '🔗 Multi-Hive 분석' 버튼 클릭")
            return
        
        if len(self.selected_files) < 2:
            messagebox.showwarning("경고", 
                                 f"현재 선택된 파일: {len(self.selected_files)}개\n\n"
                                 "Multi-hive 분석을 위해서는 최소 2개 이상의 파일이 필요합니다.\n\n"
                                 "'📂 파일 선택' 버튼으로 파일을 더 추가해주세요.")
            return
        
        # 선택된 파일을 multi_hive_files로 사용
        multi_hive_files = self.selected_files
        
        # 분석 시작
        try:
            self.results_text.config(state=tk.NORMAL)
            self.results_text.delete('1.0', tk.END)
            self.results_text.insert(tk.END, "🔄 Multi-Hive 분석 시작...\n\n")
            self.results_text.insert(tk.END, f"선택된 파일: {len(multi_hive_files)}개\n")
            for i, fp in enumerate(multi_hive_files, 1):
                self.results_text.insert(tk.END, f"  {i}. {os.path.basename(fp)}\n")
            self.results_text.insert(tk.END, "\n")
            self.root.update()
            
            # MultiHiveAnalyzer 생성
            analyzer = MultiHiveAnalyzer()
            
            # 각 파일 로드
            self.results_text.insert(tk.END, "📂 하이브 파일 로드 중...\n")
            loaded_hives = []
            
            for fp in multi_hive_files:
                # 파일 읽기
                with open(fp, 'rb') as f:
                    data = f.read()
                
                # Hive 타입 자동 감지
                parser = RegistryParser(data, fp)
                hive_type = parser.detect_hive_type()
                
                # 하이브 추가
                success = analyzer.add_hive(fp, hive_type)
                if success:
                    loaded_hives.append((os.path.basename(fp), hive_type))
                    self.results_text.insert(tk.END, f"  ✅ {os.path.basename(fp)} ({hive_type})\n")
                else:
                    self.results_text.insert(tk.END, f"  ❌ {os.path.basename(fp)} - 로드 실패\n")
                
                self.root.update()
            
            if not loaded_hives:
                messagebox.showerror("오류", "하이브 파일을 로드할 수 없습니다.")
                return
            
            self.results_text.insert(tk.END, f"\n✅ {len(loaded_hives)}개 하이브 로드 완료\n\n")
            self.root.update()
            
            # 상관관계 분석
            self.results_text.insert(tk.END, "🔍 상관관계 분석 중...\n")
            self.root.update()
            
            correlations = analyzer.find_correlations()
            self.results_text.insert(tk.END, f"✅ {len(correlations)}개 상관관계 발견\n\n")
            self.root.update()
            
            # 타임라인 생성
            self.results_text.insert(tk.END, "📅 타임라인 생성 중...\n")
            self.root.update()
            
            timeline = analyzer.build_timeline()
            self.results_text.insert(tk.END, f"✅ {len(timeline)}개 이벤트 추출\n\n")
            self.root.update()
            
            # 요약 정보
            summary = analyzer.get_summary()
            
            # AI 분석 (API 키가 설정된 경우)
            ai_result = None
            if self.api_key.get():
                self.results_text.insert(tk.END, "🤖 AI 기반 통합 분석 중...\n")
                self.root.update()
                
                # Multi-Hive 분석 결과를 AI로 분석
                # 모든 하이브의 findings를 합침
                all_findings = {}
                all_strings = []
                
                for hive_type, hive_data in analyzer.hives.items():
                    findings = hive_data.get('findings', {})
                    for artifact_type, artifacts in findings.items():
                        if artifact_type not in all_findings:
                            all_findings[artifact_type] = []
                        all_findings[artifact_type].extend(artifacts)
                    
                    # 문자열도 수집 (최대 200개씩)
                    if hive_data.get('parser'):
                        strings = hive_data['parser'].extract_strings()[:200]
                        all_strings.extend(strings)
                
                # AI 분석 실행
                try:
                    if self.api_provider.get() == 'gemini':
                        ai_result = AIAnalyzer.analyze_with_gemini(
                            self.api_key.get(),
                            'Multi-Hive',
                            all_strings[:1000],  # 최대 1000개 문자열
                            {
                                'summary': summary,
                                'correlations': correlations[:20],  # 상위 20개
                                'timeline': timeline[:50],  # 최근 50개
                                'artifact_counts': {k: len(v) for k, v in all_findings.items()}
                            }
                        )
                    else:
                        ai_result = AIAnalyzer.analyze_with_openai(
                            self.api_key.get(),
                            'Multi-Hive',
                            all_strings[:1000],
                            {
                                'summary': summary,
                                'correlations': correlations[:20],
                                'timeline': timeline[:50],
                                'artifact_counts': {k: len(v) for k, v in all_findings.items()}
                            }
                        )
                    
                    self.results_text.insert(tk.END, "✅ AI 분석 완료\n\n")
                    self.root.update()
                except Exception as e:
                    self.results_text.insert(tk.END, f"⚠️  AI 분석 실패: {str(e)}\n\n")
                    self.root.update()
            
            # 결과 표시 (analyzer 객체 전달)
            self.display_multi_hive_results(analyzer, loaded_hives, correlations, timeline, summary, ai_result)
            
            # 내보내기 버튼 활성화
            self.export_json_btn.config(state=tk.NORMAL)
            self.export_csv_btn.config(state=tk.NORMAL)
            
            # 분석 결과 저장
            self.analysis_results = {
                'type': 'multi-hive',
                'loaded_hives': loaded_hives,
                'correlations': correlations,
                'timeline': timeline,
                'summary': summary,
                'ai_analysis': ai_result if ai_result else None
            }
            
        except Exception as e:
            self.results_text.config(state=tk.DISABLED)
            messagebox.showerror("Error", f"Multi-hive analysis failed: {str(e)}")
    
    def display_multi_hive_results(self, analyzer, loaded_hives, correlations, timeline, summary, ai_result=None):
        """Multi-hive 분석 결과 표시 - 모든 아티팩트 상세 출력 + AI 분석 (v4.0)"""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete('1.0', tk.END)
        
        # 헤더
        self.results_text.insert(tk.END, "╔" + "═"*78 + "╗\n")
        self.results_text.insert(tk.END, f"║  Multi-Hive Analysis Results - FULL DETAILS{' '*33}║\n")
        self.results_text.insert(tk.END, "╚" + "═"*78 + "╝\n\n")
        
        # 로드된 하이브
        self.results_text.insert(tk.END, "═" * 80 + "\n")
        self.results_text.insert(tk.END, "📚 Loaded Registry Hives\n")
        self.results_text.insert(tk.END, "═" * 80 + "\n\n")
        
        for i, (filename, hive_type) in enumerate(loaded_hives, 1):
            self.results_text.insert(tk.END, f"  {i}. {filename} - {hive_type}\n")
        self.results_text.insert(tk.END, "\n")
        
        # 요약 정보
        self.results_text.insert(tk.END, "═" * 80 + "\n")
        self.results_text.insert(tk.END, "📊 Analysis Summary\n")
        self.results_text.insert(tk.END, "═" * 80 + "\n\n")
        
        self.results_text.insert(tk.END, f"Hive Count: {summary['hive_count']}\n")
        self.results_text.insert(tk.END, f"Total Artifacts: {summary['total_artifacts']}\n")
        self.results_text.insert(tk.END, f"Correlations Found: {summary['correlation_count']}\n")
        self.results_text.insert(tk.END, f"  └─ High Confidence: {summary['high_confidence_correlations']}\n")
        self.results_text.insert(tk.END, f"Timeline Events: {summary['timeline_events']}\n")
        self.results_text.insert(tk.END, "\n")
        
        # ===== 모든 하이브의 모든 아티팩트 상세 출력 =====
        self.results_text.insert(tk.END, "\n" + "#" * 80 + "\n")
        self.results_text.insert(tk.END, "#  DETAILED ARTIFACTS FROM ALL HIVES - 모든 아티팩트 상세 정보\n")
        self.results_text.insert(tk.END, "#" * 80 + "\n\n")
        
        # analyzer.hives를 순회하며 모든 findings 출력
        for hive_type, hive_data in analyzer.hives.items():
            hive_path = hive_data.get('path', 'Unknown')
            findings = hive_data.get('findings', {})
            
            self.results_text.insert(tk.END, "\n" + "="*80 + "\n")
            self.results_text.insert(tk.END, f"🗂️  HIVE: {hive_type.upper()} - {hive_path}\n")
            self.results_text.insert(tk.END, "="*80 + "\n\n")
            
            # 각 artifact type별로 모든 항목 출력
            for artifact_type, artifacts in findings.items():
                if not artifacts:
                    continue
                
                self.results_text.insert(tk.END, f"\n{'─'*80}\n")
                self.results_text.insert(tk.END, f"📌 {artifact_type.upper()} ({len(artifacts)} items)\n")
                self.results_text.insert(tk.END, f"{'─'*80}\n\n")
                
                # artifact type별로 다른 출력 포맷 적용
                if artifact_type == 'shimcache':
                    for i, item in enumerate(artifacts, 1):
                        self.results_text.insert(tk.END, f"[{i}] Path: {item.get('path', 'N/A')}\n")
                        self.results_text.insert(tk.END, f"    Last Modified: {item.get('lastModified', 'N/A')}\n")
                        if item.get('fileSize'):
                            self.results_text.insert(tk.END, f"    Size: {item.get('fileSize')}\n")
                        self.results_text.insert(tk.END, "\n")
                
                elif artifact_type == 'amcache':
                    for i, item in enumerate(artifacts, 1):
                        self.results_text.insert(tk.END, f"[{i}] Program: {item.get('programName', 'N/A')}\n")
                        self.results_text.insert(tk.END, f"    Path: {item.get('fullPath', 'N/A')}\n")
                        if item.get('sha1'):
                            self.results_text.insert(tk.END, f"    SHA1: {item.get('sha1')}\n")
                        if item.get('fileSize'):
                            self.results_text.insert(tk.END, f"    Size: {item.get('fileSize')} bytes\n")
                        if item.get('lastModified'):
                            self.results_text.insert(tk.END, f"    Modified: {item.get('lastModified')}\n")
                        if item.get('created'):
                            self.results_text.insert(tk.END, f"    Created: {item.get('created')}\n")
                        self.results_text.insert(tk.END, "\n")
                
                elif artifact_type == 'userassist':
                    for i, item in enumerate(artifacts, 1):
                        self.results_text.insert(tk.END, f"[{i}] Program: {item.get('programName', 'N/A')}\n")
                        self.results_text.insert(tk.END, f"    GUID: {item.get('guid', 'N/A')}\n")
                        self.results_text.insert(tk.END, f"    Run Count: {item.get('runCount', 0)}\n")
                        self.results_text.insert(tk.END, f"    Last Executed: {item.get('lastExecuted', 'N/A')}\n")
                        if item.get('focusCount'):
                            self.results_text.insert(tk.END, f"    Focus Count: {item.get('focusCount')}\n")
                        if item.get('focusTime'):
                            self.results_text.insert(tk.END, f"    Focus Time: {item.get('focusTime')}\n")
                        self.results_text.insert(tk.END, "\n")
                
                elif artifact_type == 'bam' or artifact_type == 'dam':
                    for i, item in enumerate(artifacts, 1):
                        self.results_text.insert(tk.END, f"[{i}] Path: {item.get('path', 'N/A')}\n")
                        self.results_text.insert(tk.END, f"    Last Executed: {item.get('lastExecuted', 'N/A')}\n")
                        if item.get('sid'):
                            self.results_text.insert(tk.END, f"    SID: {item.get('sid')}\n")
                        self.results_text.insert(tk.END, "\n")
                
                elif artifact_type == 'usb':
                    for i, item in enumerate(artifacts, 1):
                        self.results_text.insert(tk.END, f"[{i}] Device: {item.get('deviceName', 'N/A')}\n")
                        self.results_text.insert(tk.END, f"    Serial: {item.get('serialNumber', 'N/A')}\n")
                        if item.get('vendor'):
                            self.results_text.insert(tk.END, f"    Vendor: {item.get('vendor')}\n")
                        if item.get('product'):
                            self.results_text.insert(tk.END, f"    Product: {item.get('product')}\n")
                        if item.get('firstConnected'):
                            self.results_text.insert(tk.END, f"    First Connected: {item.get('firstConnected')}\n")
                        if item.get('lastConnected'):
                            self.results_text.insert(tk.END, f"    Last Connected: {item.get('lastConnected')}\n")
                        self.results_text.insert(tk.END, "\n")
                
                elif artifact_type == 'network':
                    for i, item in enumerate(artifacts, 1):
                        self.results_text.insert(tk.END, f"[{i}] Profile: {item.get('profileName', 'N/A')}\n")
                        if item.get('ssid'):
                            self.results_text.insert(tk.END, f"    SSID: {item.get('ssid')}\n")
                        if item.get('dateCreated'):
                            self.results_text.insert(tk.END, f"    Created: {item.get('dateCreated')}\n")
                        if item.get('lastConnected'):
                            self.results_text.insert(tk.END, f"    Last Connected: {item.get('lastConnected')}\n")
                        self.results_text.insert(tk.END, "\n")
                
                elif artifact_type == 'shellbags':
                    for i, item in enumerate(artifacts, 1):
                        self.results_text.insert(tk.END, f"[{i}] Path: {item.get('path', 'N/A')}\n")
                        if item.get('shellbagType'):
                            self.results_text.insert(tk.END, f"    Type: {item.get('shellbagType')}\n")
                        if item.get('accessed'):
                            self.results_text.insert(tk.END, f"    Accessed: {item.get('accessed')}\n")
                        if item.get('modified'):
                            self.results_text.insert(tk.END, f"    Modified: {item.get('modified')}\n")
                        self.results_text.insert(tk.END, "\n")
                
                elif artifact_type == 'muicache':
                    for i, item in enumerate(artifacts, 1):
                        self.results_text.insert(tk.END, f"[{i}] Path: {item.get('path', 'N/A')}\n")
                        if item.get('friendlyName'):
                            self.results_text.insert(tk.END, f"    Name: {item.get('friendlyName')}\n")
                        self.results_text.insert(tk.END, "\n")
                
                elif artifact_type == 'prefetch':
                    for i, item in enumerate(artifacts, 1):
                        self.results_text.insert(tk.END, f"[{i}] File: {item.get('fileName', 'N/A')}\n")
                        self.results_text.insert(tk.END, f"    Path: {item.get('path', 'N/A')}\n")
                        if item.get('runCount'):
                            self.results_text.insert(tk.END, f"    Run Count: {item.get('runCount')}\n")
                        if item.get('lastRun'):
                            self.results_text.insert(tk.END, f"    Last Run: {item.get('lastRun')}\n")
                        self.results_text.insert(tk.END, "\n")
                
                elif artifact_type == 'lnk':
                    for i, item in enumerate(artifacts, 1):
                        self.results_text.insert(tk.END, f"[{i}] File: {item.get('fileName', 'N/A')}\n")
                        self.results_text.insert(tk.END, f"    Target: {item.get('targetPath', 'N/A')}\n")
                        if item.get('created'):
                            self.results_text.insert(tk.END, f"    Created: {item.get('created')}\n")
                        if item.get('modified'):
                            self.results_text.insert(tk.END, f"    Modified: {item.get('modified')}\n")
                        if item.get('accessed'):
                            self.results_text.insert(tk.END, f"    Accessed: {item.get('accessed')}\n")
                        self.results_text.insert(tk.END, "\n")
                
                elif artifact_type == 'installed_software':
                    for i, item in enumerate(artifacts, 1):
                        self.results_text.insert(tk.END, f"[{i}] Software: {item.get('displayName', 'N/A')}\n")
                        if item.get('version'):
                            self.results_text.insert(tk.END, f"    Version: {item.get('version')}\n")
                        if item.get('publisher'):
                            self.results_text.insert(tk.END, f"    Publisher: {item.get('publisher')}\n")
                        if item.get('installDate'):
                            self.results_text.insert(tk.END, f"    Install Date: {item.get('installDate')}\n")
                        if item.get('installLocation'):
                            self.results_text.insert(tk.END, f"    Location: {item.get('installLocation')}\n")
                        self.results_text.insert(tk.END, "\n")
                
                elif artifact_type == 'security_software':
                    for i, item in enumerate(artifacts, 1):
                        self.results_text.insert(tk.END, f"[{i}] Product: {item.get('productName', 'N/A')}\n")
                        if item.get('enabled'):
                            self.results_text.insert(tk.END, f"    Enabled: {item.get('enabled')}\n")
                        if item.get('upToDate'):
                            self.results_text.insert(tk.END, f"    Up to Date: {item.get('upToDate')}\n")
                        self.results_text.insert(tk.END, "\n")
                
                elif artifact_type == 'typed_paths':
                    for i, item in enumerate(artifacts, 1):
                        self.results_text.insert(tk.END, f"[{i}] Path: {item.get('path', 'N/A')}\n")
                        if item.get('timestamp'):
                            self.results_text.insert(tk.END, f"    Accessed: {item.get('timestamp')}\n")
                        if item.get('order'):
                            self.results_text.insert(tk.END, f"    Order: {item.get('order')}\n")
                        self.results_text.insert(tk.END, "\n")
                
                elif artifact_type == 'recent_apps':
                    for i, item in enumerate(artifacts, 1):
                        self.results_text.insert(tk.END, f"[{i}] App: {item.get('appName', 'N/A')}\n")
                        if item.get('path'):
                            self.results_text.insert(tk.END, f"    Path: {item.get('path')}\n")
                        if item.get('lastAccess'):
                            self.results_text.insert(tk.END, f"    Last Access: {item.get('lastAccess')}\n")
                        if item.get('launchCount'):
                            self.results_text.insert(tk.END, f"    Launch Count: {item.get('launchCount')}\n")
                        self.results_text.insert(tk.END, "\n")
                
                elif artifact_type == 'services':
                    for i, item in enumerate(artifacts, 1):
                        self.results_text.insert(tk.END, f"[{i}] Service: {item.get('serviceName', 'N/A')}\n")
                        if item.get('displayName'):
                            self.results_text.insert(tk.END, f"    Display Name: {item.get('displayName')}\n")
                        if item.get('imagePath'):
                            self.results_text.insert(tk.END, f"    Image Path: {item.get('imagePath')}\n")
                        if item.get('startType'):
                            self.results_text.insert(tk.END, f"    Start Type: {item.get('startType')}\n")
                        if item.get('serviceType'):
                            self.results_text.insert(tk.END, f"    Service Type: {item.get('serviceType')}\n")
                        if item.get('description'):
                            self.results_text.insert(tk.END, f"    Description: {item.get('description')}\n")
                        self.results_text.insert(tk.END, "\n")
                
                elif artifact_type == 'wlan_profiles':
                    for i, item in enumerate(artifacts, 1):
                        self.results_text.insert(tk.END, f"[{i}] SSID: {item.get('ssid', 'N/A')}\n")
                        if item.get('profileName'):
                            self.results_text.insert(tk.END, f"    Profile: {item.get('profileName')}\n")
                        if item.get('authentication'):
                            self.results_text.insert(tk.END, f"    Auth: {item.get('authentication')}\n")
                        if item.get('encryption'):
                            self.results_text.insert(tk.END, f"    Encryption: {item.get('encryption')}\n")
                        if item.get('connectionMode'):
                            self.results_text.insert(tk.END, f"    Connection Mode: {item.get('connectionMode')}\n")
                        self.results_text.insert(tk.END, "\n")
                
                elif artifact_type == 'timezone':
                    for i, item in enumerate(artifacts, 1):
                        self.results_text.insert(tk.END, f"[{i}] Timezone: {item.get('timezone', 'N/A')}\n")
                        if item.get('displayName'):
                            self.results_text.insert(tk.END, f"    Display Name: {item.get('displayName')}\n")
                        if item.get('standardName'):
                            self.results_text.insert(tk.END, f"    Standard Name: {item.get('standardName')}\n")
                        if item.get('daylightName'):
                            self.results_text.insert(tk.END, f"    Daylight Name: {item.get('daylightName')}\n")
                        if item.get('bias'):
                            self.results_text.insert(tk.END, f"    Bias: {item.get('bias')} minutes\n")
                        self.results_text.insert(tk.END, "\n")
                
                # 기타 아티팩트는 기본 포맷으로 출력
                else:
                    for i, item in enumerate(artifacts, 1):
                        self.results_text.insert(tk.END, f"[{i}] {item}\n\n")
        
        # ===== 상관관계 결과 (모든 항목 출력) =====
        if correlations:
            self.results_text.insert(tk.END, "\n" + "#" * 80 + "\n")
            self.results_text.insert(tk.END, "#  CROSS-HIVE CORRELATIONS - 모든 상관관계\n")
            self.results_text.insert(tk.END, "#" * 80 + "\n\n")
            
            for i, corr in enumerate(correlations, 1):
                corr_type = corr.get('type', 'Unknown')
                confidence = corr.get('confidence', 'UNKNOWN')
                significance = corr.get('significance', '')
                
                # Confidence 이모지
                conf_emoji = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(confidence, '⚪')
                
                self.results_text.insert(tk.END, f"{conf_emoji} [{i}] [{confidence}] {corr_type}\n")
                self.results_text.insert(tk.END, f"     {significance}\n")
                
                # 세부 정보 (타입별로 다르게 표시)
                if corr_type == 'ShimCache-Amcache Match':
                    program = corr.get('program', 'N/A')
                    path = corr.get('path', 'N/A')
                    self.results_text.insert(tk.END, f"     Program: {program}\n")
                    self.results_text.insert(tk.END, f"     Path: {path}\n")
                    if corr.get('sha1'):
                        self.results_text.insert(tk.END, f"     SHA1: {corr['sha1']}\n")
                
                elif corr_type == 'User Activity Pattern':
                    program = corr.get('program', 'N/A')
                    sources = corr.get('sources', [])
                    run_count = corr.get('total_run_count', 0)
                    self.results_text.insert(tk.END, f"     Program: {program}\n")
                    self.results_text.insert(tk.END, f"     Sources: {', '.join(sources)}\n")
                    if run_count:
                        self.results_text.insert(tk.END, f"     Total Runs: {run_count}\n")
                
                elif corr_type == 'USB Device Usage':
                    usb_count = len(corr.get('usb_devices', []))
                    file_count = corr.get('total_file_count', 0)
                    self.results_text.insert(tk.END, f"     USB Devices: {usb_count}\n")
                    self.results_text.insert(tk.END, f"     Files Accessed: {file_count}\n")
                
                elif corr_type == 'Network Activity':
                    net_count = corr.get('network_profiles', 0)
                    wifi_count = corr.get('wlan_profiles', 0)
                    self.results_text.insert(tk.END, f"     Network Profiles: {net_count}\n")
                    self.results_text.insert(tk.END, f"     WiFi Profiles: {wifi_count}\n")
                
                elif corr_type == 'Autorun Software Correlation':
                    matched = corr.get('matched_count', 0)
                    self.results_text.insert(tk.END, f"     Matched Programs: {matched}\n")
                
                elif corr_type == 'Services-Software Correlation':
                    matched = corr.get('matched_count', 0)
                    self.results_text.insert(tk.END, f"     Matched Services: {matched}\n")
                
                elif corr_type == 'Timezone Information':
                    tz = corr.get('timezone', 'N/A')
                    offset = corr.get('utc_offset', 'N/A')
                    self.results_text.insert(tk.END, f"     Timezone: {tz} ({offset})\n")
                
                self.results_text.insert(tk.END, "\n")
        
        # ===== 타임라인 (모든 이벤트 출력) =====
        if timeline:
            self.results_text.insert(tk.END, "\n" + "#" * 80 + "\n")
            self.results_text.insert(tk.END, f"#  UNIFIED TIMELINE - 모든 {len(timeline)}개 이벤트\n")
            self.results_text.insert(tk.END, "#" * 80 + "\n\n")
            
            # 모든 이벤트를 시간순으로 정렬하여 표시 (타임스탬프 타입 안전 처리)
            def safe_sort_key(event):
                ts = event.get('timestamp', '')
                if isinstance(ts, str):
                    return ts
                else:
                    return str(ts)
            
            sorted_timeline = sorted(timeline, key=safe_sort_key, reverse=True)
            
            for i, event in enumerate(sorted_timeline, 1):
                ts = event.get('timestamp', 'N/A')
                desc = event.get('description', 'Unknown event')
                hive = event.get('hive', 'N/A')
                artifact = event.get('artifact_type', 'N/A')
                
                self.results_text.insert(tk.END, f"{i:4d}. [{ts}] {desc}\n")
                self.results_text.insert(tk.END, f"        Source: {hive} - {artifact}\n")
                
                # 추가 정보가 있으면 표시
                if event.get('path'):
                    self.results_text.insert(tk.END, f"        Path: {event['path']}\n")
                if event.get('details'):
                    self.results_text.insert(tk.END, f"        Details: {event['details']}\n")
                
                self.results_text.insert(tk.END, "\n")
        
        # ===== AI 분석 결과 =====
        if ai_result:
            self.results_text.insert(tk.END, "\n" + "#" * 80 + "\n")
            self.results_text.insert(tk.END, "#  🤖 AI-POWERED FORENSIC ANALYSIS - AI 기반 통합 포렌식 분석\n")
            self.results_text.insert(tk.END, "#" * 80 + "\n\n")
            
            if 'error' in ai_result:
                self.results_text.insert(tk.END, f"❌ AI Analysis Error: {ai_result['error']}\n\n")
            else:
                # Summary (요약)
                if ai_result.get('summary'):
                    self.results_text.insert(tk.END, "═" * 80 + "\n")
                    self.results_text.insert(tk.END, "📊 Summary (요약)\n")
                    self.results_text.insert(tk.END, "═" * 80 + "\n\n")
                    self.results_text.insert(tk.END, f"{ai_result['summary']}\n\n")
                
                # Suspicious Activities (의심스러운 활동)
                if ai_result.get('suspiciousActivities'):
                    self.results_text.insert(tk.END, "═" * 80 + "\n")
                    self.results_text.insert(tk.END, "⚠️  Suspicious Activities (의심스러운 활동)\n")
                    self.results_text.insert(tk.END, "═" * 80 + "\n\n")
                    for i, activity in enumerate(ai_result['suspiciousActivities'], 1):
                        self.results_text.insert(tk.END, f"{i}. {activity}\n")
                    self.results_text.insert(tk.END, "\n")
                
                # Timeline (타임라인)
                if ai_result.get('timeline'):
                    self.results_text.insert(tk.END, "═" * 80 + "\n")
                    self.results_text.insert(tk.END, "⏱️  AI-Generated Timeline (AI 생성 타임라인)\n")
                    self.results_text.insert(tk.END, "═" * 80 + "\n\n")
                    for i, item in enumerate(ai_result['timeline'], 1):
                        timestamp = item.get('timestamp', 'N/A')
                        event = item.get('event', 'Unknown')
                        self.results_text.insert(tk.END, f"{i}. [{timestamp}] {event}\n")
                    self.results_text.insert(tk.END, "\n")
                
                # Recommendations (권장사항)
                if ai_result.get('recommendations'):
                    self.results_text.insert(tk.END, "═" * 80 + "\n")
                    self.results_text.insert(tk.END, "💡 Security Recommendations (보안 권장사항)\n")
                    self.results_text.insert(tk.END, "═" * 80 + "\n\n")
                    for i, rec in enumerate(ai_result['recommendations'], 1):
                        self.results_text.insert(tk.END, f"{i}. {rec}\n")
                    self.results_text.insert(tk.END, "\n")
        
        self.results_text.insert(tk.END, "\n" + "═" * 80 + "\n")
        if ai_result:
            self.results_text.insert(tk.END, "✅ Multi-Hive 전체 상세 분석 + AI 분석 완료! (생략 없음)\n")
        else:
            self.results_text.insert(tk.END, "✅ Multi-Hive 전체 상세 분석 완료! (생략 없음)\n")
            self.results_text.insert(tk.END, "💡 TIP: API 키를 입력하면 AI 기반 통합 분석도 제공됩니다.\n")
        self.results_text.insert(tk.END, "═" * 80 + "\n")
        
        self.results_text.config(state=tk.DISABLED)


