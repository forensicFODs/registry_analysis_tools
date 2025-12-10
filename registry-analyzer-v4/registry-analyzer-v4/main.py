#!/usr/bin/env python3
"""
Windows Registry Forensic Analyzer v4.0
메인 실행 파일 - 완전히 분리된 객체 지향 구조
AI 기반 포렌식 분석 및 전체 상세 출력 지원

사용법:
    python3 main.py
"""

import tkinter as tk
import sys
import os

# AI API 클라이언트 자동 설치
try:
    import requests
except ImportError:
    print("Installing required packages...")
    os.system(f"{sys.executable} -m pip install requests")
    import requests

# 모듈 import
from gui.main_window import RegistryForensicGUI


def main():
    """메인 함수"""
    root = tk.Tk()
    app = RegistryForensicGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
