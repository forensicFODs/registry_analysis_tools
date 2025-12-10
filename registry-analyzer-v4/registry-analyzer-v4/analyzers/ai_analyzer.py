#!/usr/bin/env python3
"""
AI Analyzer - AI 기반 포렌식 분석
Version: 4.0
"""

import json
import requests
from typing import Dict, List


class AIAnalyzer:
    """AI 기반 분석기"""
    
    @staticmethod
    def analyze_with_gemini(api_key: str, hive_type: str, strings: List[str], raw_findings: Dict) -> Dict:
        """Gemini API로 분석"""
        prompt = f"""Windows 레지스트리 {hive_type} 하이브의 포렌식 데이터를 분석하세요.

바이너리 분석에서 추출된 원시 데이터:
{json.dumps(raw_findings, indent=2)}

추출된 문자열 (처음 30개):
{chr(10).join(strings)}

이 데이터를 기반으로 다음 내용을 포함한 포렌식 분석을 제공하세요:
- 발견된 활동에 대한 요약
- 의심스럽거나 주목할 만한 항목들
- 이벤트 타임라인
- 보안 권장사항

**반드시 한국어로 답변하고**, 다음 JSON 구조만 반환하세요:
{{
  "summary": "간단한 요약 (한국어)",
  "suspiciousActivities": ["항목1 (한국어)", "항목2 (한국어)"],
  "timeline": [{{"timestamp": "2024-01-01", "event": "설명 (한국어)"}}],
  "recommendations": ["권장사항1 (한국어)", "권장사항2 (한국어)"]
}}"""
        
        try:
            response = requests.post(
                f'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}',
                headers={'Content-Type': 'application/json'},
                json={
                    'contents': [{'parts': [{'text': prompt}]}],
                    'generationConfig': {
                        'temperature': 0.1,
                        'maxOutputTokens': 4096
                    }
                },
                timeout=30
            )
            
            if response.status_code != 200:
                return {'error': f'API error: {response.status_code}'}
            
            data = response.json()
            
            if 'candidates' not in data or not data['candidates']:
                return {'error': 'Invalid API response'}
            
            content = data['candidates'][0]['content']['parts'][0]['text']
            
            # Clean JSON
            content = content.strip()
            content = content.replace('```json', '').replace('```', '').strip()
            
            json_start = content.find('{')
            json_end = content.rfind('}')
            
            if json_start != -1 and json_end != -1:
                content = content[json_start:json_end+1]
            
            return json.loads(content)
            
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def analyze_with_openai(api_key: str, hive_type: str, strings: List[str], raw_findings: Dict) -> Dict:
        """OpenAI API로 분석"""
        prompt = f"""Windows 레지스트리 {hive_type} 하이브의 포렌식 데이터를 분석하세요.

추출된 원시 데이터: {json.dumps(raw_findings, indent=2)}

추출된 문자열: {chr(10).join(strings)}

**반드시 한국어로 답변하고**, 다음 항목을 포함한 JSON 형식으로 포렌식 분석을 제공하세요:
- summary: 요약 (한국어)
- suspiciousActivities: 의심스러운 활동 목록 (한국어)
- timeline: 타임라인 (한국어)
- recommendations: 권장사항 (한국어)"""
        
        try:
            response = requests.post(
                'https://api.openai.com/v1/chat/completions',
                headers={
                    'Content-Type': 'application/json',
                    'Authorization': f'Bearer {api_key}'
                },
                json={
                    'model': 'gpt-4o-mini',
                    'messages': [
                        {'role': 'system', 'content': '당신은 Windows 레지스트리 포렌식 전문가입니다. 반드시 한국어로 답변하고, 유효한 JSON 형식만 반환하세요.'},
                        {'role': 'user', 'content': prompt}
                    ],
                    'temperature': 0.1,
                    'max_tokens': 4000
                },
                timeout=30
            )
            
            if response.status_code != 200:
                return {'error': f'API error: {response.status_code}'}
            
            data = response.json()
            content = data['choices'][0]['message']['content']
            
            # Clean JSON
            content = content.strip().replace('```json', '').replace('```', '').strip()
            json_start = content.find('{')
            json_end = content.rfind('}')
            
            if json_start != -1 and json_end != -1:
                content = content[json_start:json_end+1]
            
            return json.loads(content)
            
        except Exception as e:
            return {'error': str(e)}


