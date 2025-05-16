"""
취약점 수정을 위한 LLM 프롬프트 구성 모듈
"""

import os
import logging
from pathlib import Path

from run.config import (
    PROMPT_TEMPLATES_DIR,
    SYSTEM_PROMPT_FILE,
    USER_PROMPT_FILE,
    MODEL_SIZE,
    USE_GRAPH_INFO
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class PromptBuilder:
    """LLM 프롬프트를 구성하는 클래스"""
    
    def __init__(self, templates_dir=PROMPT_TEMPLATES_DIR):
        """
        초기화
        
        Args:
            templates_dir: 프롬프트 템플릿 디렉토리
        """
        self.templates_dir = Path(templates_dir)
        self.system_prompt = self._load_template(SYSTEM_PROMPT_FILE)
        self.user_prompt = self._load_template(USER_PROMPT_FILE)
    
    def _load_template(self, template_path):
        """
        템플릿 파일 로드
        
        Args:
            template_path: 템플릿 파일 경로
            
        Returns:
            템플릿 문자열 또는 None
        """
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logger.error(f"템플릿 로드 오류 ({template_path}): {e}")
            # 기본 템플릿 제공
            if template_path.name == "system_prompt.txt":
                return self._get_default_system_prompt()
            elif template_path.name == "user_prompt.txt":
                return self._get_default_user_prompt()
            return None
    
    def _get_default_system_prompt(self):
        """기본 시스템 프롬프트 반환"""
        return """당신은 취약점 수정 전문가입니다. Java 코드의 보안 취약점을 안전하게 수정해야 합니다.
취약점이 있는 코드와 그 정보를 제공받을 것입니다. 취약점을 수정한 코드를 제공해주세요.
수정된 코드는 기능을 유지하면서 보안 취약점을 제거해야 합니다."""
    
    def _get_default_user_prompt(self):
        """기본 사용자 프롬프트 반환"""
        return """다음은 취약점이 있는 Java 코드입니다:

```java
{vulnerable_method}
```

이 코드는 다음과 같은 취약점이 있습니다:
- 취약점 ID: {cwe_id}
- 취약점 설명: {description}

{graph_info}

취약점을 수정한 코드를 제공해주세요. 코드는 전체 메소드를 포함해야 합니다."""
    
    def build_prompt(self, vuln_info, graph_info_text=None, model_size=MODEL_SIZE):
        """
        프롬프트 구성
        
        Args:
            vuln_info: 취약점 정보 딕셔너리
            graph_info_text: 그래프 정보 텍스트 (None이면 사용하지 않음)
            model_size: 모델 크기 ("1b", "10b", "large")
            
        Returns:
            구성된 프롬프트 딕셔너리 (system, user)
        """
        # 기본 템플릿 복사
        system_prompt = self.system_prompt
        user_prompt = self.user_prompt
        
        # 모델 크기에 따라 시스템 프롬프트 조정
        if model_size == "1b":
            system_prompt = "당신은 취약점 수정 전문가입니다. 다음 Java 코드의 보안 취약점을 수정해주세요."
        
        # 사용자 프롬프트에 정보 삽입
        user_prompt = user_prompt.format(
            vulnerable_method=vuln_info.get('vulnerable_method', ''),
            cwe_id=vuln_info.get('cwe_id', ''),
            description=vuln_info.get('description', ''),
            graph_info=graph_info_text if USE_GRAPH_INFO and graph_info_text else ""
        )
        
        return {
            "system": system_prompt,
            "user": user_prompt
        }
    
    def build_chat_completion_messages(self, vuln_info, graph_info_text=None, model_size=MODEL_SIZE):
        """
        Chat Completion API 메시지 포맷으로 프롬프트 구성
        
        Args:
            vuln_info: 취약점 정보 딕셔너리
            graph_info_text: 그래프 정보 텍스트 (None이면 사용하지 않음)
            model_size: 모델 크기 ("1b", "10b", "large")
            
        Returns:
            Chat Completion API 메시지 리스트
        """
        prompt = self.build_prompt(vuln_info, graph_info_text, model_size)
        
        messages = [
            {"role": "system", "content": prompt["system"]},
            {"role": "user", "content": prompt["user"]}
        ]
        
        return messages
    
    def build_prompt_text(self, vuln_info, graph_info_text=None, model_size=MODEL_SIZE):
        """
        텍스트 포맷으로 프롬프트 구성 (SLM용)
        
        Args:
            vuln_info: 취약점 정보 딕셔너리
            graph_info_text: 그래프 정보 텍스트 (None이면 사용하지 않음)
            model_size: 모델 크기 ("1b", "10b", "large")
            
        Returns:
            프롬프트 텍스트
        """
        prompt = self.build_prompt(vuln_info, graph_info_text, model_size)
        
        # SLM 모델을 위한 형식
        prompt_text = f"""[SYSTEM]
{prompt["system"]}

[USER]
{prompt["user"]}

[ASSISTANT]
"""
        
        return prompt_text