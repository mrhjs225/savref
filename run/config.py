"""
취약점 수정을 위한 LLM 기반 기술 실험에 필요한 설정 파라미터
"""

import os
from pathlib import Path

# 기본 경로 설정
BASE_DIR = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATASET_DIR = BASE_DIR / "dataset"
RESULTS_DIR = BASE_DIR / "results"
ANALYSIS_DIR = BASE_DIR / "analysis"

# 데이터셋 설정
DATASET_FILE = DATASET_DIR / "avr_dataset.pkl"
FILES_DIR = DATASET_DIR / "file"

# 외부 도구 경로 설정 (실제 경로로 수정 필요)
JOERN_PATH = "/path/to/joern"  # Joern 실행 파일 경로
CODEQL_PATH = "/path/to/codeql"  # CodeQL 실행 파일 경로
SEMGREP_PATH = "/path/to/semgrep"  # Semgrep 실행 파일 경로

# 코드 QL 쿼리 설정
CODEQL_QUERIES_DIR = BASE_DIR / "run" / "resources" / "codeql_queries"
TAINT_FLOW_QUERY = CODEQL_QUERIES_DIR / "java_taint_flow.ql"
SECURITY_PATTERNS_QUERY = CODEQL_QUERIES_DIR / "java_security_patterns.ql"

# Semgrep 룰 설정
SEMGREP_RULES_DIR = BASE_DIR / "run" / "resources" / "semgrep_rules"
SEMGREP_RULES_FILE = SEMGREP_RULES_DIR / "java_security_rules.yaml"

# 모델 설정
# 모델 타입 옵션: "openai", "anthropic", "local_slm" (소규모 언어 모델)
MODEL_TYPE = "openai"
MODEL_SIZE = "large"  # "1b", "10b", "large" 중 하나 선택

# OpenAI API 설정
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_MODEL = "gpt-4o-mini"  # 또는 다른 OpenAI 모델

# Anthropic API 설정
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = "claude-3-opus-20240229"  # 또는 다른 Anthropic 모델

# 로컬 SLM 설정
SLM_MODEL_PATH = "/path/to/slm_model"  # 로컬 모델 경로
SLM_MODEL_SIZE = "10b"  # "1b" 또는 "10b"

# 프롬프트 설정
PROMPT_TEMPLATES_DIR = BASE_DIR / "run" / "resources" / "prompt_templates"
SYSTEM_PROMPT_FILE = PROMPT_TEMPLATES_DIR / "system_prompt.txt"
USER_PROMPT_FILE = PROMPT_TEMPLATES_DIR / "user_prompt.txt"

# 평가 설정
EVALUATION_TIMEOUT = 300  # 평가 타임아웃 (초)
USE_GRAPH_INFO = True  # 그래프 정보 사용 여부