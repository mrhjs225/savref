# 취약점 수정 LLM 기술 구현 방법

이 프로젝트는 LLM(Large Language Model)을 사용하여 Java 코드에서 발견된 보안 취약점을 자동으로 수정하는 기술을 구현합니다. 코드 실행 및 평가를 위한 종합적인 파이프라인을 제공합니다.

## 프로젝트 구조

```
run/
├── main.py                     # 전체 파이프라인을 실행하는 메인 스크립트
├── config.py                   # 설정 파라미터
├── utils/                      # 유틸리티 모듈
│   ├── dataset.py              # 데이터셋 로딩 및 전처리
│   ├── file_utils.py           # 파일 처리 유틸리티
│   └── evaluation.py           # 평가 유틸리티
├── extraction/                 # 코드 추출 모듈
│   └── code_extractor.py       # 코드 및 정보 추출 (Step 1)
├── graph/                      # 그래프 관련 모듈
│   ├── graph_builder.py        # 보안 강화 그래프 구축 (Step 2)
│   └── graph_processor.py      # 그래프 정보 처리 (Step 3)
├── prompting/                  # 프롬프트 관련 모듈
│   └── prompt_builder.py       # 프롬프트 구성 (Step 4)
├── inference/                  # 추론 관련 모듈
│   ├── model_loader.py         # 모델 로딩 유틸리티
│   └── inference.py            # LLM 추론 (Step 5)
├── evaluation/                 # 평가 관련 모듈
│   ├── code_integrator.py      # 코드 통합 (Step 6)
│   └── evaluator.py            # 자동 평가 (Step 7)
└── resources/                  # 리소스 파일
    ├── prompt_templates/       # 프롬프트 템플릿
    │   ├── system_prompt.txt   # 시스템 프롬프트 템플릿
    │   └── user_prompt.txt     # 사용자 프롬프트 템플릿
    ├── codeql_queries/         # CodeQL 쿼리
    │   ├── java_taint_flow.ql  # Taint Flow 분석용 쿼리
    │   └── java_security_patterns.ql # 보안 패턴 분석용 쿼리
    └── semgrep_rules/          # Semgrep 규칙
        └── java_security_rules.yaml # Java 보안 규칙
```

## 설치 요구사항

1. Python 3.8 이상
2. 필수 Python 패키지:
   - pandas
   - numpy
   - networkx
   - torch (SLM을 위해)
   - transformers (SLM을 위해)
   - openai (OpenAI API를 위해)
   - anthropic (Anthropic API를 위해)
   - javalang (Java 파싱을 위해)

3. 외부 도구 (선택적):
   - Joern (CPG 생성)
   - CodeQL (취약점 분석)
   - Semgrep (패턴 매칭)

## 설치 방법

1. 저장소 복제:
```bash
git clone https://github.com/yourusername/vulnerability-fixing-llm.git
cd vulnerability-fixing-llm
```

2. 의존성 설치:
```bash
pip install -r requirements.txt
```

3. 외부 도구 설치 (선택적):
   - Joern: https://github.com/joernio/joern#installation
   - CodeQL: https://github.com/github/codeql-cli-binaries/releases
   - Semgrep: `pip install semgrep`

4. 설정 수정:
   - `run/config.py` 파일을 수정하여 모델 설정, 외부 도구 경로 등을 지정합니다.

## 사용 방법

### 단일 취약점 분석 및 수정

```bash
python -m run.main --bug_id <버그_ID> --model_type openai --model_size large --use_graph
```

### 모든 취약점 처리

```bash
python -m run.main --model_type openai --model_size large --use_graph
```

### 그래프 정보 없이 실행

```bash
python -m run.main --bug_id <버그_ID> --model_type openai --model_size large
```

### 로컬 SLM 사용

```bash
python -m run.main --bug_id <버그_ID> --model_type local_slm --model_size 10b
```

## 주요 기능

1. **취약점 정보 추출**: 데이터셋에서 취약점 정보, 코드, 메타데이터를 추출합니다.
2. **보안 강화 그래프 구축**: Joern, CodeQL, Semgrep을 사용하여 코드 분석 그래프를 구축합니다.
3. **프롬프트 생성**: 추출된 정보와 그래프 정보를 바탕으로 LLM에 전달할 프롬프트를 생성합니다.
4. **LLM 추론**: 다양한 모델(OpenAI, Anthropic, 로컬 SLM)을 사용하여 수정된 코드를 생성합니다.
5. **코드 통합**: 생성된 코드를 원본 프로젝트에 통합합니다.
6. **평가**: 코드의 기능성, 보안성, 견고성, 품질을 평가하고 결과를 보고합니다.

## 확장 방법

1. **새로운 모델 추가**: `inference/model_loader.py` 및 `inference/inference.py`를 수정하여 새로운 LLM 모델을 추가할 수 있습니다.
2. **Semgrep 규칙 추가**: `resources/semgrep_rules/` 디렉토리에 새로운 규칙 파일을 추가하여 다양한 취약점 패턴을 탐지할 수 있습니다.
3. **CodeQL 쿼리 추가**: `resources/codeql_queries/` 디렉토리에 새로운 쿼리 파일을 추가하여 더 복잡한 취약점 패턴을 분석할 수 있습니다.
4. **평가 방법 확장**: `evaluation/evaluator.py`를 수정하여 새로운 평가 메트릭을 추가할 수 있습니다.

## 데이터셋 형식

이 프로젝트는 다음과 같은 구조의 pickle 파일로 저장된 데이터셋을 사용합니다:

```
{
  'ID': 버그 식별자,
  'before_context': 취약점 코드 앞의 메소드 코드,
  'after_context': 취약점 코드 뒤의 메소드 코드,
  'summary': 메소드 docstring,
  'target_code': 수정된(안전한) 코드,
  'Title': 취약점 CWE 제목,
  'Description': 취약점 설명,
  'Extended Description': 취약점 상세 설명
}
```

또한 파일 구조는 다음과 같습니다:
```
dataset/
  ├── file/
  │   ├── 버그ID1/
  │   │   ├── before.java (취약한 버전)
  │   │   └── after.java (수정된 버전)
  │   ├── 버그ID2/
  │   │   ├── before.java
  │   │   └── after.java
  │   └── ...
  └── avr_dataset.pkl (메타데이터)
```
