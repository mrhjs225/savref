# 취약점 수정 LLM 기술 사용 설명서

이 문서는 취약점 수정 LLM 기술 구현 프로젝트의 상세한 사용 방법을 안내합니다.

## 환경 설정

1. 필요한 패키지 설치:
```bash
pip install -r requirements.txt
```

2. 환경 변수 설정:
`.env.template` 파일을 `.env`로 복사하고 API 키 및 경로 설정을 수정합니다.
```bash
cp .env.template .env
# .env 파일을 편집하여 API 키 및 경로 설정
```

3. 외부 도구 설치 (선택 사항):
   - Joern: [설치 가이드](https://joern.io/docs/)를 참조하세요.
   - CodeQL: [GitHub 릴리스](https://github.com/github/codeql-cli-binaries/releases)에서 다운로드하세요.
   - Semgrep: `pip install semgrep`로 설치합니다.

## 기본 사용법

### 단일 취약점 수정하기

특정 취약점 ID에 대해 수정 실행:
```bash
./run.sh --bug_id 버그ID --model_type openai --model_size large --use_graph
```

예:
```bash
./run.sh --bug_id CWE-89-01 --model_type openai --model_size large --use_graph
```

### 전체 데이터셋 실행하기

모든 취약점에 대해 수정 실행:
```bash
./run.sh --model_type openai --model_size large --use_graph
```

### 그래프 정보 없이 실행하기

그래프 정보 생성 단계를 건너뛰고 실행:
```bash
./run.sh --bug_id 버그ID --model_type openai --model_size large
```

### 평가 없이 실행하기

수정 생성 후 평가 단계를 건너뛰고 실행:
```bash
./run.sh --bug_id 버그ID --model_type openai --model_size large --no_eval
```

## 모델 유형 및 크기

다양한 모델 유형과 크기를 사용할 수 있습니다:

1. **OpenAI API** (`--model_type openai`):
   - `--model_size large`: GPT-4를 사용합니다.

2. **Anthropic API** (`--model_type anthropic`):
   - `--model_size large`: Claude 모델을 사용합니다.

3. **로컬 SLM** (`--model_type local_slm`):
   - `--model_size 1b`: 1B 파라미터 SLM 모델을 사용합니다.
   - `--model_size 10b`: 10B 파라미터 SLM 모델을 사용합니다.

## 결과 해석하기

실행이 완료되면 `results/` 디렉토리에 다음과 같은 결과가 생성됩니다:

1. **graphs/**: 생성된 보안 그래프 및 정보
   - `{bug_id}_graph.graphml`: NetworkX GraphML 형식의 그래프
   - `{bug_id}_graph_info.txt`: 텍스트로 변환된 그래프 정보

2. **prompts/**: LLM에 전송된 프롬프트
   - `{bug_id}_prompt.json`: 프롬프트 내용

3. **responses/**: LLM이 생성한 응답
   - `{bug_id}_response.txt`: LLM의 전체 응답 텍스트

4. **generated_code/**: 추출된 코드
   - `{bug_id}_code.java`: LLM이 생성한 수정된 코드

5. **evaluations/**: 평가 결과
   - `{bug_id}_evaluation.json`: 평가 지표 (기능성, 보안성, 견고성, 코드 품질)

6. **all_results.json**: 모든 결과의 요약 및 통계

평가 지표 해석:
- **functionality**: 수정된 코드가 기능 테스트를 통과했는지 여부
- **security**: 수정된 코드에서 원래 취약점이 제거되었는지 여부
- **soundness**: 수정된 코드가 새로운 문제를 도입하지 않았는지 여부
- **code_quality**: 수정된 코드와 정답 코드 간의 CodeBLEU 점수 (높을수록 좋음)

## 추가 설정 옵션

`config.py` 파일에서 다음과 같은 추가 설정을 변경할 수 있습니다:

1. **타임아웃 설정**: `EVALUATION_TIMEOUT`으로 평가 단계의 타임아웃 시간을 설정합니다.
2. **모델 파라미터**: 온도(temperature), 최대 토큰 수 등의 모델 파라미터는 `inference.py`에서 수정할 수 있습니다.
3. **프롬프트 템플릿**: `resources/prompt_templates/` 내의 템플릿 파일을 수정하여 프롬프트 형식을 변경할 수 있습니다.

## 문제 해결

1. **외부 도구 오류**: Joern, CodeQL, Semgrep 등의 외부 도구가 설치되지 않은 경우, `--use_graph` 옵션을 제외하고 실행하세요.
2. **메모리 오류**: 로컬 SLM 모델 사용 시 메모리 부족 오류가 발생하면, 더 작은 모델(`--model_size 1b`)을 사용하거나 양자화된 모델을 설정하세요.
3. **API 할당량 초과**: OpenAI/Anthropic API 할당량 초과 시, 간격을 두고 다시 시도하거나 API 키를 교체하세요.

## 로그 파일

모든 실행 로그는 `run.log` 파일에 저장됩니다. 오류 분석이나 디버깅에 활용할 수 있습니다.

```bash
# 로그 파일 내의 오류 확인
grep "ERROR" run.log
```

## 고급 사용법: 새로운 취약점 유형 추가

새로운 취약점 유형(CWE)을 추가하려면:

1. Semgrep 규칙 추가:
   - `resources/semgrep_rules/` 디렉토리에 `cwe-<번호>-rules.yaml` 파일 생성

2. CodeQL 쿼리 추가:
   - `resources/codeql_queries/` 디렉토리에 `cwe-<번호>-query.ql` 파일 생성

3. 프롬프트 템플릿 수정:
   - 새 CWE 유형에 맞게 프롬프트 템플릿 조정

## 성능 최적화

대규모 데이터셋을 실행할 때 성능을 최적화하려면:

1. 그래프 캐싱: 이미 분석한 그래프를 캐싱하여 재사용
2. 병렬 처리: `-m run.main`에 `--parallel` 옵션 추가 (구현 필요)
3. 선택적 모듈 사용: 외부 도구 중 일부만 선택하여 실행 시간 단축
