"""
취약점 수정 솔루션 평가를 위한 유틸리티
"""

import os
import subprocess
import tempfile
import logging
import json
from pathlib import Path
import re
import time

from run.config import EVALUATION_TIMEOUT, SEMGREP_PATH

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def run_command(command, cwd=None, timeout=60):  # 타임아웃을 300초에서 60초로 줄임
    """
    외부 명령어 실행
    
    Args:
        command: 실행할 명령어 리스트
        cwd: 작업 디렉토리
        timeout: 타임아웃 시간 (초)
        
    Returns:
        (returncode, stdout, stderr) 튜플
    """
    try:
        logger.info(f"Running command: {' '.join(command)}")
        result = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        logger.info(f"Command completed with return code: {result.returncode}")
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        logger.error(f"Command execution timed out after {timeout} seconds: {' '.join(command)}")
        return -1, "", "Timeout expired"
    except Exception as e:
        logger.error(f"Command execution error: {e}")
        return -2, "", str(e)


def run_maven_test(project_dir):
    """
    Maven 테스트 실행
    
    Args:
        project_dir: Maven 프로젝트 디렉토리
        
    Returns:
        (성공 여부, 테스트 결과) 튜플
    """
    logger.info(f"Maven 테스트 실행 중: {project_dir}")
    
    # Maven 테스트 실행
    logger.info("Executing: mvn test")
    returncode, stdout, stderr = run_command(
        ["mvn", "test"],
        cwd=project_dir
    )
    
    if returncode != 0:
        logger.error(f"Maven 테스트 실패 (returncode: {returncode}): {stderr}")
        return False, stderr
    
    logger.info("Maven test completed successfully")
    return True, stdout


def run_gradle_test(project_dir):
    """
    Gradle 테스트 실행
    
    Args:
        project_dir: Gradle 프로젝트 디렉토리
        
    Returns:
        (성공 여부, 테스트 결과) 튜플
    """
    logger.info(f"Gradle 테스트 실행 중: {project_dir}")
    
    # 실행 가능한 gradlew 파일이 있는지 확인
    gradlew_path = Path(project_dir) / "gradlew"
    if gradlew_path.exists():
        cmd = ["./gradlew"]
    else:
        cmd = ["gradle"]
    
    cmd.append("test")
    logger.info(f"Executing: {' '.join(cmd)}")
    
    # Gradle 테스트 실행
    returncode, stdout, stderr = run_command(
        cmd,
        cwd=project_dir
    )
    
    if returncode != 0:
        logger.error(f"Gradle 테스트 실패 (returncode: {returncode}): {stderr}")
        return False, stderr
    
    logger.info("Gradle test completed successfully")
    return True, stdout


def detect_build_system(project_dir):
    """
    프로젝트의 빌드 시스템 감지
    
    Args:
        project_dir: 프로젝트 디렉토리
        
    Returns:
        "maven", "gradle" 또는 None
    """
    pom_file = Path(project_dir) / "pom.xml"
    gradle_file = Path(project_dir) / "build.gradle"
    
    if pom_file.exists():
        return "maven"
    elif gradle_file.exists():
        return "gradle"
    else:
        return None


def run_test(project_dir):
    """
    프로젝트 테스트 실행 (Maven 또는 Gradle 자동 감지)
    
    Args:
        project_dir: 프로젝트 디렉토리
        
    Returns:
        (성공 여부, 테스트 결과) 튜플
    """
    logger.info(f"Detecting build system for: {project_dir}")
    build_system = detect_build_system(project_dir)
    logger.info(f"Detected build system: {build_system}")
    
    if build_system == "maven":
        logger.info("Running Maven tests...")
        return run_maven_test(project_dir)
    elif build_system == "gradle":
        logger.info("Running Gradle tests...")
        return run_gradle_test(project_dir)
    else:
        logger.error(f"지원하는 빌드 시스템을 찾을 수 없음: {project_dir}")
        return False, "No supported build system found"


def run_semgrep(file_path, rule_path=None, rule_text=None):
    """
    Semgrep으로 취약점 검사
    
    Args:
        file_path: 검사할 파일 경로
        rule_path: Semgrep 규칙 파일 경로 (rule_text와 함께 사용 불가)
        rule_text: Semgrep 규칙 텍스트 (rule_path와 함께 사용 불가)
        
    Returns:
        (취약점 발견 여부, 결과) 튜플
    """
    if rule_path and rule_text:
        raise ValueError("rule_path와 rule_text는 함께 사용할 수 없습니다")
    
    if not (rule_path or rule_text):
        raise ValueError("rule_path 또는 rule_text가 필요합니다")
    
    # 임시 규칙 파일 생성 (rule_text 제공된 경우)
    if rule_text:
        fd, rule_path = tempfile.mkstemp(suffix='.yaml')
        with os.fdopen(fd, 'w') as f:
            f.write(rule_text)
    
    try:
        # Semgrep 실행
        command = [
            SEMGREP_PATH,
            "--json",
            "-f", rule_path,
            file_path
        ]
        
        returncode, stdout, stderr = run_command(command)
        
        if returncode != 0 and returncode != 1:  # Semgrep은 취약점 발견 시 1을 반환
            logger.error(f"Semgrep 실행 오류: {stderr}")
            return False, stderr
        
        # 결과 파싱
        try:
            result = json.loads(stdout)
            vulnerabilities = result.get("results", [])
            return len(vulnerabilities) > 0, result
        except json.JSONDecodeError:
            logger.error("Semgrep 결과를 JSON으로 파싱할 수 없음")
            return False, stdout
    
    finally:
        # 임시 파일 삭제 (rule_text 제공된 경우)
        if rule_text and os.path.exists(rule_path):
            os.remove(rule_path)


def calculate_code_bleu(generated_code, reference_code):
    """
    CodeBLEU 점수 계산 (CodeBLEU 라이브러리 필요)
    
    Args:
        generated_code: 생성된 코드
        reference_code: 참조 코드
        
    Returns:
        CodeBLEU 점수
    """
    try:
        # CodeBLEU 라이브러리 임포트
        from codebleu import calc_codebleu
        
        # CodeBLEU 계산
        # 참고: calc_codebleu는 references와 predictions를 리스트로 받음
        result = calc_codebleu(
            references=[reference_code],   # 리스트로 감싸기
            predictions=[generated_code],  # 리스트로 감싸기
            lang="java",                   # 언어 설정
            weights=(0.25, 0.25, 0.25, 0.25)  # 가중치 (ngram, weighted_ngram, syntax, dataflow)
        )
        
        # 전체 점수 반환
        return result['codebleu']
    except ImportError:
        logger.error("CodeBLEU 라이브러리를 찾을 수 없음. 'pip install codebleu'를 실행하세요.")
        return None
    except Exception as e:
        logger.error(f"CodeBLEU 계산 오류: {e}", exc_info=True)
        return None


def evaluate_solution(before_file, after_file, expected_file, rule_path=None):
    """
    취약점 수정 솔루션 평가
    
    Args:
        before_file: 수정 전 파일 경로
        after_file: 수정 후 파일 경로
        expected_file: 예상 수정 파일 경로
        rule_path: Semgrep 규칙 파일 경로
        
    Returns:
        평가 결과 딕셔너리
    """
    result = {
        "functionality": False,
        "security": False,
        "soundness": False,
        "code_quality": None
    }
    
    # 1. 보안 평가 (원본 파일에서 취약점 탐지 확인)
    if rule_path:
        orig_vuln_found, _ = run_semgrep(before_file, rule_path=rule_path)
        
        if not orig_vuln_found:
            logger.warning(f"원본 파일에서 취약점을 탐지하지 못함: {before_file}")
        
        # 수정된 파일에서 취약점 탐지 확인
        new_vuln_found, _ = run_semgrep(after_file, rule_path=rule_path)
        
        # 원래 취약점이 더 이상 탐지되지 않으면 성공
        result["security"] = orig_vuln_found and not new_vuln_found
    
    # 2. 코드 품질 평가 (CodeBLEU)
    try:
        with open(after_file, 'r', encoding='utf-8') as f:
            generated_code = f.read()
        
        with open(expected_file, 'r', encoding='utf-8') as f:
            expected_code = f.read()
        
        code_bleu_score = calculate_code_bleu(generated_code, expected_code)
        result["code_quality"] = code_bleu_score
    except Exception as e:
        logger.error(f"코드 품질 평가 오류: {e}")
    
    # 3. 프로젝트 디렉토리 추출 (일반적으로 버그 파일의 상위 디렉토리)
    project_dir = Path(after_file).parent
    
    # 상위 디렉토리가 Maven 또는 Gradle 프로젝트가 될 때까지 탐색
    while project_dir != project_dir.parent:
        if detect_build_system(project_dir) is not None:
            break
        project_dir = project_dir.parent
    
    # 4. 기능 테스트 (프로젝트 테스트 실행)
    success, _ = run_test(project_dir)
    result["functionality"] = success
    
    # 5. 견고성 평가 (간단히 기능 테스트와 동일하게 처리)
    result["soundness"] = success
    
    return result