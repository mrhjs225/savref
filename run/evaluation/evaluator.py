"""
취약점 수정 솔루션 자동 평가 모듈
"""

import os
import json
import logging
from pathlib import Path
import tempfile

from run.utils.evaluation import (
    run_test,
    run_semgrep,
    detect_build_system,
    calculate_code_bleu
)
from run.config import (
    SEMGREP_RULES_DIR,
    RESULTS_DIR
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class VulnerabilityFixEvaluator:
    """취약점 수정 솔루션을 평가하는 클래스"""
    
    def __init__(self, results_dir=RESULTS_DIR):
        """
        초기화
        
        Args:
            results_dir: 결과 저장 디렉토리
        """
        self.results_dir = Path(results_dir)
    
    def evaluate_fix(self, bug_id, fixed_file, original_file, target_code=None, project_dir=None):
        """
        취약점 수정 솔루션 평가 (CodeBLEU만 계산)
        
        Args:
            bug_id: 취약점 ID
            fixed_file: 수정된 파일 경로
            original_file: 원본 파일 경로
            target_code: 정답 코드 문자열 (None이면 자동 탐지)
            project_dir: 사용하지 않음 (호환성 유지용)
            
        Returns:
            평가 결과 딕셔너리
        """
        logger.info(f"Starting CodeBLEU evaluation for bug ID: {bug_id}")
        
        # 결과 디렉토리 설정
        result_dir = Path(self.results_dir) / bug_id / "evaluation"
        os.makedirs(result_dir, exist_ok=True)
        
        # 결과 초기화
        result = {
            'bug_id': bug_id,
            'code_quality': None,
            'details': {}
        }
        
        # 파일 존재 확인
        if not os.path.exists(fixed_file):
            logger.error(f"수정된 파일이 존재하지 않음: {fixed_file}")
            return result
            
        # 원본 코드 로드 및 저장
        try:
            with open(original_file, 'r', encoding='utf-8') as f:
                original_code = f.read()
            logger.info(f"Original code loaded: {len(original_code)} chars")
            
            # 원본 코드 저장
            with open(result_dir / "original_code.java", 'w', encoding='utf-8') as f:
                f.write(original_code)
                
        except Exception as e:
            logger.error(f"원본 코드 로드 오류: {e}")
            # 원본 코드가 없어도 계속 진행
        
        # 수정된 코드 로드
        try:
            with open(fixed_file, 'r', encoding='utf-8') as f:
                fixed_code = f.read()
            logger.info(f"Fixed code loaded: {len(fixed_code)} chars")
            
            # 수정된 코드 저장
            with open(result_dir / "generated_code.java", 'w', encoding='utf-8') as f:
                f.write(fixed_code)
                
        except Exception as e:
            logger.error(f"수정된 코드 로드 오류: {e}")
            return result
        
        # target_code가 없는 경우, target_file에서 로드 시도
        if target_code is None:
            target_file = str(original_file).replace('before.java', 'after.java')
            if os.path.exists(target_file):
                try:
                    with open(target_file, 'r', encoding='utf-8') as f:
                        target_code = f.read()
                    logger.info(f"Target code loaded from {target_file}: {len(target_code)} chars")
                except Exception as e:
                    logger.error(f"정답 코드 로드 오류: {e}")
                    return result
            else:
                logger.error(f"정답 파일이 존재하지 않음: {target_file}")
                return result
        
        # 정답 코드 저장
        try:
            with open(result_dir / "target_code.java", 'w', encoding='utf-8') as f:
                f.write(target_code)
        except Exception as e:
            logger.error(f"정답 코드 저장 오류: {e}")
        
        # CodeBLEU 계산
        try:
            code_bleu_score = calculate_code_bleu(fixed_code, target_code)
            
            if isinstance(code_bleu_score, dict):
                # CodeBLEU가 전체 결과 딕셔너리를 반환한 경우
                result['code_quality'] = code_bleu_score.get('codebleu', 0.0)
                result['details']['code_quality'] = code_bleu_score
            else:
                # CodeBLEU가 단일 점수를 반환한 경우
                result['code_quality'] = code_bleu_score
                result['details']['code_quality'] = {'code_bleu': code_bleu_score}
            
            logger.info(f"CodeBLEU score: {result['code_quality']}")
            
            # 상세 결과가 있으면 출력
            if isinstance(code_bleu_score, dict) and len(code_bleu_score) > 1:
                for key, value in code_bleu_score.items():
                    if key != 'codebleu':
                        logger.info(f"  - {key}: {value:.4f}")
            
            # CodeBLEU 결과 저장
            with open(result_dir / "codebleu_result.json", 'w', encoding='utf-8') as f:
                if isinstance(code_bleu_score, dict):
                    json.dump(code_bleu_score, f, indent=2)
                else:
                    json.dump({"codebleu": code_bleu_score}, f, indent=2)
                
        except Exception as e:
            logger.error(f"CodeBLEU 계산 오류: {e}", exc_info=True)
        
            # HTML 보고서 생성
            self._generate_html_report(
                result_dir, 
                bug_id, 
                original_code, 
                fixed_code, 
                target_code, 
                code_bleu_score
            )
            
            # 요약 결과 저장
            with open(result_dir / "evaluation_summary.json", 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2)
        
        return result
        
        # 1. 보안성 평가 (Semgrep 규칙 사용)
        try:
            # 취약점 유형에 맞는 Semgrep 규칙 찾기
            rule_file = self._find_semgrep_rule_for_bug(bug_id)
            
            if rule_file:
                # 원본 파일 취약점 확인
                orig_vuln_found, orig_result = run_semgrep(original_file, rule_path=rule_file)
                
                # 수정된 파일 취약점 확인
                fixed_vuln_found, fixed_result = run_semgrep(fixed_file, rule_path=rule_file)
                
                # 원래 취약점이 더 이상 탐지되지 않으면 성공
                result['security'] = orig_vuln_found and not fixed_vuln_found
                
                # 상세 결과 저장
                result['details']['security'] = {
                    'original_vulnerable': orig_vuln_found,
                    'fixed_vulnerable': fixed_vuln_found,
                    'rule_file': str(rule_file)
                }
            else:
                logger.warning(f"ID {bug_id}에 대한 Semgrep 규칙을 찾을 수 없음")
        
        except Exception as e:
            logger.error(f"보안성 평가 오류: {e}")
        
        # 2. 코드 품질 평가 (CodeBLEU)
        if target_file and os.path.exists(target_file):
            try:
                with open(fixed_file, 'r', encoding='utf-8') as f:
                    fixed_code = f.read()
                
                with open(target_file, 'r', encoding='utf-8') as f:
                    target_code = f.read()
                
                code_bleu_score = calculate_code_bleu(fixed_code, target_code)
                result['code_quality'] = code_bleu_score
                
                # 상세 결과 저장
                result['details']['code_quality'] = {
                    'code_bleu': code_bleu_score,
                    'target_file': str(target_file)
                }
            
            except Exception as e:
                logger.error(f"코드 품질 평가 오류: {e}")
        
        # 3. 기능성 및 견고성 평가 (테스트 실행)
        if project_dir:
            try:
                # 프로젝트 디렉토리 결정
                if not os.path.isdir(project_dir):
                    logger.error(f"프로젝트 디렉토리가 존재하지 않음: {project_dir}")
                    project_dir = None
                
                if not project_dir:
                    # 기본값: 원본 파일의 상위 디렉토리가 Maven/Gradle 프로젝트인지 확인
                    original_dir = Path(original_file).parent
                    
                    # Maven/Gradle 프로젝트 디렉토리 찾기
                    current_dir = original_dir
                    max_depth = 5  # 최대 5단계 상위 디렉토리까지만 탐색
                    current_depth = 0
                    
                    while current_dir != current_dir.parent and current_depth < max_depth:
                        if detect_build_system(current_dir) is not None:
                            project_dir = current_dir
                            break
                        current_dir = current_dir.parent
                        current_depth += 1
                    
                    # 안전 검사: 루트 디렉토리(/)나 홈 디렉토리(~)로 설정되었다면 취소
                    if project_dir and (str(project_dir) == "/" or str(project_dir) == str(Path.home())):
                        logger.error(f"위험: 프로젝트 디렉토리가 시스템 디렉토리로 잘못 식별됨: {project_dir}")
                        logger.error("안전을 위해 평가를 건너뜁니다.")
                        project_dir = None
                
                if project_dir:
                    logger.info(f"Running tests in: {project_dir}")
                    # 테스트 실행 (타임아웃 설정)
                    success, test_output = run_test(project_dir)
                    
                    # 테스트 통과 여부로 기능성 및 견고성 평가
                    result['functionality'] = success
                    result['soundness'] = success
                    
                    # 상세 결과 저장
                    result['details']['test'] = {
                        'success': success,
                        'project_dir': str(project_dir)
                    }
                    
                    if not success:
                        logger.warning(f"Tests failed. Output: {test_output[:500]}...")
                    else:
                        logger.info("Tests passed successfully")
                else:
                    logger.warning(f"Maven/Gradle 프로젝트를 찾을 수 없음")
            
            except Exception as e:
                logger.error(f"테스트 평가 오류: {e}", exc_info=True)
                result['details']['test_error'] = str(e)
        else:
            logger.info("Skipping test phase - no project directory provided")
        # 결과 저장
        self._save_evaluation_result(bug_id, result)
        
        return result
    
    def _find_semgrep_rule_for_bug(self, bug_id):
        """
        버그 ID에 맞는 Semgrep 규칙 파일 찾기
        
        Args:
            bug_id: 버그 ID
            
        Returns:
            규칙 파일 경로 또는 None
        """
        try:
            # 규칙 디렉토리 확인
            rules_dir = Path(SEMGREP_RULES_DIR)
            if not rules_dir.exists():
                logger.error(f"Semgrep 규칙 디렉토리가 존재하지 않음: {rules_dir}")
                return None
            
            # 버그 ID와 일치하는 규칙 찾기
            for rule_file in rules_dir.glob("*.yaml"):
                if bug_id in rule_file.stem:
                    return rule_file
            
            # CWE ID로 시도
            for rule_file in rules_dir.glob("*.yaml"):
                with open(rule_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if f"CWE-{bug_id}" in content or f"cwe: {bug_id}" in content:
                        return rule_file
            
            # 일반적인 Java 보안 규칙 반환
            default_rule = rules_dir / "java_security_rules.yaml"
            if default_rule.exists():
                return default_rule
            
            return None
        
        except Exception as e:
            logger.error(f"Semgrep 규칙 검색 오류: {e}")
            return None
    
    def _save_evaluation_result(self, bug_id, result):
        """
        평가 결과 저장
        
        Args:
            bug_id: 버그 ID
            result: 평가 결과 딕셔너리
        """
        try:
            # 결과 디렉토리 생성
            eval_dir = self.results_dir / "evaluations"
            os.makedirs(eval_dir, exist_ok=True)
            
            # 결과 파일 경로
            result_file = eval_dir / f"{bug_id}_evaluation.json"
            
            # JSON으로 저장
            with open(result_file, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            
            logger.info(f"평가 결과 저장됨: {result_file}")
        
        except Exception as e:
            logger.error(f"평가 결과 저장 오류: {e}")