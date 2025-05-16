"""
생성된 코드를 원본 파일에 통합하는 모듈
"""

import os
import logging
import shutil
from pathlib import Path

from run.utils.file_utils import (
    read_file,
    write_file,
    find_method_in_file,
    replace_method_in_file,
    copy_directory
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class CodeIntegrator:
    """생성된 코드를 원본 파일에 통합하는 클래스"""
    
    def __init__(self, results_dir=None):
        """
        초기화
        
        Args:
            results_dir: 결과 저장 디렉토리
        """
        self.results_dir = Path(results_dir) if results_dir else None
    
    def integrate_code(self, generated_code, vuln_info, output_dir=None):
        """
        생성된 코드를 원본 파일에 통합 (CodeBLEU 평가용)
        
        Args:
            generated_code: 생성된 코드
            vuln_info: 취약점 정보 딕셔너리
            output_dir: 출력 디렉토리 (None이면 결과 디렉토리 사용)
            
        Returns:
            (통합 성공 여부, 통합된 파일 경로) 튜플
        """
        if not generated_code or not vuln_info:
            logger.error("코드 통합에 필요한 정보가 없습니다.")
            return False, None
        
        # 필요한 정보 추출
        bug_id = vuln_info.get('bug_id')
        if not bug_id:
            logger.error("코드 통합에 필요한 정보가 부족합니다.")
            return False, None
        
        # 출력 디렉토리 설정
        if output_dir:
            target_dir = Path(output_dir)
        elif self.results_dir:
            target_dir = self.results_dir / bug_id
        else:
            target_dir = Path('results') / bug_id
        
        # 출력 디렉토리 생성
        os.makedirs(target_dir, exist_ok=True)
        
        # 출력 파일 경로 결정 (간단하게 fixed.java로 저장)
        output_file = target_dir / "fixed.java"
        
        try:
            # 생성된 코드를 파일에 저장
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(generated_code)
            
            logger.info(f"생성된 코드 저장 완료: {output_file}")
            return True, output_file
        
        except Exception as e:
            logger.error(f"코드 저장 오류: {e}")
            return False, None
    
    def integrate_code_to_project(self, generated_code, vuln_info, project_dir=None):
        """
        (더 이상 사용하지 않음) 호환성을 위해 유지하는 메서드
        
        Returns:
            (False, None) 항상 실패 튜플 반환
        """
        logger.info("Project integration is disabled, only CodeBLEU evaluation is enabled")
        return False, None