"""
취약점 코드 및 관련 정보 추출 모듈
"""

import os
import re
import logging
import javalang
from pathlib import Path

from run.utils.file_utils import (
    read_file, 
    find_method_in_file, 
    extract_package_from_java_file,
    extract_imports_from_java_file
)
from run.utils.dataset import VulnerabilityDataset

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class VulnerabilityCodeExtractor:
    """취약점 코드와 정보를 추출하는 클래스"""
    
    def __init__(self, dataset=None):
        """
        초기화
        
        Args:
            dataset: VulnerabilityDataset 인스턴스 (None이면 새로 생성)
        """
        self.dataset = dataset if dataset else VulnerabilityDataset()
    
    def extract_vulnerability_info(self, bug_id):
        """
        취약점 정보 추출
        
        Args:
            bug_id: 취약점 ID
            
        Returns:
            취약점 정보 딕셔너리
        """
        # 기본 취약점 정보 가져오기
        vuln_details = self.dataset.get_vulnerability_details(bug_id)
        if not vuln_details:
            logger.error(f"ID {bug_id}에 대한 취약점 정보를 찾을 수 없습니다.")
            return None
        
        # 파일 경로 가져오기
        before_file, after_file = self.dataset.get_file_paths(bug_id)
        
        # 메소드 이름 추출 시도
        method_name = self._extract_method_name_from_code(vuln_details['target_code'])
        
        if not method_name:
            logger.warning(f"ID {bug_id}에 대한 메소드 이름을 추출할 수 없습니다.")
        
        # 메소드 위치 및 코드 추출
        start_line, end_line, vulnerable_method = None, None, None
        
        if method_name and before_file.exists():
            start_line, end_line, vulnerable_method = find_method_in_file(before_file, method_name)
        
        # 패키지 및 임포트 정보 추출
        package_name = None
        imports = []
        
        if before_file.exists():
            package_name = extract_package_from_java_file(before_file)
            imports = extract_imports_from_java_file(before_file)
        
        # CWE ID 추출 (제목에서)
        cwe_id = None
        if vuln_details['title']:
            cwe_match = re.search(r'CWE-(\d+)', vuln_details['title'])
            if cwe_match:
                cwe_id = cwe_match.group(1)
        
        # 결과 구성
        result = {
            'bug_id': bug_id,
            'cwe_id': cwe_id,
            'title': vuln_details['title'],
            'description': vuln_details['description'],
            'extended_description': vuln_details['extended_description'],
            'method_name': method_name,
            'start_line': start_line,
            'end_line': end_line,
            'vulnerable_method': vulnerable_method,
            'target_code': vuln_details['target_code'],
            'before_file': str(before_file),
            'after_file': str(after_file),
            'package_name': package_name,
            'imports': imports
        }
        
        return result
    
    def _extract_method_name_from_code(self, code_snippet):
        """
        코드 스니펫에서 메소드 이름 추출
        
        Args:
            code_snippet: 코드 스니펫
            
        Returns:
            메소드 이름 또는 None
        """
        if not code_snippet:
            return None
        
        # 메소드 선언 패턴
        method_pattern = r'(?:public|private|protected|static|final|native|synchronized|abstract|transient)* [a-zA-Z0-9<>[\].,\s]*\s+([a-zA-Z0-9_]+)\s*\([^)]*\)'
        
        # 정규식으로 메소드 이름 추출 시도
        match = re.search(method_pattern, code_snippet)
        if match:
            return match.group(1)
        
        # javalang 파서 사용 시도
        try:
            # 메소드 선언으로 코드를 감싸서 파싱 가능하게 만듦
            wrapped_code = f"class Temp {{ {code_snippet} }}"
            tree = javalang.parse.parse(wrapped_code)
            
            # 첫 번째 메소드 선언 찾기
            for _, class_node in tree.filter(javalang.tree.ClassDeclaration):
                for method_node in class_node.methods:
                    return method_node.name
        
        except Exception as e:
            logger.debug(f"javalang 파싱 오류: {e}")
        
        return None
    
    def extract_vulnerable_code_section(self, bug_id):
        """
        취약한 코드 부분만 추출
        
        Args:
            bug_id: 취약점 ID
            
        Returns:
            취약한 코드 섹션 문자열
        """
        # 취약점 정보 가져오기
        vuln_info = self.extract_vulnerability_info(bug_id)
        if not vuln_info:
            return None
        
        # 메소드 코드가 없으면 추출 불가
        if not vuln_info['vulnerable_method']:
            logger.error(f"ID {bug_id}에 대한 취약한 메소드 코드가 없습니다.")
            return None
        
        # target_code는 수정된 코드이므로, vulnerable_method에서 취약한 부분 추정
        # (실제 구현에서는 더 정교한 로직 필요)
        
        # 간단한 가정: 메소드의 본문 부분이 취약한 코드일 가능성이 높음
        try:
            method_code = vuln_info['vulnerable_method']
            
            # 메소드 본문 시작 위치 찾기 (첫 번째 중괄호 이후)
            body_start = method_code.find('{') + 1
            
            # 메소드 본문 끝 위치 찾기 (마지막 중괄호)
            body_end = method_code.rfind('}')
            
            if body_start > 0 and body_end > body_start:
                # 메소드 본문 추출
                method_body = method_code[body_start:body_end].strip()
                return method_body
            
            return method_code
        
        except Exception as e:
            logger.error(f"취약한 코드 섹션 추출 오류: {e}")
            return None
    
    def get_complete_extraction(self, bug_id):
        """
        취약점 분석에 필요한 모든 정보 추출
        
        Args:
            bug_id: 취약점 ID
            
        Returns:
            취약점 분석에 필요한 모든 정보를 담은 딕셔너리
        """
        # 취약점 기본 정보 추출
        vuln_info = self.extract_vulnerability_info(bug_id)
        if not vuln_info:
            return None
        
        # 취약한 코드 섹션 추출
        vulnerable_code = self.extract_vulnerable_code_section(bug_id)
        
        # 파일 내용 전체 가져오기
        before_file_content = None
        after_file_content = None
        
        if os.path.exists(vuln_info['before_file']):
            before_file_content = read_file(vuln_info['before_file'])
        
        if os.path.exists(vuln_info['after_file']):
            after_file_content = read_file(vuln_info['after_file'])
        
        # 완전한 타겟 메서드 가져오기
        complete_target_method = self.dataset.get_complete_target_method(bug_id)
        
        # 결과 구성
        result = {
            **vuln_info,
            'vulnerable_code': vulnerable_code,
            'before_file_content': before_file_content,
            'after_file_content': after_file_content,
            'complete_target_method': complete_target_method
        }
        
        return result