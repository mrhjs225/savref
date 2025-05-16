"""
취약점 데이터셋 로딩 및 처리를 위한 유틸리티
"""

import os
import pickle
import pandas as pd
from pathlib import Path
import logging

from run.config import DATASET_FILE, FILES_DIR

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class VulnerabilityDataset:
    """취약점 데이터셋을 로드하고 처리하는 클래스"""

    def get_complete_target_method(self, bug_id):
        """
        버그 ID에 대한 완전한 타겟 메서드 코드 구성 (before_context + target_code + after_context)
        
        Args:
            bug_id: 취약점 ID
            
        Returns:
            완전한 타겟 메서드 코드
        """
        vuln_data = self.get_vulnerability_by_id(bug_id)
        if vuln_data is None:
            return None
        
        # 메서드 코드 구성
        method_code = ""
        
        # 메서드 docstring 추가 (있는 경우)
        if pd.notna(vuln_data.get('summary')) and vuln_data['summary']:
            method_code += vuln_data['summary'] + "\n"
        
        # 메서드 앞부분 컨텍스트 추가
        if pd.notna(vuln_data.get('before_context')) and vuln_data['before_context']:
            method_code += vuln_data['before_context'] + "\n"
        
        # 타겟 코드 추가 (수정된 코드)
        if pd.notna(vuln_data.get('target_code')) and vuln_data['target_code']:
            method_code += vuln_data['target_code'] + "\n"
        
        # 메서드 뒷부분 컨텍스트 추가
        if pd.notna(vuln_data.get('after_context')) and vuln_data['after_context']:
            method_code += vuln_data['after_context']
        
        return method_code

    def __init__(self, dataset_path=DATASET_FILE, files_dir=FILES_DIR):
        """
        데이터셋 초기화
        
        Args:
            dataset_path: avr_dataset.pkl 파일 경로
            files_dir: 소스 코드 파일이 저장된 디렉토리 경로
        """
        self.dataset_path = Path(dataset_path)
        self.files_dir = Path(files_dir)
        self.df = None
        
        self._load_dataset()
    
    def _load_dataset(self):
        """pickle 파일에서 데이터셋 로드"""
        try:
            logger.info(f"데이터셋 로드 중: {self.dataset_path}")
            with open(self.dataset_path, 'rb') as f:
                self.df = pickle.load(f)
            logger.info(f"데이터셋 로드 완료: {len(self.df)} 개의 취약점 항목")
        except Exception as e:
            logger.error(f"데이터셋 로드 중 오류 발생: {e}")
            raise
    
    def get_vulnerability_by_id(self, bug_id):
        """
        ID로 취약점 데이터 가져오기
        
        Args:
            bug_id: 취약점 ID
            
        Returns:
            해당 ID의 취약점 데이터를 담은 Series 객체
        """
        if self.df is None:
            logger.error("데이터셋이 로드되지 않았습니다.")
            return None
        
        try:
            return self.df[self.df['ID'] == bug_id].iloc[0]
        except IndexError:
            logger.error(f"ID {bug_id}를 가진 취약점을 찾을 수 없습니다.")
            return None
    
    def get_file_paths(self, bug_id):
        """
        취약점 ID에 해당하는 파일 경로 가져오기
        
        Args:
            bug_id: 취약점 ID
            
        Returns:
            before.java와 after.java 파일 경로의 튜플
        """
        bug_dir = self.files_dir / bug_id
        before_file = bug_dir / "before.java"
        after_file = bug_dir / "after.java"
        
        if not before_file.exists():
            logger.warning(f"버그 ID {bug_id}의 before.java 파일이 존재하지 않습니다: {before_file}")
        
        if not after_file.exists():
            logger.warning(f"버그 ID {bug_id}의 after.java 파일이 존재하지 않습니다: {after_file}")
        
        return before_file, after_file
    
    def get_all_bug_ids(self):
        """
        데이터셋의 모든 버그 ID 목록 반환
        
        Returns:
            모든 버그 ID의 리스트
        """
        if self.df is None:
            logger.error("데이터셋이 로드되지 않았습니다.")
            return []
        
        return self.df['ID'].tolist()
    
    def get_vulnerability_method(self, bug_id):
        """
        버그 ID에 대한 취약한 메소드 코드 구성
        
        Args:
            bug_id: 취약점 ID
            
        Returns:
            취약한 메소드의 전체 코드 (before_context + 취약 코드 + after_context)
        """
        vuln_data = self.get_vulnerability_by_id(bug_id)
        if vuln_data is None:
            return None
        
        # 메소드 코드 구성
        method_code = ""
        
        # 메소드 docstring 추가 (있는 경우)
        if pd.notna(vuln_data.get('summary')) and vuln_data['summary']:
            method_code += vuln_data['summary'] + "\n"
        
        # 메소드 앞부분 컨텍스트 추가
        if pd.notna(vuln_data.get('before_context')) and vuln_data['before_context']:
            method_code += vuln_data['before_context'] + "\n"
        
        # 취약한 코드 추가 (target_code는 고쳐진 코드이므로 before.java 파일에서 추출 필요)
        # 이 부분은 code_extractor.py에서 더 정교하게 구현 예정
        
        # 메소드 뒷부분 컨텍스트 추가
        if pd.notna(vuln_data.get('after_context')) and vuln_data['after_context']:
            method_code += vuln_data['after_context']
        
        return method_code
    
    def get_vulnerability_details(self, bug_id):
        """
        취약점에 대한 상세 정보 가져오기
        
        Args:
            bug_id: 취약점 ID
            
        Returns:
            취약점 상세 정보를 담은 딕셔너리
        """
        vuln_data = self.get_vulnerability_by_id(bug_id)
        if vuln_data is None:
            return None
        
        details = {
            'id': bug_id,
            'title': vuln_data.get('Title', ''),
            'description': vuln_data.get('Description', ''),
            'extended_description': vuln_data.get('Extended Description', ''),
            'target_code': vuln_data.get('target_code', '')
        }
        
        return details