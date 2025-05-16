"""
파일 처리를 위한 유틸리티 함수들
"""

import os
import shutil
import tempfile
import logging
from pathlib import Path
import re
import javalang

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def read_file(file_path):
    """
    파일 내용 읽기
    
    Args:
        file_path: 파일 경로
        
    Returns:
        파일 내용 문자열
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        logger.error(f"파일 읽기 오류 ({file_path}): {e}")
        return None


def write_file(file_path, content):
    """
    파일에 내용 쓰기
    
    Args:
        file_path: 파일 경로
        content: 파일에 쓸 내용
        
    Returns:
        성공 여부 (bool)
    """
    try:
        # 디렉토리가 없으면 생성
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    except Exception as e:
        logger.error(f"파일 쓰기 오류 ({file_path}): {e}")
        return False


def create_temp_directory():
    """
    임시 디렉토리 생성
    
    Returns:
        임시 디렉토리 경로
    """
    return tempfile.mkdtemp()


def copy_directory(src_dir, dst_dir):
    """
    디렉토리 복사
    
    Args:
        src_dir: 원본 디렉토리
        dst_dir: 대상 디렉토리
        
    Returns:
        성공 여부 (bool)
    """
    try:
        # 안전 검사: 시스템 주요 디렉토리는 복사하지 않음
        src_path = Path(src_dir)
        if str(src_path) == "/" or str(src_path) == str(Path.home()):
            logger.error(f"안전 오류: 시스템 중요 디렉토리 복사 시도: {src_dir}")
            return False
        
        # 디렉토리 크기 확인 (1GB 이상이면 위험 가능성)
        import subprocess
        try:
            result = subprocess.run(["du", "-sb", str(src_path)], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                size_str = result.stdout.strip().split()[0]
                size_bytes = int(size_str)
                if size_bytes > 1024 * 1024 * 1024:  # 1GB
                    logger.error(f"안전 오류: 복사하려는 디렉토리가 너무 큽니다 ({size_bytes / (1024*1024*1024):.2f} GB): {src_dir}")
                    return False
        except:
            logger.warning(f"디렉토리 크기를 확인할 수 없습니다: {src_dir}")
        
        if os.path.exists(dst_dir):
            shutil.rmtree(dst_dir)
        shutil.copytree(src_dir, dst_dir)
        logger.info(f"디렉토리 복사 완료: {src_dir} -> {dst_dir}")
        return True
    except Exception as e:
        logger.error(f"디렉토리 복사 오류 ({src_dir} -> {dst_dir}): {e}")
        return False


def find_method_in_file(file_path, method_name):
    """
    Java 파일에서 메소드 위치 찾기
    
    Args:
        file_path: Java 파일 경로
        method_name: 찾을 메소드 이름
        
    Returns:
        (시작 라인, 끝 라인, 메소드 코드) 튜플
    """
    try:
        file_content = read_file(file_path)
        if not file_content:
            return None, None, None
        
        # 먼저 javalang으로 파싱 시도
        try:
            tree = javalang.parse.parse(file_content)
            method_declaration = None
            
            # 클래스 내의 모든 메소드 순회
            for _, class_node in tree.filter(javalang.tree.ClassDeclaration):
                for method_node in class_node.methods:
                    if method_node.name == method_name:
                        method_declaration = method_node
                        break
                if method_declaration:
                    break
                    
            if method_declaration:
                # 메소드 위치 찾기
                start_pos = method_declaration.position.line if hasattr(method_declaration, 'position') else None
                
                if start_pos:
                    # 메소드 끝 찾기 (완벽하지 않을 수 있음)
                    lines = file_content.splitlines()
                    brace_count = 0
                    end_pos = start_pos
                    
                    for i in range(start_pos-1, len(lines)):
                        line = lines[i]
                        brace_count += line.count('{') - line.count('}')
                        if brace_count <= 0 and i > start_pos-1:
                            end_pos = i + 1
                            break
                    
                    method_code = '\n'.join(lines[start_pos-1:end_pos])
                    return start_pos, end_pos, method_code
        
        except Exception as e:
            logger.warning(f"javalang 파싱 오류, 정규식 방식 시도: {e}")
            
        # javalang 파싱 실패시 정규식 사용
        lines = file_content.splitlines()
        method_pattern = rf'(?:public|private|protected|static|final|native|synchronized|abstract|transient)* [a-zA-Z0-9<>[\].,\s]*\s+{re.escape(method_name)}\s*\([^)]*\)\s*(?:\s*throws\s+[^{{]+)?\s*{{'
        
        for i, line in enumerate(lines):
            if re.search(method_pattern, line):
                start_pos = i + 1
                brace_count = 0
                end_pos = start_pos
                
                for j in range(start_pos - 1, len(lines)):
                    line = lines[j]
                    brace_count += line.count('{') - line.count('}')
                    if brace_count <= 0 and j > start_pos - 1:
                        end_pos = j + 1
                        break
                
                method_code = '\n'.join(lines[start_pos-1:end_pos])
                return start_pos, end_pos, method_code
        
        return None, None, None
    
    except Exception as e:
        logger.error(f"메소드 위치 찾기 오류 ({file_path}, {method_name}): {e}")
        return None, None, None


def replace_method_in_file(file_path, method_name, new_method_code, output_path=None):
    """
    Java 파일에서 메소드 교체
    
    Args:
        file_path: 원본 Java 파일 경로
        method_name: 교체할 메소드 이름
        new_method_code: 새 메소드 코드
        output_path: 출력 파일 경로 (None이면 원본 덮어쓰기)
        
    Returns:
        성공 여부 (bool)
    """
    try:
        start_line, end_line, _ = find_method_in_file(file_path, method_name)
        if start_line is None or end_line is None:
            logger.error(f"메소드를 찾을 수 없음: {method_name} in {file_path}")
            return False
        
        file_content = read_file(file_path)
        if not file_content:
            return False
        
        lines = file_content.splitlines()
        
        # 메소드 교체
        new_lines = lines[:start_line-1] + new_method_code.splitlines() + lines[end_line:]
        new_content = '\n'.join(new_lines)
        
        # 출력 파일 경로 결정
        target_path = output_path if output_path else file_path
        
        return write_file(target_path, new_content)
    
    except Exception as e:
        logger.error(f"메소드 교체 오류: {e}")
        return False


def extract_package_from_java_file(file_path):
    """
    Java 파일에서 패키지 경로 추출
    
    Args:
        file_path: Java 파일 경로
        
    Returns:
        패키지 경로 문자열
    """
    try:
        file_content = read_file(file_path)
        if not file_content:
            return None
        
        # 정규식으로 패키지 추출
        package_match = re.search(r'package\s+([a-zA-Z0-9_.]+);', file_content)
        if package_match:
            return package_match.group(1)
        
        return None
    
    except Exception as e:
        logger.error(f"패키지 추출 오류 ({file_path}): {e}")
        return None


def extract_imports_from_java_file(file_path):
    """
    Java 파일에서 import 문 추출
    
    Args:
        file_path: Java 파일 경로
        
    Returns:
        import 문 목록
    """
    try:
        file_content = read_file(file_path)
        if not file_content:
            return []
        
        # 정규식으로 import 추출
        imports = re.findall(r'import\s+([a-zA-Z0-9_.*]+);', file_content)
        return imports
    
    except Exception as e:
        logger.error(f"import 추출 오류 ({file_path}): {e}")
        return []