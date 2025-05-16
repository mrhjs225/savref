"""
보안 강화 그래프 구축 모듈
"""

import os
import subprocess
import json
import tempfile
import logging
import networkx as nx
from pathlib import Path

from run.config import (
    JOERN_PATH, 
    CODEQL_PATH, 
    SEMGREP_PATH,
    TAINT_FLOW_QUERY,
    SECURITY_PATTERNS_QUERY
)
from run.utils.file_utils import read_file, write_file

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SecurityGraphBuilder:
    """보안 강화 그래프를 구축하는 클래스"""
    
    def __init__(self, use_joern=True, use_codeql=True, use_semgrep=True):
        """
        초기화
        
        Args:
            use_joern: Joern 사용 여부
            use_codeql: CodeQL 사용 여부
            use_semgrep: Semgrep 사용 여부
        """
        self.use_joern = use_joern
        self.use_codeql = use_codeql
        self.use_semgrep = use_semgrep
        
        # 그래프 초기화
        self.graph = nx.MultiDiGraph()
        
        # 임시 디렉토리 설정
        self.temp_dir = None
    
    def _create_temp_dir(self):
        """임시 디렉토리 생성"""
        if not self.temp_dir:
            self.temp_dir = tempfile.mkdtemp()
            logger.info(f"임시 디렉토리 생성: {self.temp_dir}")
        return self.temp_dir
    
    def _run_command(self, command, cwd=None):
        """
        외부 명령어 실행
        
        Args:
            command: 실행할 명령어 리스트
            cwd: 작업 디렉토리
            
        Returns:
            (returncode, stdout, stderr) 튜플
        """
        try:
            result = subprocess.run(
                command,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=300  # 5분 타임아웃
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            logger.error(f"명령 실행 타임아웃: {' '.join(command)}")
            return -1, "", "Timeout expired"
        except Exception as e:
            logger.error(f"명령 실행 오류: {e}")
            return -2, "", str(e)
    
    def build_graph_for_file(self, file_path, method_name=None, start_line=None, end_line=None):
        """
        파일에 대한 보안 강화 그래프 구축
        
        Args:
            file_path: 분석할 Java 파일 경로
            method_name: 취약한 메소드 이름 (선택 사항)
            start_line: 취약한 코드 시작 라인 (선택 사항)
            end_line: 취약한 코드 끝 라인 (선택 사항)
            
        Returns:
            구축된 networkx 그래프
        """
        # 그래프 초기화
        self.graph = nx.MultiDiGraph()
        
        # 임시 디렉토리 생성
        temp_dir = self._create_temp_dir()
        
        # 분석 범위 설정 (메소드, 라인 정보가 제공된 경우)
        scope = {}
        if method_name:
            scope['method_name'] = method_name
        if start_line and end_line:
            scope['start_line'] = start_line
            scope['end_line'] = end_line
        
        # 1. Joern을 사용한 CPG 생성 (선택 사항)
        if self.use_joern:
            self._build_joern_cpg(file_path, scope)
        
        # 2. CodeQL을 사용한 Taint Flow 분석 (선택 사항)
        if self.use_codeql:
            self._build_codeql_taint_flow(file_path, scope)
        
        # 3. Semgrep을 사용한 보안 패턴 매칭 (선택 사항)
        if self.use_semgrep:
            self._build_semgrep_patterns(file_path, scope)
        
        return self.graph
    
    def _build_joern_cpg(self, file_path, scope=None):
        """
        Joern을 사용하여 CPG 구축
        
        Args:
            file_path: 분석할 Java 파일 경로
            scope: 분석 범위 정보 (메소드 이름, 라인 범위 등)
        """
        logger.info(f"Joern CPG 생성 중: {file_path}")
        
        try:
            # 임시 디렉토리 생성
            temp_dir = self._create_temp_dir()
            
            # 임시 스크립트 파일 생성
            script_path = os.path.join(temp_dir, "joern_script.scala")
            script_content = f"""
            |@main def main() = {{
            |  val cpg = importCode("{file_path}")
            |  exportCpg(cpg, "{temp_dir}/cpg")
            |}}
            """.stripMargin('|')
            
            write_file(script_path, script_content)
            
            # Joern 실행
            command = [
                JOERN_PATH,
                "--script", script_path
            ]
            
            returncode, stdout, stderr = self._run_command(command)
            
            if returncode != 0:
                logger.error(f"Joern 실행 오류: {stderr}")
                return
            
            # GraphML 형식으로 내보내기
            export_command = [
                JOERN_PATH + "-export",
                "--format", "graphml",
                temp_dir + "/cpg"
            ]
            
            returncode, stdout, stderr = self._run_command(export_command)
            
            if returncode != 0:
                logger.error(f"Joern 내보내기 오류: {stderr}")
                return
            
            # GraphML 파일 읽기
            graphml_file = os.path.join(temp_dir, "cpg.graphml")
            if os.path.exists(graphml_file):
                joern_graph = nx.read_graphml(graphml_file)
                
                # NetworkX 그래프로 변환하여 통합
                self._integrate_joern_graph(joern_graph, scope)
            else:
                logger.error(f"GraphML 파일을 찾을 수 없음: {graphml_file}")
        
        except Exception as e:
            logger.error(f"Joern CPG 생성 오류: {e}")
    
    def _integrate_joern_graph(self, joern_graph, scope=None):
        """
        Joern 그래프를 메인 그래프에 통합
        
        Args:
            joern_graph: Joern으로 생성된 그래프
            scope: 분석 범위 정보 (메소드 이름, 라인 범위 등)
        """
        # 그래프 통합 로직
        # 1. 노드 추가
        for node, attrs in joern_graph.nodes(data=True):
            # 노드 범위 필터링 (scope가 제공된 경우)
            if scope:
                if 'method_name' in scope and 'METHOD_NAME' in attrs:
                    if attrs['METHOD_NAME'] != scope['method_name']:
                        continue
                
                if 'start_line' in scope and 'end_line' in scope and 'LINE_NUMBER' in attrs:
                    line_num = attrs['LINE_NUMBER']
                    if line_num < scope['start_line'] or line_num > scope['end_line']:
                        continue
            
            # 노드 유형에 따라 속성 추가
            node_type = attrs.get('TYPE', 'UNKNOWN')
            
            # 그래프에 노드 추가
            self.graph.add_node(
                node,
                **attrs,
                source='joern',
                node_type=node_type
            )
        
        # 2. 엣지 추가
        for u, v, attrs in joern_graph.edges(data=True):
            # 두 노드가 모두 그래프에 있는 경우에만 엣지 추가
            if u in self.graph and v in self.graph:
                edge_type = attrs.get('TYPE', 'UNKNOWN')
                
                self.graph.add_edge(
                    u, v,
                    **attrs,
                    source='joern',
                    edge_type=edge_type
                )
    
    def _build_codeql_taint_flow(self, file_path, scope=None):
        """
        CodeQL을 사용하여 Taint Flow 분석 수행
        
        Args:
            file_path: 분석할 Java 파일 경로
            scope: 분석 범위 정보 (메소드 이름, 라인 범위 등)
        """
        logger.info(f"CodeQL Taint Flow 분석 중: {file_path}")
        
        try:
            # 임시 디렉토리 생성
            temp_dir = self._create_temp_dir()
            
            # CodeQL 데이터베이스 생성
            db_path = os.path.join(temp_dir, "codeql_db")
            
            create_db_command = [
                CODEQL_PATH, "database", "create",
                "--language=java",
                db_path,
                "--source-root", os.path.dirname(file_path)
            ]
            
            returncode, stdout, stderr = self._run_command(create_db_command)
            
            if returncode != 0:
                logger.error(f"CodeQL 데이터베이스 생성 오류: {stderr}")
                return
            
            # Taint Flow 쿼리 실행
            results_path = os.path.join(temp_dir, "taint_results.json")
            
            run_query_command = [
                CODEQL_PATH, "query", "run",
                str(TAINT_FLOW_QUERY),
                "--database", db_path,
                "--output", results_path,
                "--format=json"
            ]
            
            returncode, stdout, stderr = self._run_command(run_query_command)
            
            if returncode != 0:
                logger.error(f"CodeQL 쿼리 실행 오류: {stderr}")
                return
            
            # 결과 파싱 및 그래프 통합
            if os.path.exists(results_path):
                self._parse_codeql_taint_results(results_path, scope)
            else:
                logger.error(f"CodeQL 결과 파일을 찾을 수 없음: {results_path}")
        
        except Exception as e:
            logger.error(f"CodeQL Taint Flow 분석 오류: {e}")
    
    def _parse_codeql_taint_results(self, results_path, scope=None):
        """
        CodeQL Taint Flow 결과 파싱 및 그래프 통합
        
        Args:
            results_path: CodeQL 결과 파일 경로
            scope: 분석 범위 정보 (메소드 이름, 라인 범위 등)
        """
        try:
            # 결과 파일 읽기
            with open(results_path, 'r') as f:
                results = json.load(f)
            
            # 결과 순회
            for result in results:
                # 결과 범위 필터링 (scope가 제공된 경우)
                if scope and 'method_name' in scope:
                    # 메소드 이름으로 필터링 로직 추가 (CodeQL 결과 형식에 따라 조정 필요)
                    pass
                
                # 경로 정보 추출 (CodeQL 결과에 경로 정보가 있다고 가정)
                if 'paths' in result:
                    for path in result['paths']:
                        self._add_taint_flow_path(path, result)
        
        except Exception as e:
            logger.error(f"CodeQL 결과 파싱 오류: {e}")
    
    def _add_taint_flow_path(self, path, result_info):
        """
        Taint Flow 경로를 그래프에 추가
        
        Args:
            path: Taint Flow 경로 정보
            result_info: 결과 메타데이터
        """
        # CodeQL 결과 형식에 맞게 조정 필요
        # 예시 구현:
        if 'nodes' in path:
            prev_node_id = None
            
            for i, node in enumerate(path['nodes']):
                # 노드 ID 생성
                node_id = f"codeql_node_{len(self.graph.nodes) + 1}"
                
                # 노드 위치 정보
                location = node.get('location', {})
                line = location.get('startLine')
                column = location.get('startColumn')
                file_path = location.get('file')
                
                # 노드 유형 결정 (첫 번째는 Source, 마지막은 Sink, 나머지는 중간 노드)
                if i == 0:
                    node_type = 'SOURCE'
                elif i == len(path['nodes']) - 1:
                    node_type = 'SINK'
                else:
                    node_type = 'TAINT_STEP'
                
                # 노드 속성 구성
                node_attrs = {
                    'label': node.get('label', ''),
                    'line': line,
                    'column': column,
                    'file': file_path,
                    'source': 'codeql',
                    'node_type': node_type
                }
                
                # 그래프에 노드 추가
                self.graph.add_node(node_id, **node_attrs)
                
                # 이전 노드와 연결 (첫 번째 노드가 아닌 경우)
                if prev_node_id:
                    self.graph.add_edge(
                        prev_node_id, node_id,
                        edge_type='TAINT_FLOW',
                        source='codeql'
                    )
                
                prev_node_id = node_id
    
    def _build_semgrep_patterns(self, file_path, scope=None):
        """
        Semgrep을 사용하여 보안 패턴 탐지
        
        Args:
            file_path: 분석할 Java 파일 경로
            scope: 분석 범위 정보 (메소드 이름, 라인 범위 등)
        """
        logger.info(f"Semgrep 보안 패턴 탐지 중: {file_path}")
        
        try:
            # Semgrep 실행
            results_path = os.path.join(self._create_temp_dir(), "semgrep_results.json")
            
            command = [
                SEMGREP_PATH,
                "--json",
                "-f", str(SECURITY_PATTERNS_QUERY),
                file_path,
                "-o", results_path
            ]
            
            returncode, stdout, stderr = self._run_command(command)
            
            if returncode != 0 and returncode != 1:  # Semgrep은 패턴 발견 시 1을 반환할 수 있음
                logger.error(f"Semgrep 실행 오류: {stderr}")
                return
            
            # 결과 파싱 및 그래프 통합
            if os.path.exists(results_path):
                self._parse_semgrep_results(results_path, scope)
            else:
                logger.error(f"Semgrep 결과 파일을 찾을 수 없음: {results_path}")
        
        except Exception as e:
            logger.error(f"Semgrep 패턴 탐지 오류: {e}")
    
    def _parse_semgrep_results(self, results_path, scope=None):
        """
        Semgrep 결과 파싱 및 그래프 통합
        
        Args:
            results_path: Semgrep 결과 파일 경로
            scope: 분석 범위 정보 (메소드 이름, 라인 범위 등)
        """
        try:
            # 결과 파일 읽기
            with open(results_path, 'r') as f:
                results = json.load(f)
            
            # 결과 순회
            for result in results.get('results', []):
                # 결과 범위 필터링 (scope가 제공된 경우)
                if scope:
                    if 'start_line' in scope and 'end_line' in scope:
                        line = result.get('start', {}).get('line')
                        if line and (line < scope['start_line'] or line > scope['end_line']):
                            continue
                
                # 패턴 정보 추출
                pattern_id = result.get('check_id')
                severity = result.get('extra', {}).get('severity')
                message = result.get('extra', {}).get('message')
                line = result.get('start', {}).get('line')
                
                # 노드 ID 생성
                node_id = f"semgrep_pattern_{len(self.graph.nodes) + 1}"
                
                # 노드 속성 구성
                node_attrs = {
                    'label': pattern_id,
                    'pattern_id': pattern_id,
                    'severity': severity,
                    'message': message,
                    'line': line,
                    'source': 'semgrep',
                    'node_type': 'SECURITY_PATTERN'
                }
                
                # 그래프에 노드 추가
                self.graph.add_node(node_id, **node_attrs)
                
                # 관련 코드 라인 노드와 연결 (있는 경우)
                if line:
                    for node, attrs in self.graph.nodes(data=True):
                        if attrs.get('source') == 'joern' and attrs.get('line') == line:
                            self.graph.add_edge(
                                node_id, node,
                                edge_type='PATTERN_MATCH',
                                source='semgrep'
                            )
        
        except Exception as e:
            logger.error(f"Semgrep 결과 파싱 오류: {e}")
    
    def save_graph(self, output_path):
        """
        그래프를 GraphML 형식으로 저장
        
        Args:
            output_path: 출력 파일 경로
            
        Returns:
            성공 여부 (bool)
        """
        try:
            # 디렉토리 생성
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            # 그래프 저장
            nx.write_graphml(self.graph, output_path)
            logger.info(f"그래프가 저장됨: {output_path}")
            return True
        
        except Exception as e:
            logger.error(f"그래프 저장 오류: {e}")
            return False
    
    def load_graph(self, input_path):
        """
        GraphML 파일에서 그래프 로드
        
        Args:
            input_path: 입력 파일 경로
            
        Returns:
            성공 여부 (bool)
        """
        try:
            self.graph = nx.read_graphml(input_path)
            logger.info(f"그래프가 로드됨: {input_path} (노드: {len(self.graph.nodes)}, 엣지: {len(self.graph.edges)})")
            return True
        
        except Exception as e:
            logger.error(f"그래프 로드 오류: {e}")
            return False