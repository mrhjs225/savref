"""
그래프 정보 처리 및 텍스트 변환 모듈
"""

import logging
import networkx as nx

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class GraphProcessor:
    """그래프 정보를 처리하고 텍스트로 변환하는 클래스"""
    
    def __init__(self, graph=None):
        """
        초기화
        
        Args:
            graph: NetworkX 그래프 (None이면 빈 그래프 생성)
        """
        self.graph = graph if graph else nx.MultiDiGraph()
    
    def set_graph(self, graph):
        """
        그래프 설정
        
        Args:
            graph: NetworkX 그래프
        """
        self.graph = graph
    
    def find_vulnerable_nodes(self, method_name=None, start_line=None, end_line=None):
        """
        취약한 노드 찾기
        
        Args:
            method_name: 취약한 메소드 이름 (선택 사항)
            start_line: 시작 라인 (선택 사항)
            end_line: 끝 라인 (선택 사항)
            
        Returns:
            취약한 노드 ID 목록
        """
        vulnerable_nodes = []
        
        for node, attrs in self.graph.nodes(data=True):
            # 메소드 이름으로 필터링
            if method_name and 'METHOD_NAME' in attrs:
                if attrs['METHOD_NAME'] != method_name:
                    continue
            
            # 라인 범위로 필터링
            if start_line and end_line and 'line' in attrs:
                line = attrs.get('line')
                if line and (line < start_line or line > end_line):
                    continue
            
            # 보안 패턴 노드 또는 Taint Flow 노드 우선 추가
            if attrs.get('node_type') in ['SECURITY_PATTERN', 'SOURCE', 'SINK']:
                vulnerable_nodes.append(node)
        
        return vulnerable_nodes
    
    def find_taint_flow_paths(self):
        """
        Taint Flow 경로 찾기
        
        Returns:
            Taint Flow 경로 목록 (각 경로는 노드 ID 목록)
        """
        # Source 노드 찾기
        source_nodes = [
            node for node, attrs in self.graph.nodes(data=True)
            if attrs.get('node_type') == 'SOURCE'
        ]
        
        # Sink 노드 찾기
        sink_nodes = [
            node for node, attrs in self.graph.nodes(data=True)
            if attrs.get('node_type') == 'SINK'
        ]
        
        paths = []
        
        # 각 Source에서 각 Sink로의 경로 찾기
        for source in source_nodes:
            for sink in sink_nodes:
                try:
                    # 모든 단순 경로 찾기 (중복 노드 없음)
                    for path in nx.all_simple_paths(self.graph, source, sink):
                        paths.append(path)
                except nx.NetworkXNoPath:
                    continue
        
        return paths
    
    def find_security_patterns(self):
        """
        보안 패턴 노드 찾기
        
        Returns:
            보안 패턴 노드 ID와 속성의 딕셔너리
        """
        patterns = {}
        
        for node, attrs in self.graph.nodes(data=True):
            if attrs.get('node_type') == 'SECURITY_PATTERN':
                patterns[node] = attrs
        
        return patterns
    
    def extract_control_flow_info(self, method_name=None, start_line=None, end_line=None):
        """
        제어 흐름 정보 추출
        
        Args:
            method_name: 메소드 이름 (선택 사항)
            start_line: 시작 라인 (선택 사항)
            end_line: 끝 라인 (선택 사항)
            
        Returns:
            제어 흐름 정보 딕셔너리
        """
        control_flow_info = {
            'conditional_nodes': [],
            'loop_nodes': [],
            'call_nodes': []
        }
        
        for node, attrs in self.graph.nodes(data=True):
            # 메소드 이름으로 필터링
            if method_name and 'METHOD_NAME' in attrs:
                if attrs['METHOD_NAME'] != method_name:
                    continue
            
            # 라인 범위로 필터링
            if start_line and end_line and 'line' in attrs:
                line = attrs.get('line')
                if line and (line < start_line or line > end_line):
                    continue
            
            # 노드 유형별 분류
            node_type = attrs.get('node_type', '')
            
            if 'CONTROL_STRUCTURE' in node_type:
                if 'IF' in node_type or 'CONDITION' in node_type:
                    control_flow_info['conditional_nodes'].append((node, attrs))
                elif 'LOOP' in node_type or 'FOR' in node_type or 'WHILE' in node_type:
                    control_flow_info['loop_nodes'].append((node, attrs))
            
            elif 'CALL' in node_type or 'METHOD_CALL' in node_type:
                control_flow_info['call_nodes'].append((node, attrs))
        
        return control_flow_info
    
    def extract_data_flow_info(self, method_name=None, start_line=None, end_line=None):
        """
        데이터 흐름 정보 추출
        
        Args:
            method_name: 메소드 이름 (선택 사항)
            start_line: 시작 라인 (선택 사항)
            end_line: 끝 라인 (선택 사항)
            
        Returns:
            데이터 흐름 정보 딕셔너리
        """
        data_flow_info = {
            'variable_nodes': [],
            'assignment_edges': [],
            'data_flow_edges': []
        }
        
        # 범위 내 노드 필터링
        nodes_in_scope = []
        for node, attrs in self.graph.nodes(data=True):
            # 메소드 이름으로 필터링
            if method_name and 'METHOD_NAME' in attrs:
                if attrs['METHOD_NAME'] != method_name:
                    continue
            
            # 라인 범위로 필터링
            if start_line and end_line and 'line' in attrs:
                line = attrs.get('line')
                if line and (line < start_line or line > end_line):
                    continue
            
            nodes_in_scope.append(node)
            
            # 변수 노드 추가
            if attrs.get('node_type', '') in ['VARIABLE', 'FIELD_IDENTIFIER', 'LOCAL', 'PARAMETER']:
                data_flow_info['variable_nodes'].append((node, attrs))
        
        # 엣지 추가
        for u, v, attrs in self.graph.edges(data=True):
            if u in nodes_in_scope and v in nodes_in_scope:
                edge_type = attrs.get('edge_type', '')
                
                if edge_type in ['DEFINES', 'ASSIGNS']:
                    data_flow_info['assignment_edges'].append((u, v, attrs))
                elif edge_type in ['FLOWS_TO', 'DATA_FLOW', 'REACHES']:
                    data_flow_info['data_flow_edges'].append((u, v, attrs))
        
        return data_flow_info
    
    def extract_graph_info(self, method_name=None, start_line=None, end_line=None, model_size="large"):
        """
        그래프에서 보안 관련 정보 추출
        
        Args:
            method_name: 메소드 이름 (선택 사항)
            start_line: 시작 라인 (선택 사항)
            end_line: 끝 라인 (선택 사항)
            model_size: 모델 크기 ("1b", "10b", "large")
            
        Returns:
            추출된 정보 딕셔너리
        """
        # 취약한 노드 찾기
        vulnerable_nodes = self.find_vulnerable_nodes(method_name, start_line, end_line)
        
        # Taint Flow 경로 찾기
        taint_flow_paths = self.find_taint_flow_paths()
        
        # 보안 패턴 찾기
        security_patterns = self.find_security_patterns()
        
        # 제어 흐름 정보 추출
        control_flow_info = self.extract_control_flow_info(method_name, start_line, end_line)
        
        # 데이터 흐름 정보 추출
        data_flow_info = self.extract_data_flow_info(method_name, start_line, end_line)
        
        # 정보 통합
        graph_info = {
            'vulnerable_nodes': vulnerable_nodes,
            'taint_flow_paths': taint_flow_paths,
            'security_patterns': security_patterns,
            'control_flow_info': control_flow_info,
            'data_flow_info': data_flow_info
        }
        
        return graph_info
    
    def format_graph_info_to_text(self, graph_info, model_size="large"):
        """
        그래프 정보를 텍스트로 포맷팅
        
        Args:
            graph_info: extract_graph_info()에서 반환된 정보 딕셔너리
            model_size: 모델 크기 ("1b", "10b", "large")
            
        Returns:
            포맷팅된 텍스트
        """
        # 모델 크기에 따라 상세도 조정
        if model_size == "1b":
            detail_level = "low"
        elif model_size == "10b":
            detail_level = "medium"
        else:  # "large"
            detail_level = "high"
        
        # 텍스트 구성
        sections = []
        
        # 1. 보안 취약점 패턴 정보
        if graph_info['security_patterns']:
            section = "## Security Vulnerability Patterns\n"
            
            for node, attrs in graph_info['security_patterns'].items():
                pattern_id = attrs.get('pattern_id', 'Unknown')
                severity = attrs.get('severity', 'Unknown')
                message = attrs.get('message', '')
                line = attrs.get('line', 'Unknown')
                
                section += f"- Pattern: {pattern_id} (Severity: {severity}, Line: {line})\n"
                
                if detail_level in ["medium", "high"] and message:
                    section += f"  - Description: {message}\n"
            
            sections.append(section)
        
        # 2. Taint Flow 경로 정보
        if graph_info['taint_flow_paths']:
            section = "## Taint Flow Paths\n"
            
            for i, path in enumerate(graph_info['taint_flow_paths']):
                section += f"### Path {i+1}\n"
                
                for j, node in enumerate(path):
                    node_attrs = self.graph.nodes[node] if node in self.graph.nodes else {}
                    node_type = node_attrs.get('node_type', 'Unknown')
                    line = node_attrs.get('line', 'Unknown')
                    label = node_attrs.get('label', '')
                    
                    if j == 0:
                        section += f"- Source: {label} (Line: {line})\n"
                    elif j == len(path) - 1:
                        section += f"- Sink: {label} (Line: {line})\n"
                    elif detail_level == "high":
                        section += f"- Step {j}: {label} (Line: {line})\n"
                
                if len(path) > 2 and detail_level != "high":
                    section += f"- (Path contains {len(path)-2} intermediate steps)\n"
            
            sections.append(section)
        
        # 3. 제어 흐름 정보
        if any(graph_info['control_flow_info'].values()):
            if detail_level in ["medium", "high"]:
                section = "## Control Flow Information\n"
                
                # 조건문 노드
                if graph_info['control_flow_info']['conditional_nodes']:
                    section += "### Conditionals\n"
                    
                    for node, attrs in graph_info['control_flow_info']['conditional_nodes']:
                        line = attrs.get('line', 'Unknown')
                        label = attrs.get('label', '')
                        
                        section += f"- Line {line}: {label}\n"
                
                # 루프 노드
                if graph_info['control_flow_info']['loop_nodes']:
                    section += "### Loops\n"
                    
                    for node, attrs in graph_info['control_flow_info']['loop_nodes']:
                        line = attrs.get('line', 'Unknown')
                        label = attrs.get('label', '')
                        
                        section += f"- Line {line}: {label}\n"
                
                # 메소드 호출 노드
                if graph_info['control_flow_info']['call_nodes'] and detail_level == "high":
                    section += "### Method Calls\n"
                    
                    for node, attrs in graph_info['control_flow_info']['call_nodes']:
                        line = attrs.get('line', 'Unknown')
                        label = attrs.get('label', '')
                        
                        section += f"- Line {line}: {label}\n"
                
                sections.append(section)
        
        # 4. 데이터 흐름 정보
        if any(graph_info['data_flow_info'].values()) and detail_level == "high":
            section = "## Data Flow Information\n"
            
            # 변수 노드
            if graph_info['data_flow_info']['variable_nodes']:
                section += "### Key Variables\n"
                
                for node, attrs in graph_info['data_flow_info']['variable_nodes']:
                    line = attrs.get('line', 'Unknown')
                    label = attrs.get('label', '')
                    
                    section += f"- Line {line}: {label}\n"
            
            # 데이터 흐름 엣지
            if graph_info['data_flow_info']['data_flow_edges']:
                section += "### Data Flows\n"
                
                for u, v, attrs in graph_info['data_flow_info']['data_flow_edges']:
                    u_attrs = self.graph.nodes[u] if u in self.graph.nodes else {}
                    v_attrs = self.graph.nodes[v] if v in self.graph.nodes else {}
                    
                    u_label = u_attrs.get('label', 'Unknown')
                    v_label = v_attrs.get('label', 'Unknown')
                    
                    section += f"- {u_label} -> {v_label}\n"
            
            sections.append(section)
        
        # 5. 요약 정보 (항상 포함)
        summary = "## Security Vulnerability Summary\n"
        
        if graph_info['security_patterns']:
            pattern_count = len(graph_info['security_patterns'])
            patterns = list(graph_info['security_patterns'].values())
            pattern_ids = [attrs.get('pattern_id', 'Unknown') for attrs in patterns]
            
            summary += f"- {pattern_count} security vulnerability patterns detected: {', '.join(pattern_ids)}\n"
        else:
            summary += "- No specific security vulnerability patterns detected\n"
        
        if graph_info['taint_flow_paths']:
            path_count = len(graph_info['taint_flow_paths'])
            summary += f"- {path_count} Taint Flow paths detected\n"
            
            # 소스와 싱크 유형 추출
            sources = set()
            sinks = set()
            
            for path in graph_info['taint_flow_paths']:
                if path:
                    # 첫 번째 노드가 소스
                    if path[0] in self.graph:
                        source_label = self.graph.nodes[path[0]].get('label', 'Unknown')
                        sources.add(source_label)
                    
                    # 마지막 노드가 싱크
                    if path[-1] in self.graph:
                        sink_label = self.graph.nodes[path[-1]].get('label', 'Unknown')
                        sinks.add(sink_label)
            
            if sources:
                summary += f"  - Sources: {', '.join(sources)}\n"
            if sinks:
                summary += f"  - Sinks: {', '.join(sinks)}\n"
        else:
            summary += "- No Taint Flow paths detected\n"
        
        # 요약을 맨 앞에 추가
        sections.insert(0, summary)
        
        # 최종 텍스트 구성
        return "\n".join(sections)