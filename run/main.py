"""
취약점 수정 LLM 기술 실험 메인 스크립트
"""

import os
import sys
import argparse
import logging
import json
from pathlib import Path
import time

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from run.config import (
    DATASET_DIR,
    RESULTS_DIR,
    MODEL_TYPE,
    MODEL_SIZE,
    USE_GRAPH_INFO
)
from run.utils.dataset import VulnerabilityDataset
from run.extraction.code_extractor import VulnerabilityCodeExtractor
from run.graph.graph_builder import SecurityGraphBuilder
from run.graph.graph_processor import GraphProcessor
from run.prompting.prompt_builder import PromptBuilder
from run.inference.inference import LLMInference
from run.evaluation.code_integrator import CodeIntegrator
from run.evaluation.evaluator import VulnerabilityFixEvaluator

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("run.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


def parse_args():
    """명령줄 인수 파싱"""
    parser = argparse.ArgumentParser(description="취약점 수정 LLM 기술 실험")
    
    # 데이터셋 관련 인수
    parser.add_argument("--dataset_dir", type=str, default=str(DATASET_DIR),
                       help="데이터셋 디렉토리")
    parser.add_argument("--results_dir", type=str, default=str(RESULTS_DIR),
                       help="결과 저장 디렉토리")
    parser.add_argument("--bug_id", type=str, default=None,
                       help="특정 버그 ID (지정하지 않으면 모든 버그 처리)")
    
    # 모델 관련 인수
    parser.add_argument("--model_type", type=str, default=MODEL_TYPE,
                       choices=["openai", "anthropic", "local_slm"],
                       help="모델 유형")
    parser.add_argument("--model_size", type=str, default=MODEL_SIZE,
                       choices=["1b", "10b", "large"],
                       help="모델 크기")
    
    # 그래프 관련 인수
    parser.add_argument("--use_graph", action="store_true", default=USE_GRAPH_INFO,
                       help="그래프 정보 사용 여부")
    parser.add_argument("--joern", action="store_true", default=True,
                       help="Joern 사용 여부")
    parser.add_argument("--codeql", action="store_true", default=True,
                       help="CodeQL 사용 여부")
    parser.add_argument("--semgrep", action="store_true", default=True,
                       help="Semgrep 사용 여부")
    
    # 평가 관련 인수
    parser.add_argument("--no_evaluate", action="store_false", dest="evaluate",
                       help="자동 평가 단계 건너뛰기")
    parser.add_argument("--evaluate", action="store_true", default=True,
                       help="자동 평가 수행 여부")
    
    return parser.parse_args()


def process_bug(bug_id, args, dataset):
    """
    단일 버그 처리
    
    Args:
        bug_id: 버그 ID
        args: 명령줄 인수
        dataset: 데이터셋 객체
    
    Returns:
        처리 결과 딕셔너리
    """
    result = {
        "bug_id": bug_id,
        "success": False,
        "stages": {}
    }
    
    try:
        logger.info(f"========== Processing Bug ID: {bug_id} ==========")
        start_time = time.time()
        
        # ===== Step 1: Code and Information Extraction =====
        logger.info("Step 1: Extracting code and vulnerability information...")
        extractor = VulnerabilityCodeExtractor(dataset)
        vuln_info = extractor.get_complete_extraction(bug_id)
        
        if not vuln_info:
            logger.error(f"Could not extract vulnerability information for ID {bug_id}.")
            return result
        
        result["stages"]["extraction"] = True
        logger.info(f"Vulnerability info extracted: CWE-{vuln_info['cwe_id']} - {vuln_info['title']}")
        
        # ===== Step 2: Security Graph Construction =====
        graph_info_text = None
        if args.use_graph:
            logger.info("Step 2: Building security enhanced graph...")
            
            builder = SecurityGraphBuilder(
                use_joern=args.joern,
                use_codeql=args.codeql,
                use_semgrep=args.semgrep
            )
            
            # 그래프 구축
            graph = builder.build_graph_for_file(
                vuln_info['before_file'],
                vuln_info['method_name'],
                vuln_info['start_line'],
                vuln_info['end_line']
            )
            
            # 그래프 저장
            graph_dir = Path(args.results_dir) / "graphs"
            os.makedirs(graph_dir, exist_ok=True)
            graph_file = graph_dir / f"{bug_id}_graph.graphml"
            builder.save_graph(graph_file)
            
            # 그래프 정보 처리
            processor = GraphProcessor(graph)
            graph_info = processor.extract_graph_info(
                vuln_info['method_name'],
                vuln_info['start_line'],
                vuln_info['end_line'],
                args.model_size
            )
            
            # 그래프 정보 텍스트 변환
            graph_info_text = processor.format_graph_info_to_text(graph_info, args.model_size)
            
            # 그래프 정보 저장
            graph_text_file = graph_dir / f"{bug_id}_graph_info.txt"
            with open(graph_text_file, 'w', encoding='utf-8') as f:
                f.write(graph_info_text)
            
            result["stages"]["graph_building"] = True
            logger.info(f"Graph construction completed: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
        
        # ===== Step 3-4: Prompt Construction and LLM Inference =====
        logger.info("Step 3-4: Building prompt and running LLM inference...")
        
        # 프롬프트 구성
        prompt_builder = PromptBuilder()
        
        if args.model_type in ["openai", "anthropic"]:
            # Chat Completion API 형식 프롬프트
            messages = prompt_builder.build_chat_completion_messages(
                vuln_info,
                graph_info_text,
                args.model_size
            )
            prompt_text = None
        else:
            # SLM 형식 프롬프트
            messages = None
            prompt_text = prompt_builder.build_prompt_text(
                vuln_info,
                graph_info_text,
                args.model_size
            )
        
        # 프롬프트 저장
        prompt_dir = Path(args.results_dir) / "prompts"
        os.makedirs(prompt_dir, exist_ok=True)
        
        with open(prompt_dir / f"{bug_id}_prompt.json", 'w', encoding='utf-8') as f:
            if messages:
                json.dump(messages, f, indent=2, ensure_ascii=False)
            else:
                json.dump({"text": prompt_text}, f, indent=2, ensure_ascii=False)
        
        # LLM 추론
        inference = LLMInference(args.model_type, args.model_size)
        response = inference.generate(messages, prompt_text)
        
        if not response:
            logger.error("Failed to generate LLM response.")
            return result
        
        # 응답 저장
        response_dir = Path(args.results_dir) / "responses"
        os.makedirs(response_dir, exist_ok=True)
        
        with open(response_dir / f"{bug_id}_response.txt", 'w', encoding='utf-8') as f:
            f.write(response)
        
        # 코드 추출
        generated_code = inference.extract_code_from_response(response)
        
        if not generated_code:
            logger.error("Could not extract code from the response.")
            return result
        
        # 코드 저장
        code_dir = Path(args.results_dir) / "generated_code"
        os.makedirs(code_dir, exist_ok=True)
        
        with open(code_dir / f"{bug_id}_code.java", 'w', encoding='utf-8') as f:
            f.write(generated_code)
        
        result["stages"]["inference"] = True
        logger.info(f"LLM inference completed: Generated code length {len(generated_code)} chars")
        
        # ===== Step 5-6: Code Integration and CodeBLEU Evaluation =====
        if args.evaluate:
            logger.info("Step 5-6: Integrating code and calculating CodeBLEU...")
            
            # 코드 통합 (단순 파일 저장)
            integrator = CodeIntegrator(args.results_dir)
            success, fixed_file = integrator.integrate_code(generated_code, vuln_info)
            
            if not success or not fixed_file:
                logger.error("Failed to integrate code.")
                return result
            
            # CodeBLEU 평가
            evaluator = VulnerabilityFixEvaluator(args.results_dir)
            eval_result = evaluator.evaluate_fix(
                bug_id,
                fixed_file,
                vuln_info['before_file'],
                vuln_info.get('complete_target_method')  # 전체 타겟 메서드 사용
            )
            
            result["stages"]["evaluation"] = True
            result["evaluation"] = eval_result
            
            logger.info(f"Evaluation results:")
            if eval_result.get('code_quality') is not None:
                logger.info(f"  Code Quality (CodeBLEU): {eval_result['code_quality']}")
            else:
                logger.info("  Code Quality: Could not calculate CodeBLEU score")
        
        # 처리 시간 기록
        elapsed_time = time.time() - start_time
        result["elapsed_time"] = elapsed_time
        result["success"] = True
        
        logger.info(f"========== Bug ID: {bug_id} processing completed (Time: {elapsed_time:.2f} seconds) ==========")
        
        return result
    
    except Exception as e:
        logger.error(f"버그 ID {bug_id} 처리 중 오류 발생: {e}", exc_info=True)
        return result


def main():
    """메인 함수"""
    # 명령줄 인수 파싱
    args = parse_args()
    
    # 결과 디렉토리 생성
    os.makedirs(args.results_dir, exist_ok=True)
    
    # 설정 저장
    config = {
        "dataset_dir": args.dataset_dir,
        "results_dir": args.results_dir,
        "bug_id": args.bug_id,
        "model_type": args.model_type,
        "model_size": args.model_size,
        "use_graph": args.use_graph,
        "joern": args.joern,
        "codeql": args.codeql,
        "semgrep": args.semgrep,
        "evaluate": args.evaluate
    }
    
    with open(os.path.join(args.results_dir, "config.json"), 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    
    # 데이터셋 로드
    dataset = VulnerabilityDataset(os.path.join(args.dataset_dir, "avr_dataset.pkl"))
    
    # 버그 ID 결정
    if args.bug_id:
        bug_ids = [args.bug_id]
    else:
        bug_ids = dataset.get_all_bug_ids()
    
    # 결과 초기화
    all_results = {
        "config": config,
        "results": {}
    }
    
    # 각 버그 처리
    for bug_id in bug_ids:
        try:
            result = process_bug(bug_id, args, dataset)
            all_results["results"][bug_id] = result
            
            # 중간 결과 저장
            with open(os.path.join(args.results_dir, "all_results.json"), 'w', encoding='utf-8') as f:
                json.dump(all_results, f, indent=2, ensure_ascii=False)
        
        except Exception as e:
            logger.error(f"버그 ID {bug_id} 처리 중 오류 발생: {e}", exc_info=True)
    
    # 요약 결과 계산
    summary = {
        "total": len(bug_ids),
        "success": sum(1 for bug_id in bug_ids if all_results["results"].get(bug_id, {}).get("success", False)),
        "evaluation": {
            "code_quality_avg": 0.0,
            "ngram_match_avg": 0.0,
            "weighted_ngram_match_avg": 0.0,
            "syntax_match_avg": 0.0,
            "dataflow_match_avg": 0.0
        }
    }
    
    # 평가 결과 집계
    eval_count = 0
    code_quality_sum = 0.0
    ngram_match_sum = 0.0
    weighted_ngram_match_sum = 0.0
    syntax_match_sum = 0.0
    dataflow_match_sum = 0.0
    
    for bug_id in bug_ids:
        result = all_results["results"].get(bug_id, {})
        eval_result = result.get("evaluation", {})
        
        if eval_result:
            eval_count += 1
            
            # 기본 CodeBLEU 점수
            if eval_result.get("code_quality") is not None:
                code_quality_sum += eval_result["code_quality"]
            
            # 세부 요소 점수들
            details = eval_result.get("details", {}).get("code_quality", {})
            if isinstance(details, dict):
                if "ngram_match_score" in details:
                    ngram_match_sum += details.get("ngram_match_score", 0.0)
                if "weighted_ngram_match_score" in details:
                    weighted_ngram_match_sum += details.get("weighted_ngram_match_score", 0.0)
                if "syntax_match_score" in details:
                    syntax_match_sum += details.get("syntax_match_score", 0.0)
                if "dataflow_match_score" in details:
                    dataflow_match_sum += details.get("dataflow_match_score", 0.0)
    
    # 평균 계산
    if eval_count > 0:
        summary["evaluation"]["code_quality_avg"] = code_quality_sum / eval_count
        summary["evaluation"]["ngram_match_avg"] = ngram_match_sum / eval_count
        summary["evaluation"]["weighted_ngram_match_avg"] = weighted_ngram_match_sum / eval_count
        summary["evaluation"]["syntax_match_avg"] = syntax_match_sum / eval_count
        summary["evaluation"]["dataflow_match_avg"] = dataflow_match_sum / eval_count
    
    # 요약 저장
    all_results["summary"] = summary
    
    with open(os.path.join(args.results_dir, "all_results.json"), 'w', encoding='utf-8') as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)
    
    # 요약 출력
    logger.info("========== Experiment Summary ==========")
    logger.info(f"Total bugs: {summary['total']}")
    logger.info(f"Successfully processed: {summary['success']}")
    logger.info(f"Evaluated: {eval_count}")
    
    if eval_count > 0:
        logger.info(f"Average CodeBLEU score: {summary['evaluation']['code_quality_avg']:.4f}")
        # 세부 요소 점수들이 있으면 출력
        if summary['evaluation']['ngram_match_avg'] > 0:
            logger.info(f"  - N-gram match: {summary['evaluation']['ngram_match_avg']:.4f}")
            logger.info(f"  - Weighted N-gram: {summary['evaluation']['weighted_ngram_match_avg']:.4f}")
            logger.info(f"  - Syntax match: {summary['evaluation']['syntax_match_avg']:.4f}")
            logger.info(f"  - Dataflow match: {summary['evaluation']['dataflow_match_avg']:.4f}")
    
    logger.info("========== Experiment Completed ==========")


if __name__ == "__main__":
    main()