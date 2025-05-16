"""
LLM 모델 로딩 유틸리티
"""

import os
import logging
import torch

from run.config import (
    MODEL_TYPE,
    MODEL_SIZE,
    OPENAI_API_KEY,
    OPENAI_MODEL,
    ANTHROPIC_API_KEY,
    ANTHROPIC_MODEL,
    SLM_MODEL_PATH,
    SLM_MODEL_SIZE
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ModelLoader:
    """LLM 모델을 로드하는 클래스"""
    
    def __init__(self, model_type=MODEL_TYPE, model_size=MODEL_SIZE):
        """
        초기화
        
        Args:
            model_type: 모델 유형 ("openai", "anthropic", "local_slm")
            model_size: 모델 크기 ("1b", "10b", "large")
        """
        self.model_type = model_type
        self.model_size = model_size
        self.model = None
        self.tokenizer = None
    
    def load_model(self):
        """
        모델 로드
        
        Returns:
            모델과 토크나이저의 튜플 또는 None
        """
        if self.model_type == "openai":
            return self._load_openai_model()
        elif self.model_type == "anthropic":
            return self._load_anthropic_model()
        elif self.model_type == "local_slm":
            return self._load_local_slm()
        else:
            logger.error(f"지원하지 않는 모델 유형: {self.model_type}")
            return None, None
    
    def _load_openai_model(self):
        """
        OpenAI API 모델 로드
        
        Returns:
            OpenAI API 클라이언트 또는 None
        """
        try:
            from openai import OpenAI
            
            # API 키 설정
            api_key = OPENAI_API_KEY
            if not api_key:
                logger.error("OpenAI API 키가 설정되지 않았습니다.")
                return None, None
            
            # 클라이언트 생성
            client = OpenAI(api_key=api_key)
            logger.info(f"OpenAI 모델 {OPENAI_MODEL} 초기화 완료")
            
            return client, OPENAI_MODEL
        
        except ImportError:
            logger.error("OpenAI 패키지가 설치되지 않았습니다. 'pip install openai'를 실행하세요.")
            return None, None
        except Exception as e:
            logger.error(f"OpenAI 모델 로드 오류: {e}")
            return None, None
    
    def _load_anthropic_model(self):
        """
        Anthropic API 모델 로드
        
        Returns:
            Anthropic API 클라이언트 또는 None
        """
        try:
            from anthropic import Anthropic
            
            # API 키 설정
            api_key = ANTHROPIC_API_KEY
            if not api_key:
                logger.error("Anthropic API 키가 설정되지 않았습니다.")
                return None, None
            
            # 클라이언트 생성
            client = Anthropic(api_key=api_key)
            logger.info(f"Anthropic 모델 {ANTHROPIC_MODEL} 초기화 완료")
            
            return client, ANTHROPIC_MODEL
        
        except ImportError:
            logger.error("Anthropic 패키지가 설치되지 않았습니다. 'pip install anthropic'를 실행하세요.")
            return None, None
        except Exception as e:
            logger.error(f"Anthropic 모델 로드 오류: {e}")
            return None, None
    
    def _load_local_slm(self):
        """
        로컬 SLM 모델 로드
        
        Returns:
            모델과 토크나이저의 튜플 또는 None
        """
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer
            
            # 모델 경로 설정
            model_path = SLM_MODEL_PATH
            if not model_path:
                logger.error("SLM 모델 경로가 설정되지 않았습니다.")
                return None, None
            
            # 모델 크기에 따른 설정
            if self.model_size in ["1b", "10b"]:
                model_size = self.model_size
            else:
                model_size = SLM_MODEL_SIZE
                logger.warning(f"SLM에 대해 잘못된 모델 크기: {self.model_size}, {model_size}로 대체")
            
            # GPU 사용 여부 확인
            device = "cuda" if torch.cuda.is_available() else "cpu"
            
            # 토크나이저 로드
            tokenizer = AutoTokenizer.from_pretrained(model_path)
            
            # 모델 로드
            model = AutoModelForCausalLM.from_pretrained(
                model_path,
                torch_dtype=torch.float16 if device == "cuda" else torch.float32,
                device_map="auto" if device == "cuda" else None
            )
            
            logger.info(f"로컬 SLM 모델 {model_size} 로드 완료 (디바이스: {device})")
            
            return model, tokenizer
        
        except ImportError:
            logger.error("transformers 패키지가 설치되지 않았습니다. 'pip install transformers torch'를 실행하세요.")
            return None, None
        except Exception as e:
            logger.error(f"로컬 SLM 모델 로드 오류: {e}")
            return None, None
