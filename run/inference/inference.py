"""
LLM 추론 모듈
"""

import os
import logging
import re
import torch

from run.config import (
    MODEL_TYPE,
    MODEL_SIZE,
    OPENAI_MODEL,
    ANTHROPIC_MODEL
)
from run.inference.model_loader import ModelLoader

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class LLMInference:
    """LLM 추론을 수행하는 클래스"""
    
    def __init__(self, model_type=MODEL_TYPE, model_size=MODEL_SIZE):
        """
        초기화
        
        Args:
            model_type: 모델 유형 ("openai", "anthropic", "local_slm")
            model_size: 모델 크기 ("1b", "10b", "large")
        """
        self.model_type = model_type
        self.model_size = model_size
        self.loader = ModelLoader(model_type, model_size)
        self.model, self.tokenizer = self.loader.load_model()
    
    def generate(self, prompt_messages=None, prompt_text=None, temperature=0.2, max_tokens=1500):
        """
        LLM 추론 수행
        
        Args:
            prompt_messages: Chat Completion API용 메시지 리스트
            prompt_text: SLM용 프롬프트 텍스트
            temperature: 샘플링 온도
            max_tokens: 최대 생성 토큰 수
            
        Returns:
            생성된 텍스트
        """
        if self.model_type == "openai":
            return self._generate_openai(prompt_messages, temperature, max_tokens)
        elif self.model_type == "anthropic":
            return self._generate_anthropic(prompt_messages, temperature, max_tokens)
        elif self.model_type == "local_slm":
            return self._generate_local_slm(prompt_text, temperature, max_tokens)
        else:
            logger.error(f"지원하지 않는 모델 유형: {self.model_type}")
            return None
    
    def _generate_openai(self, prompt_messages, temperature, max_tokens):
        """
        OpenAI API로 추론 수행
        
        Args:
            prompt_messages: Chat Completion API용 메시지 리스트
            temperature: 샘플링 온도
            max_tokens: 최대 생성 토큰 수
            
        Returns:
            생성된 텍스트
        """
        if not self.model or not isinstance(prompt_messages, list) or not prompt_messages:
            return None
        
        try:
            # API 호출
            response = self.model.chat.completions.create(
                model=OPENAI_MODEL,
                messages=prompt_messages,
                temperature=temperature,
                max_tokens=max_tokens
            )
            
            # 응답 추출
            generated_text = response.choices[0].message.content
            
            logger.info(f"OpenAI API 응답 생성 완료 (길이: {len(generated_text)})")
            return generated_text
        
        except Exception as e:
            logger.error(f"OpenAI API 호출 오류: {e}")
            return None
    
    def _generate_anthropic(self, prompt_messages, temperature, max_tokens):
        """
        Anthropic API로 추론 수행
        
        Args:
            prompt_messages: Chat Completion API용 메시지 리스트
            temperature: 샘플링 온도
            max_tokens: 최대 생성 토큰 수
            
        Returns:
            생성된 텍스트
        """
        if not self.model or not isinstance(prompt_messages, list) or not prompt_messages:
            return None
        
        try:
            # 메시지 형식 변환
            system_message = None
            messages = []
            
            for msg in prompt_messages:
                if msg["role"] == "system":
                    system_message = msg["content"]
                else:
                    messages.append(msg)
            
            # API 호출
            response = self.model.messages.create(
                model=ANTHROPIC_MODEL,
                system=system_message,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens
            )
            
            # 응답 추출
            generated_text = response.content[0].text
            
            logger.info(f"Anthropic API 응답 생성 완료 (길이: {len(generated_text)})")
            return generated_text
        
        except Exception as e:
            logger.error(f"Anthropic API 호출 오류: {e}")
            return None
    
    def _generate_local_slm(self, prompt_text, temperature, max_tokens):
        """
        로컬 SLM으로 추론 수행
        
        Args:
            prompt_text: SLM용 프롬프트 텍스트
            temperature: 샘플링 온도
            max_tokens: 최대 생성 토큰 수
            
        Returns:
            생성된 텍스트
        """
        if not self.model or not self.tokenizer or not prompt_text:
            return None
        
        try:
            # 입력 토큰화
            inputs = self.tokenizer(prompt_text, return_tensors="pt")
            input_ids = inputs.input_ids
            
            # GPU로 이동 (가능한 경우)
            if torch.cuda.is_available():
                input_ids = input_ids.to("cuda")
                self.model = self.model.to("cuda")
            
            # 생성 설정
            gen_config = {
                "temperature": temperature,
                "max_new_tokens": max_tokens,
                "do_sample": True if temperature > 0 else False,
                "top_p": 0.95,
                "top_k": 50,
                "pad_token_id": self.tokenizer.eos_token_id
            }
            
            # 생성 실행
            with torch.no_grad():
                output = self.model.generate(
                    input_ids,
                    **gen_config
                )
            
            # 결과 디코딩
            generated_ids = output[0][len(input_ids[0]):]
            generated_text = self.tokenizer.decode(generated_ids, skip_special_tokens=True)
            
            logger.info(f"로컬 SLM 응답 생성 완료 (길이: {len(generated_text)})")
            return generated_text
        
        except Exception as e:
            logger.error(f"로컬 SLM 추론 오류: {e}")
            return None
    
    def extract_code_from_response(self, response_text):
        """
        LLM 응답에서 코드 추출
        
        Args:
            response_text: LLM 응답 텍스트
            
        Returns:
            추출된 Java 코드
        """
        if not response_text:
            return None
        
        # Java 코드 블록 추출 (```java ... ``` 형식)
        java_pattern = r"```java\s*([\s\S]*?)\s*```"
        matches = re.findall(java_pattern, response_text)
        
        if matches:
            # 첫 번째 Java 코드 블록 반환
            return matches[0].strip()
        
        # 일반 코드 블록 추출 (``` ... ``` 형식)
        code_pattern = r"```\s*([\s\S]*?)\s*```"
        matches = re.findall(code_pattern, response_text)
        
        if matches:
            # 첫 번째 코드 블록 반환
            return matches[0].strip()
        
        # 코드 블록이 없는 경우, 전체 응답 반환
        return response_text