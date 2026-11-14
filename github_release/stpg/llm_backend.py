"""
모델 호출 공통 백엔드(rev12). 모든 모델 호출(victim, TSA judge, witness, attribution judge, scalar judge, summarizer)은
generate() 하나를 거친다. 모델명으로 경로를 고른다:
  - "meta/..." (Vertex AI Model-as-a-Service, Llama 계열)  -> OpenAI 호환 chat.completions 엔드포인트
        https://{loc}-aiplatform.googleapis.com/v1beta1/projects/{project}/locations/{loc}/endpoints/openapi
        인증: ADC(gcloud auth application-default login) 의 액세스 토큰(만료 전 자동 갱신)
        환경변수: GOOGLE_CLOUD_PROJECT, STPG_MAAS_LOCATION(기본 us-east5). llama-3.3-70b-instruct-maas 는 2026-10-21 에
        MaaS 제공이 종료되어 Llama 4 Maverick(meta/llama-4-maverick-17b-128e-instruct-maas) 을 쓴다.
  - 그 외 (gemini-*)                                        -> google-genai (vertex 또는 aistudio)
반환: (text, prompt_tokens, completion_tokens). JSON 응답은 호출자가 정규식으로 추출한다(기존과 동일).
"""
from __future__ import annotations
import os, time
from stpg import config as C

_GENAI = None
_OAI = {"client": None, "exp": 0.0, "loc": None}


def _gemini_client():
    global _GENAI
    if _GENAI is None:
        from google import genai
        if os.environ.get("STPG_LLM_BACKEND", "aistudio") == "vertex":
            _GENAI = genai.Client(vertexai=True, project=os.environ["GOOGLE_CLOUD_PROJECT"],
                                  location=os.environ.get("STPG_LOCATION", "us-central1"))
        else:
            _GENAI = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    return _GENAI


def is_openai_compat(model: str) -> bool:
    return str(model).startswith("meta/") or str(model).startswith("openai-compat:")


def _oai_client():
    """Vertex MaaS OpenAI 호환 클라이언트. ADC 토큰은 50분마다 갱신한다."""
    now = time.time()
    if _OAI["client"] is None or now > _OAI["exp"]:
        from openai import OpenAI
        import google.auth, google.auth.transport.requests
        creds, proj = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        creds.refresh(google.auth.transport.requests.Request())
        project = os.environ.get("GOOGLE_CLOUD_PROJECT") or proj
        loc = os.environ.get("STPG_MAAS_LOCATION", "us-east5")       # Llama 4 MaaS 제공 리전
        base = f"https://{loc}-aiplatform.googleapis.com/v1beta1/projects/{project}/locations/{loc}/endpoints/openapi"
        _OAI["client"] = OpenAI(base_url=base, api_key=creds.token); _OAI["exp"] = now + 50 * 60; _OAI["loc"] = loc
    return _OAI["client"]


def _gen_openai(model: str, system: str, user: str, max_tokens: int, temperature: float):
    name = model.split("openai-compat:", 1)[-1]
    msgs = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    def call(json_mode: bool):
        kw = dict(model=name, messages=msgs, temperature=temperature, max_tokens=max_tokens)
        if json_mode:
            kw["response_format"] = {"type": "json_object"}
        return _oai_client().chat.completions.create(**kw)
    try:
        r = C.call_with_backoff(lambda: call(True))
    except Exception as e:                      # response_format 미지원 모델: JSON 모드 없이 재시도
        if "response_format" in str(e) or "json_object" in str(e) or "400" in str(e):
            r = C.call_with_backoff(lambda: call(False))
        else:
            raise
    text = (r.choices[0].message.content or "") if r.choices else ""
    u = getattr(r, "usage", None)
    return text, int(getattr(u, "prompt_tokens", 0) or 0), int(getattr(u, "completion_tokens", 0) or 0)


def _gen_gemini(model: str, system: str, user: str, max_tokens: int, temperature: float):
    from google.genai import types
    r = C.call_with_backoff(lambda: _gemini_client().models.generate_content(
        model=model, contents=user,
        config=types.GenerateContentConfig(system_instruction=system, temperature=temperature,
                                           response_mime_type="application/json",
                                           **C.gen_config_kwargs(model, max_tokens))))
    try:
        u = r.usage_metadata; it, ot = int(u.prompt_token_count or 0), int(u.candidates_token_count or 0)
    except Exception:
        it, ot = 0, 0
    return (r.text or ""), it, ot


def generate(model: str, system: str, user: str, max_tokens: int, temperature: float = 0.0):
    """(text, prompt_tokens, completion_tokens)."""
    if is_openai_compat(model):
        return _gen_openai(model, system, user, max_tokens, temperature)
    return _gen_gemini(model, system, user, max_tokens, temperature)


def price(model: str) -> tuple[float, float]:
    """USD per 1M tokens (input, output); config.MODELS 또는 MAAS 목록."""
    for k, v in C.MODELS.items():
        if v.name == model or k == model:
            return v.input_usd_per_m, v.output_usd_per_m
    return C.MAAS_PRICES.get(model, (0.0, 0.0))
