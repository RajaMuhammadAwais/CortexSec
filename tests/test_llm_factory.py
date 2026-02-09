from cortexsec.llm.deepseek import DeepSeekLLM
from cortexsec.llm.factory import create_llm


def test_factory_supports_deepseek_provider():
    llm = create_llm(provider="deepseek", model="deepseek-reasoner", api_key="test-key")
    assert isinstance(llm, DeepSeekLLM)
    assert llm.model == "deepseek-reasoner"
