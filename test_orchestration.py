#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线测试「业务编排逻辑 / Orchestration Loop」与「双后端消息翻译」—— 全部用假后端/纯函数,
无需任何 API Key。

覆盖:
  1) test_normal_flow          : 正常的 工具A(审计) -> 工具B(探测) -> 最终答案 流程
  2) test_infinite_loop_guarded: 死循环防护(缺陷1修复)——模型永远返回工具调用时被截断收尾
  3) test_dedup_same_turn      : 同一轮内完全相同的工具调用被去重, 只真正执行一次
  4) test_openai_translation   : 归一化历史 -> OpenAI 消息格式(tool_calls/arguments 序列化)
  5) test_anthropic_translation: 归一化历史 -> Anthropic (system 抽离 / tool_use 块 /
                                 tool_result 块 / 相邻 user 合并)

运行: py test_orchestration.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # 任意 cwd 下都能导入同目录的 main
import main


class MockBackend:
    """假后端: 实现与真实后端一致的 complete(history, mode) -> LLMResult 接口。"""

    provider = "mock"
    model = "mock-model"
    endpoint = "mock"

    def __init__(self, script):
        self.script = script   # list[callable(mode) -> LLMResult]
        self.i = 0
        self.modes = []        # 记录每次调用使用的 mode

    def complete(self, history, mode):
        self.modes.append(mode)
        step = self.script[min(self.i, len(self.script) - 1)]
        self.i += 1
        return step(mode)


def _R(text=None, tool_calls=None):
    return main.LLMResult(text=text, tool_calls=tool_calls)


def test_normal_flow():
    """工具A(审计) -> 工具B(探测端口) -> 最终答案。"""
    script = [
        lambda m: _R(tool_calls=[{"id": "c1", "name": "Command_Analyzer",
                                  "arguments": {"command": "docker run -d -p 0.0.0.0:3306:3306 mysql"}}]),
        lambda m: _R(tool_calls=[{"id": "c2", "name": "Environment_Prober",
                                  "arguments": {"action": "check_port", "target": "3306"}}]),
        lambda m: _R(text="## 🔍 风险评级: high\n修复后命令: docker run -d -p 127.0.0.1:3306:3306 mysql"),
    ]
    backend = MockBackend(script)
    history = [{"role": "system", "content": main.SYSTEM_PROMPT},
               {"role": "user", "content": "docker run -d -p 0.0.0.0:3306:3306 mysql"}]
    answer = main.run_agent_turn(backend, history)
    assert "风险评级" in answer, answer
    assert backend.modes[0] == "force_analyzer", backend.modes  # 首轮强制审计
    tool_msgs = [m for m in history if m.get("role") == "tool"]
    assert len(tool_msgs) == 2, tool_msgs
    print("✅ test_normal_flow 通过: A->B->最终答案; 首轮强制审计; 两次工具结果入历史")


def test_infinite_loop_guarded():
    """模型永远返回工具调用 -> 必须被 MAX_TOOL_ITERATIONS 截断并强制收尾(缺陷1修复)。"""
    def always_tool(mode):
        if mode == "none":  # 强制收尾轮
            return _R(text="【强制收尾】基于已收集证据给出最终结论。")
        return _R(tool_calls=[{"id": "loop", "name": "Command_Analyzer",
                               "arguments": {"command": "ls"}}])

    backend = MockBackend([always_tool])
    history = [{"role": "system", "content": "x"}, {"role": "user", "content": "ls"}]
    answer = main.run_agent_turn(backend, history)
    assert "强制收尾" in answer, answer
    assert len(backend.modes) == main.MAX_TOOL_ITERATIONS + 1, backend.modes
    assert backend.modes[0] == "force_analyzer" and backend.modes[-1] == "none", backend.modes
    print(f"✅ test_infinite_loop_guarded 通过: {main.MAX_TOOL_ITERATIONS} 轮后强制收尾, 未陷入死循环")


def test_dedup_same_turn():
    """同一轮内出现两个完全相同的工具调用 -> 真实只执行一次(缺陷1修复:去重)。"""
    counter = {"n": 0}
    real_analyze = main.analyze_command

    def counting_analyze(cmd):
        counter["n"] += 1
        return real_analyze(cmd)

    main.analyze_command = counting_analyze
    try:
        script = [
            lambda m: _R(tool_calls=[
                {"id": "d1", "name": "Command_Analyzer", "arguments": {"command": "rm -rf /"}},
                {"id": "d2", "name": "Command_Analyzer", "arguments": {"command": "rm -rf /"}},
            ]),
            lambda m: _R(text="done"),
        ]
        backend = MockBackend(script)
        history = [{"role": "system", "content": "x"}, {"role": "user", "content": "rm -rf /"}]
        main.run_agent_turn(backend, history)
        assert counter["n"] == 1, counter
        print("✅ test_dedup_same_turn 通过: 重复调用被去重, analyze_command 真实只执行一次")
    finally:
        main.analyze_command = real_analyze


def _sample_history():
    return [
        {"role": "system", "content": "SYS-PROMPT"},
        {"role": "user", "content": "审计 rm -rf /"},
        {"role": "assistant", "content": None,
         "tool_calls": [{"id": "t1", "name": "Command_Analyzer",
                         "arguments": {"command": "rm -rf /"}}]},
        {"role": "tool", "tool_call_id": "t1", "name": "Command_Analyzer",
         "content": '{"risk_level": "critical"}'},
        {"role": "user", "content": "⚠️ 已达到上限, 请收尾。"},  # 与上面的 tool 结果相邻(都会变成 user)
    ]


def test_openai_translation():
    msgs = main.to_openai_messages(_sample_history())
    assistant = [m for m in msgs if m["role"] == "assistant"][0]
    assert "tool_calls" in assistant
    # OpenAI 要求 arguments 是 JSON 字符串
    raw_args = assistant["tool_calls"][0]["function"]["arguments"]
    assert isinstance(raw_args, str) and "rm -rf /" in raw_args, raw_args
    tool_msg = [m for m in msgs if m["role"] == "tool"][0]
    assert tool_msg["tool_call_id"] == "t1"
    print("✅ test_openai_translation 通过: assistant.tool_calls 正常, arguments 已序列化为字符串")


def test_anthropic_translation():
    system_str, msgs = main.to_anthropic(_sample_history())
    assert system_str == "SYS-PROMPT", system_str
    # 期望 3 条: user(原始) / assistant(tool_use) / user(合并: tool_result + 收尾文本)
    assert [m["role"] for m in msgs] == ["user", "assistant", "user"], [m["role"] for m in msgs]
    assert any(b["type"] == "tool_use" for b in msgs[1]["content"]), msgs[1]
    last_types = [b["type"] for b in msgs[2]["content"]]
    assert "tool_result" in last_types and "text" in last_types, last_types  # 相邻 user 已合并
    print("✅ test_anthropic_translation 通过: system 抽离 / tool_use 块 / tool_result 块 / 相邻user合并")


if __name__ == "__main__":
    test_normal_flow()
    test_infinite_loop_guarded()
    test_dedup_same_turn()
    test_openai_translation()
    test_anthropic_translation()
    print("\n🎉 编排逻辑 + 双后端消息翻译 全部测试通过 (无需 API Key)")
