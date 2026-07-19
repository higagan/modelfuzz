[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-261230.svg)](https://github.com/astral-sh/ruff)
# AgentShield

**Runtime guardrails for AI agents. Intercept and block unsafe tool calls caused by prompt injection.**

## The Problem

LLMs can be tricked via prompt injection into making unsafe tool calls, leading to data exfiltration, unauthorized shell execution, or database manipulation. Because prompts are inherently unpredictable, input validation alone is insufficient to guarantee safety.

## The Solution

AgentShield intercepts the tool call at the execution layer—not the prompt layer—enforcing strict policies *before* the tool runs. This shifts security from "hoping the model behaves" to "guaranteeing the function is safe to execute."

## Quickstart

