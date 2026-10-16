"""Offline tests: no target, no network, no PHP.

They cover the layers the modules are built on - message parsing, parameter
placement, mutation, evidence judging, state - so a change to the engine can be
checked without a lab. Anything that needs a live target belongs in `lab/`.
"""
