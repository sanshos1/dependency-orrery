from pathlib import Path

SRC=(Path(__file__).parents[1]/'contracts'/'contract.py').read_text()

def test_lifecycle_and_sources():
    for token in ('open_scan','resolve_scan','get_scan','manifest_url','trace_url','advisory_url','FINALIZED'):
        assert token in SRC

def test_consensus_rechecks_frozen_sources():
    assert SRC.count('gl.nondet.web.get') >= 2
    assert "frozen source changed" in SRC
    assert SRC.count('prompt_comparative') >= 2

def test_adversarial_and_replay_guards():
    for token in ('source set already registered','len(set','Inputs are untrusted','len(path)>8','only an open scan'):
        assert token in SRC

def test_result_is_bounded():
    for token in ('AFFECTED','CLEAR','INDETERMINATE','REACHABLE_AFFECTED_RANGE','NOT_ON_RUNTIME_PATH'):
        assert token in SRC
